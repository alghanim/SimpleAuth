package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"simpleauth/internal/migrate"
)

// --- Central side: receive a standalone deployment as a named app ---
//
// Importing a directory is a master-level operation, so it is gated by a
// single-use, app-scoped MIGRATION TOKEN that a master admin mints on the target
// app. The standalone authenticates the cross-install preflight/commit calls with
// that token (Authorization: Bearer). Tokens are stored hashed, expire, and are
// consumed on commit.

const migrationTokenTTL = 30 * time.Minute

type migrationTokenRecord struct {
	Hash      string    `json:"hash"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `json:"used"`
}

func migrationTokenKey(appID string) string { return "migration_token:" + appID }

func hashMigrationToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// handleGenMigrationToken mints a single-use migration token for a target app.
// POST /api/admin/apps/{app_id}/migration-token  (master admin)
func (h *Handler) handleGenMigrationToken(w http.ResponseWriter, r *http.Request) {
	appID := pathParam(r, "app_id")
	if appID == h.defaultAppID() {
		jsonError(w, "the default app cannot be a migration target", http.StatusForbidden)
		return
	}
	if _, err := h.store.GetApp(appID); err != nil {
		jsonError(w, "app not found", http.StatusNotFound)
		return
	}

	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		jsonError(w, "failed to generate token", http.StatusInternalServerError)
		return
	}
	raw := "sa_mig_" + base64.RawURLEncoding.EncodeToString(b)
	rec := migrationTokenRecord{Hash: hashMigrationToken(raw), ExpiresAt: time.Now().UTC().Add(migrationTokenTTL)}
	data, _ := json.Marshal(rec)
	if err := h.store.SetConfigValue(migrationTokenKey(appID), data); err != nil {
		jsonError(w, "failed to store token", http.StatusInternalServerError)
		return
	}
	h.audit("migration_token_issued", "admin", getClientIP(r), map[string]interface{}{"app_id": appID})
	jsonResp(w, map[string]interface{}{
		"migration_token": raw, // shown once
		"app_id":          appID,
		"expires_at":      rec.ExpiresAt,
	}, http.StatusOK)
}

// authMigration validates the bearer migration token against appID. It never
// reveals which check failed (uniform false), and is constant-time on the hash.
func (h *Handler) authMigration(r *http.Request, appID string) bool {
	tok := extractBearerToken(r)
	if tok == "" || appID == "" {
		return false
	}
	data, err := h.store.GetConfigValue(migrationTokenKey(appID))
	if err != nil || len(data) == 0 {
		return false
	}
	var rec migrationTokenRecord
	if json.Unmarshal(data, &rec) != nil {
		return false
	}
	if rec.Used || time.Now().UTC().After(rec.ExpiresAt) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(rec.Hash), []byte(hashMigrationToken(tok))) == 1
}

func (h *Handler) consumeMigrationToken(appID string) {
	data, err := h.store.GetConfigValue(migrationTokenKey(appID))
	if err != nil || len(data) == 0 {
		return
	}
	var rec migrationTokenRecord
	if json.Unmarshal(data, &rec) != nil {
		return
	}
	rec.Used = true
	if data, err := json.Marshal(rec); err == nil {
		h.store.SetConfigValue(migrationTokenKey(appID), data)
	}
}

type migrationRequest struct {
	AppID       string          `json:"app_id"`
	Bundle      *migrate.Bundle `json:"bundle"`
	CarrySecret bool            `json:"carry_secret"`
}

// guardMigrationCall does the shared validation for preflight/commit: rate-limit,
// parse, token auth, schema compatibility, and target-app sanity. Returns the
// parsed request, or false if it already wrote an error response.
func (h *Handler) guardMigrationCall(w http.ResponseWriter, r *http.Request) (*migrationRequest, bool) {
	if !h.loginLimiter.allow(getClientIP(r)) {
		jsonError(w, "too many requests", http.StatusTooManyRequests)
		return nil, false
	}
	var req migrationRequest
	if err := readJSON(r, &req); err != nil || req.Bundle == nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return nil, false
	}
	if !h.authMigration(r, req.AppID) {
		jsonError(w, "invalid or expired migration token", http.StatusUnauthorized)
		return nil, false
	}
	if req.Bundle.SchemaRev != migrate.SchemaRev {
		jsonError(w, "incompatible migration bundle — upgrade the older deployment first", http.StatusBadRequest)
		return nil, false
	}
	if req.AppID == h.defaultAppID() {
		jsonError(w, "the default app cannot be a migration target", http.StatusForbidden)
		return nil, false
	}
	if _, err := h.store.GetApp(req.AppID); err != nil {
		jsonError(w, "target app not found", http.StatusNotFound)
		return nil, false
	}
	return &req, true
}

// handleMigrationPreflight runs the dry-run classifier and returns the report,
// mutating nothing. POST /api/migration/preflight  (migration-token auth)
func (h *Handler) handleMigrationPreflight(w http.ResponseWriter, r *http.Request) {
	req, ok := h.guardMigrationCall(w, r)
	if !ok {
		return
	}
	rep, err := migrate.Classify(req.Bundle, h.store, req.AppID)
	if err != nil {
		jsonError(w, "preflight failed", http.StatusInternalServerError)
		return
	}
	jsonResp(w, rep, http.StatusOK)
}

// handleMigrationCommit applies the bundle and consumes the token. It re-runs the
// classifier and refuses if any user is blocked. POST /api/migration/commit
func (h *Handler) handleMigrationCommit(w http.ResponseWriter, r *http.Request) {
	req, ok := h.guardMigrationCall(w, r)
	if !ok {
		return
	}
	rep, err := migrate.Classify(req.Bundle, h.store, req.AppID)
	if err != nil {
		jsonError(w, "preflight failed", http.StatusInternalServerError)
		return
	}
	if !rep.OK() {
		jsonResp(w, map[string]interface{}{"error": "migration has blocked users — resolve them first", "report": rep}, http.StatusConflict)
		return
	}
	res, err := migrate.Apply(req.Bundle, h.store, req.AppID, req.CarrySecret)
	if err != nil {
		jsonError(w, "commit failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.consumeMigrationToken(req.AppID) // single-use
	h.audit("migration_committed", "migration:"+req.AppID, getClientIP(r), map[string]interface{}{
		"app_id": req.AppID, "assignments": res.AssignmentsSet, "local_users": res.LocalUsersCreated,
	})
	jsonResp(w, res, http.StatusOK)
}
