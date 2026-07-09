package handler

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"simpleauth/internal/store"
)

// userAppView renders one app for GET /api/user/apps (SA-1 presentation only —
// deliberately no roles/permissions/assignment-source: SA-2 is a bounded
// cross-app disclosure, so the payload is minimized). icon_url is the absolute
// URL computed from base_url + the relative icon path.
func userAppView(a *store.App) map[string]interface{} {
	display := a.DisplayName
	if len(display) == 0 {
		display = map[string]string{"en": a.Name}
	}
	iconURL := ""
	if a.Icon != "" {
		iconURL = a.BaseURL + a.Icon
	}
	return map[string]interface{}{
		"app_id":       a.AppID,
		"base_url":     a.BaseURL,
		"display_name": display,
		"category":     a.Category,
		"icon_url":     iconURL,
	}
}

// handleUserApps returns the apps the CALLER MAY ENTER (SA-2) — the authoritative
// source for the portal app-switcher and grid. It accepts any user access token
// of any audience (there is no other way to answer "which apps may this user
// enter" under audience isolation), and the "may enter" predicate is exactly
// "would be admitted at token issuance": it reuses resolveTokenRoles' admit/deny
// verdict, so a require_assignment app that would deny the user is excluded, and
// a require_assignment=false app (which admits every directory user) is included.
// Disabled apps, the global directory app, and non-launchable apps (no base_url)
// are excluded.
//
// GET /api/user/apps   Authorization: Bearer <caller's own access token>
func (h *Handler) handleUserApps(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)
	if !h.loginLimiter.allow(ip) {
		jsonError(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	tokenStr := extractBearerToken(r)
	if tokenStr == "" {
		jsonError(w, "missing authorization header", http.StatusUnauthorized)
		return
	}
	claims, err := h.validateAccessToken(tokenStr)
	if err != nil {
		jsonError(w, "invalid or revoked token", http.StatusUnauthorized)
		return
	}
	// Resolve the user for their last-known groups — the same basis refresh uses,
	// so "may enter" matches what a fresh token would actually be granted.
	user, err := h.store.ResolveUser(claims.Subject)
	if err != nil {
		jsonError(w, "user not found", http.StatusUnauthorized)
		return
	}
	// Fail closed on a disabled account, matching the login/refresh gates — a
	// just-disabled user with a still-live token must not keep enumerating apps.
	if user.Disabled {
		jsonError(w, "account disabled", http.StatusUnauthorized)
		return
	}

	apps, err := h.store.ListApps()
	if err != nil {
		jsonError(w, "failed to list apps", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]interface{}, 0, len(apps))
	for _, a := range apps {
		// Non-launchable: the global directory app, disabled apps, and apps with no
		// canonical origin (nothing to render as a launch card).
		if a.AppID == h.defaultAppID() || a.Disabled || a.BaseURL == "" {
			continue
		}
		// Authentication eligibility, not just per-app authz: an app-local user can
		// only ever authenticate into their OWN owner app, so never show them the
		// catalog of other (e.g. require_assignment=false) apps they could never
		// enter. Directory users (OwnerAppID == "") are unconstrained here.
		if user.OwnerAppID != "" && a.AppID != user.OwnerAppID {
			continue
		}
		if _, _, denied := h.resolveTokenRoles(a, user); denied {
			continue
		}
		out = append(out, userAppView(a))
	}
	// Stable order so the ETag is meaningful across backends/requests.
	sort.Slice(out, func(i, j int) bool {
		return out[i]["app_id"].(string) < out[j]["app_id"].(string)
	})

	// A weak ETag lets a shell revalidate cheaply on every cross-module hop
	// (SA-2 caching) — the list changes rarely relative to how often it is read.
	body, _ := json.Marshal(out)
	etag := fmt.Sprintf(`W/"%x"`, sha256.Sum256(body))
	w.Header().Set("ETag", etag)
	if strings.Contains(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	jsonResp(w, out, http.StatusOK)
}

// handleUserLogoutAll terminates the CALLER'S OWN presence everywhere (SA-3):
// revoke their refresh families and delete their shared __sa_sso sessions, so no
// module can silently re-mint after logout and the shared session is gone.
// Authenticated by the user's own access token of any audience — the target is
// always the token's subject, so a user can only ever log themselves out.
//
// It deliberately does NOT set the per-user access blacklist that the
// master-gated handleRevokeSessions uses. That blacklist is a BLANKET
// per-user flag (IsUserAccessRevoked ignores token iat), so it would also reject
// the user's next fresh login for the whole window — a self-lockout that is
// correct for an admin kill switch but wrong for a user logging themselves out
// and back in. Under offline-JWKS verification a live access token is valid
// until its exp regardless, so refresh-revocation + SSO teardown is the
// meaningful lever; residual access is bounded by each outstanding token's own
// remaining life. (A token-iat revocation watermark — which would kill
// outstanding tokens while still allowing an immediate re-login — is the right
// system-wide enhancement to the revocation model, out of scope here.)
//
// POST /api/user/logout-all   Authorization: Bearer <caller's own access token>
func (h *Handler) handleUserLogoutAll(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)
	if !h.loginLimiter.allow(ip) {
		jsonError(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	tokenStr := extractBearerToken(r)
	if tokenStr == "" {
		jsonError(w, "missing authorization header", http.StatusUnauthorized)
		return
	}
	// validateAccessToken rejects app-mgmt / refresh / id_token classes and honors
	// existing revocation, so only a genuine user access token reaches here.
	claims, err := h.validateAccessToken(tokenStr)
	if err != nil {
		jsonError(w, "invalid or revoked token", http.StatusUnauthorized)
		return
	}
	guid := claims.Subject // never a request parameter — self-scope only

	if err := h.store.RevokeUserTokens(guid); err != nil {
		jsonError(w, "failed to revoke sessions", http.StatusInternalServerError)
		return
	}
	h.store.DeleteUserSessions(guid)

	var auditData map[string]interface{}
	if claims.Impersonated {
		auditData = map[string]interface{}{"impersonated_by": claims.ImpersonatedBy}
	}
	h.audit("user_logout_all", guid, ip, auditData)

	jsonResp(w, map[string]string{
		"status": "logged out everywhere (refresh tokens + SSO sessions revoked)",
	}, http.StatusOK)
}

// --- SA-4: per-user UI preferences ---

// UserPreferences is a FIXED, server-validated per-user UI preference document —
// deliberately NOT a generic key/value store. Any-audience user tokens can write
// it, so one module's XSS must not be able to plant arbitrary values that every
// module shell renders before first paint: unknown keys are rejected and every
// value is enum/format-checked.
type UserPreferences struct {
	Theme         string `json:"theme"`          // light | dark | system
	Lang          string `json:"lang"`           // BCP-47 tag (e.g. en, ar, en-US)
	Dir           string `json:"dir"`            // ltr | rtl
	RailCollapsed bool   `json:"rail_collapsed"` // side-rail collapsed
}

const (
	userPrefsKeyPrefix = "user_prefs:"
	maxUserPrefsBytes  = 2 << 10 // 2 KiB cap on the request body
)

var (
	prefThemes = map[string]bool{"light": true, "dark": true, "system": true}
	prefDirs   = map[string]bool{"ltr": true, "rtl": true}
	bcp47Re    = regexp.MustCompile(`^[A-Za-z]{2,3}(-[A-Za-z0-9]{1,8})*$`)
)

func defaultUserPreferences() UserPreferences {
	return UserPreferences{Theme: "system", Lang: "en", Dir: "ltr"}
}

// normalize fills empty fields with defaults and validates the rest, returning a
// client-facing error for any invalid value.
func (p *UserPreferences) normalize() error {
	switch {
	case p.Theme == "":
		p.Theme = "system"
	case !prefThemes[p.Theme]:
		return fmt.Errorf("theme must be one of: light, dark, system")
	}
	switch {
	case p.Dir == "":
		p.Dir = "ltr"
	case !prefDirs[p.Dir]:
		return fmt.Errorf("dir must be ltr or rtl")
	}
	switch {
	case p.Lang == "":
		p.Lang = "en"
	case !bcp47Re.MatchString(p.Lang):
		return fmt.Errorf("lang must be a BCP-47 language tag")
	}
	return nil
}

// handleGetUserPreferences returns the caller's UI preferences (SA-4), defaults
// if never set. Authenticated by the user's own access token of any audience.
// A cheap single-key read, so — like userinfo — it is not rate-limited.
// GET /api/user/preferences
func (h *Handler) handleGetUserPreferences(w http.ResponseWriter, r *http.Request) {
	tokenStr := extractBearerToken(r)
	if tokenStr == "" {
		jsonError(w, "missing authorization header", http.StatusUnauthorized)
		return
	}
	claims, err := h.validateAccessToken(tokenStr)
	if err != nil {
		jsonError(w, "invalid or revoked token", http.StatusUnauthorized)
		return
	}
	prefs := defaultUserPreferences()
	if data, _ := h.store.GetConfigValue(userPrefsKeyPrefix + claims.Subject); len(data) > 0 {
		_ = json.Unmarshal(data, &prefs)
	}
	jsonResp(w, prefs, http.StatusOK)
}

// handleSetUserPreferences replaces the caller's UI preferences (SA-4,
// full-document, last-write-wins). Strict: unknown keys and out-of-range values
// are 400; the body is capped. Behind the rate limiter (it is a write).
// PUT /api/user/preferences
func (h *Handler) handleSetUserPreferences(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)
	if !h.loginLimiter.allow(ip) {
		jsonError(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	tokenStr := extractBearerToken(r)
	if tokenStr == "" {
		jsonError(w, "missing authorization header", http.StatusUnauthorized)
		return
	}
	claims, err := h.validateAccessToken(tokenStr)
	if err != nil {
		jsonError(w, "invalid or revoked token", http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUserPrefsBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var prefs UserPreferences
	if err := dec.Decode(&prefs); err != nil {
		jsonError(w, "invalid preferences body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := prefs.normalize(); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	data, _ := json.Marshal(prefs)
	if err := h.store.SetConfigValue(userPrefsKeyPrefix+claims.Subject, data); err != nil {
		jsonError(w, "failed to save preferences", http.StatusInternalServerError)
		return
	}
	jsonResp(w, prefs, http.StatusOK)
}
