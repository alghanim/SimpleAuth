package handler

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"simpleauth/internal/auth"
	"simpleauth/internal/store"
)

// appIDRe constrains app_id to a URL/path/audience-safe slug.
var appIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// generateAppSecret returns a fresh app secret (shown to the admin once).
func generateAppSecret() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sa_app_" + base64.RawURLEncoding.EncodeToString(b), nil
}

// slugifyAppID derives a safe app_id from a display name.
func slugifyAppID(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = regexp.MustCompile(`[^a-z0-9_-]+`).ReplaceAllString(s, "-")
	s = strings.Trim(s, "-_")
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// appView renders an app for API responses — never includes the secret hash.
func appView(a *store.App) map[string]interface{} {
	return map[string]interface{}{
		"app_id":             a.AppID,
		"name":               a.Name,
		"audience":           a.Audience,
		"redirect_uris":      a.RedirectURIs,
		"cors_origins":       a.CORSOrigins,
		"require_assignment": a.RequireAssignment,
		"allow_local_users":  a.AllowLocalUsers,
		"disabled":           a.Disabled,
		"created_at":         a.CreatedAt,
	}
}

// handleCreateApp registers a new app (master admin only). Returns the app
// plus its generated secret — shown exactly once.
// POST /api/admin/apps
func (h *Handler) handleCreateApp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AppID             string   `json:"app_id"`
		Name              string   `json:"name"`
		Audience          string   `json:"audience"`
		RedirectURIs      []string `json:"redirect_uris"`
		CORSOrigins       []string `json:"cors_origins"`
		RequireAssignment bool     `json:"require_assignment"`
		AllowLocalUsers   bool     `json:"allow_local_users"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	appID := strings.TrimSpace(req.AppID)
	if appID == "" {
		appID = slugifyAppID(req.Name)
	}
	if !appIDRe.MatchString(appID) {
		jsonError(w, "app_id must be 1-64 chars: lowercase letters, digits, '-' or '_' (or provide a name)", http.StatusBadRequest)
		return
	}
	audience := strings.TrimSpace(req.Audience)
	if audience == "" {
		audience = appID
	}

	secret, err := generateAppSecret()
	if err != nil {
		jsonError(w, "failed to generate secret", http.StatusInternalServerError)
		return
	}
	hash, err := auth.HashPassword(secret)
	if err != nil {
		jsonError(w, "failed to hash secret", http.StatusInternalServerError)
		return
	}

	a := &store.App{
		AppID:             appID,
		Name:              req.Name,
		Audience:          audience,
		SecretHash:        hash,
		RedirectURIs:      req.RedirectURIs,
		CORSOrigins:       req.CORSOrigins,
		RequireAssignment: req.RequireAssignment,
		AllowLocalUsers:   req.AllowLocalUsers,
		CreatedAt:         time.Now().UTC(),
	}
	if err := h.store.CreateApp(a); err != nil {
		if errors.Is(err, store.ErrAppExists) {
			jsonError(w, "app_id already exists", http.StatusConflict)
			return
		}
		jsonError(w, "failed to create app", http.StatusInternalServerError)
		return
	}

	h.audit("app_created", "admin", getClientIP(r), map[string]interface{}{"app_id": appID})

	resp := appView(a)
	resp["app_secret"] = secret // shown once
	jsonResp(w, resp, http.StatusCreated)
}

// handleListApps lists all registered apps. GET /api/admin/apps
func (h *Handler) handleListApps(w http.ResponseWriter, r *http.Request) {
	apps, err := h.store.ListApps()
	if err != nil {
		jsonError(w, "failed to list apps", http.StatusInternalServerError)
		return
	}
	out := make([]map[string]interface{}, 0, len(apps))
	for _, a := range apps {
		out = append(out, appView(a))
	}
	jsonResp(w, map[string]interface{}{"apps": out}, http.StatusOK)
}

// handleGetApp returns a single app. GET /api/admin/apps/{app_id}
func (h *Handler) handleGetApp(w http.ResponseWriter, r *http.Request) {
	a, err := h.store.GetApp(pathParam(r, "app_id"))
	if err != nil {
		jsonError(w, "app not found", http.StatusNotFound)
		return
	}
	jsonResp(w, appView(a), http.StatusOK)
}

// handleUpdateApp updates an app's mutable fields. PUT /api/admin/apps/{app_id}
func (h *Handler) handleUpdateApp(w http.ResponseWriter, r *http.Request) {
	a, err := h.store.GetApp(pathParam(r, "app_id"))
	if err != nil {
		jsonError(w, "app not found", http.StatusNotFound)
		return
	}
	var req struct {
		Name              *string   `json:"name"`
		Audience          *string   `json:"audience"`
		RedirectURIs      *[]string `json:"redirect_uris"`
		CORSOrigins       *[]string `json:"cors_origins"`
		RequireAssignment *bool     `json:"require_assignment"`
		AllowLocalUsers   *bool     `json:"allow_local_users"`
		Disabled          *bool     `json:"disabled"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name != nil {
		a.Name = *req.Name
	}
	if req.Audience != nil && strings.TrimSpace(*req.Audience) != "" {
		a.Audience = strings.TrimSpace(*req.Audience)
	}
	if req.RedirectURIs != nil {
		a.RedirectURIs = *req.RedirectURIs
	}
	if req.CORSOrigins != nil {
		a.CORSOrigins = *req.CORSOrigins
	}
	if req.RequireAssignment != nil {
		a.RequireAssignment = *req.RequireAssignment
	}
	if req.AllowLocalUsers != nil {
		a.AllowLocalUsers = *req.AllowLocalUsers
	}
	if req.Disabled != nil {
		a.Disabled = *req.Disabled
	}
	if err := h.store.UpdateApp(a); err != nil {
		jsonError(w, "failed to update app", http.StatusInternalServerError)
		return
	}
	h.audit("app_updated", "admin", getClientIP(r), map[string]interface{}{"app_id": a.AppID})
	jsonResp(w, appView(a), http.StatusOK)
}

// handleDeleteApp removes an app. DELETE /api/admin/apps/{app_id}
func (h *Handler) handleDeleteApp(w http.ResponseWriter, r *http.Request) {
	appID := pathParam(r, "app_id")
	if err := h.store.DeleteApp(appID); err != nil {
		jsonError(w, "failed to delete app", http.StatusInternalServerError)
		return
	}
	h.audit("app_deleted", "admin", getClientIP(r), map[string]interface{}{"app_id": appID})
	jsonResp(w, map[string]string{"status": "deleted"}, http.StatusOK)
}

// handleRotateAppSecret issues a new secret for an app, returned once.
// POST /api/admin/apps/{app_id}/rotate-secret
func (h *Handler) handleRotateAppSecret(w http.ResponseWriter, r *http.Request) {
	a, err := h.store.GetApp(pathParam(r, "app_id"))
	if err != nil {
		jsonError(w, "app not found", http.StatusNotFound)
		return
	}
	secret, err := generateAppSecret()
	if err != nil {
		jsonError(w, "failed to generate secret", http.StatusInternalServerError)
		return
	}
	hash, err := auth.HashPassword(secret)
	if err != nil {
		jsonError(w, "failed to hash secret", http.StatusInternalServerError)
		return
	}
	a.SecretHash = hash
	if err := h.store.UpdateApp(a); err != nil {
		jsonError(w, "failed to rotate secret", http.StatusInternalServerError)
		return
	}
	h.audit("app_secret_rotated", "admin", getClientIP(r), map[string]interface{}{"app_id": a.AppID})
	jsonResp(w, map[string]interface{}{"app_id": a.AppID, "app_secret": secret}, http.StatusOK)
}
