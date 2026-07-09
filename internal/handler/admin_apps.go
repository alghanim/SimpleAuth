package handler

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
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

// normalizeBaseURL validates a module's canonical origin (SA-1) and returns it
// normalized. It is stored and returned but NEVER dereferenced by SimpleAuth, so
// validation is purely syntactic: an absolute https URL with a host, an optional
// path prefix, and no userinfo/query/fragment; the trailing slash is stripped.
// Empty is allowed (a non-launchable app). This is deliberately strict so a
// stored base_url can be trusted as a launch target without runtime checks.
func normalizeBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("base_url is not a valid URL")
	}
	if u.Scheme != "https" {
		return "", errors.New("base_url must be an absolute https:// URL")
	}
	if u.Host == "" {
		return "", errors.New("base_url must include a host")
	}
	if u.User != nil {
		return "", errors.New("base_url must not contain userinfo")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("base_url must not contain a query or fragment")
	}
	path := strings.TrimRight(u.Path, "/")
	return u.Scheme + "://" + u.Host + path, nil
}

// validateIconPath ensures the icon is a relative path under base_url, never an
// absolute/remote URL or a traversal — SA-1 forbids inline bytes and off-origin
// icons. Empty is allowed.
func validateIconPath(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if strings.Contains(raw, "://") || strings.HasPrefix(raw, "//") {
		return errors.New("icon must be a relative path under base_url, not an absolute URL")
	}
	if strings.Contains(raw, "..") {
		return errors.New("icon path must not contain '..'")
	}
	return nil
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
		"base_url":           a.BaseURL,
		"display_name":       a.DisplayName,
		"category":           a.Category,
		"icon":               a.Icon,
	}
}

// handleCreateApp registers a new app (master admin only). Returns the app
// plus its generated secret — shown exactly once.
// POST /api/admin/apps
func (h *Handler) handleCreateApp(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AppID             string            `json:"app_id"`
		Name              string            `json:"name"`
		Audience          string            `json:"audience"`
		RedirectURIs      []string          `json:"redirect_uris"`
		CORSOrigins       []string          `json:"cors_origins"`
		RequireAssignment bool              `json:"require_assignment"`
		AllowLocalUsers   bool              `json:"allow_local_users"`
		BaseURL           string            `json:"base_url"`
		DisplayName       map[string]string `json:"display_name"`
		Category          string            `json:"category"`
		Icon              string            `json:"icon"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	baseURL, err := normalizeBaseURL(req.BaseURL)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateIconPath(req.Icon); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
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
	// The default app's id is reserved: a named app with that id would be routed
	// through the home-app branch of resolveTokenRoles (its per-app authz ignored,
	// global roles leaked). The default app is created only by ensureDefaultApp.
	if appID == h.defaultAppID() {
		jsonError(w, "app_id is reserved for the default app", http.StatusBadRequest)
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
		BaseURL:           baseURL,
		DisplayName:       req.DisplayName,
		Category:          strings.TrimSpace(req.Category),
		Icon:              strings.TrimSpace(req.Icon),
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
		Name              *string            `json:"name"`
		Audience          *string            `json:"audience"`
		RedirectURIs      *[]string          `json:"redirect_uris"`
		CORSOrigins       *[]string          `json:"cors_origins"`
		RequireAssignment *bool              `json:"require_assignment"`
		AllowLocalUsers   *bool              `json:"allow_local_users"`
		Disabled          *bool              `json:"disabled"`
		BaseURL           *string            `json:"base_url"`
		DisplayName       *map[string]string `json:"display_name"`
		Category          *string            `json:"category"`
		Icon              *string            `json:"icon"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	oldBaseURL := a.BaseURL
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
		// The default app is the global directory; "app-local users" there would get
		// role assignments written into its AppAuthz, which the home-app token path
		// ignores (dead config). Directory users are created via /api/admin/users.
		if *req.AllowLocalUsers && a.AppID == h.defaultAppID() {
			jsonError(w, "the default app cannot enable local users (it is the global directory)", http.StatusBadRequest)
			return
		}
		a.AllowLocalUsers = *req.AllowLocalUsers
	}
	if req.Disabled != nil {
		a.Disabled = *req.Disabled
	}
	if req.BaseURL != nil {
		normalized, err := normalizeBaseURL(*req.BaseURL)
		if err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.BaseURL = normalized
	}
	if req.DisplayName != nil {
		a.DisplayName = *req.DisplayName
	}
	if req.Category != nil {
		a.Category = strings.TrimSpace(*req.Category)
	}
	if req.Icon != nil {
		if err := validateIconPath(*req.Icon); err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.Icon = strings.TrimSpace(*req.Icon)
	}
	if err := h.store.UpdateApp(a); err != nil {
		jsonError(w, "failed to update app", http.StatusInternalServerError)
		return
	}
	// base_url is a user-facing launch target — whoever changes it repoints every
	// portal-card click, so record old→new for audit (SA-1).
	auditData := map[string]interface{}{"app_id": a.AppID}
	if a.BaseURL != oldBaseURL {
		auditData["old_base_url"] = oldBaseURL
		auditData["new_base_url"] = a.BaseURL
	}
	h.audit("app_updated", "admin", getClientIP(r), auditData)
	jsonResp(w, appView(a), http.StatusOK)
}

// handleDeleteApp removes an app. DELETE /api/admin/apps/{app_id}
func (h *Handler) handleDeleteApp(w http.ResponseWriter, r *http.Request) {
	appID := pathParam(r, "app_id")
	// The default ("home") app is first-class and undeletable: it is the global
	// directory and the target of every app-less token request. Deleting it would
	// also free its id for re-registration as a named app (which resolveTokenRoles
	// would then route through the home-app branch — leaking global roles).
	if appID == h.defaultAppID() {
		jsonError(w, "the default app cannot be deleted", http.StatusForbidden)
		return
	}
	if err := h.store.DeleteApp(appID); err != nil {
		jsonError(w, "failed to delete app", http.StatusInternalServerError)
		return
	}
	h.store.DeleteConfigValue(migrationTokenKey(appID)) // don't leave a token that could re-target a recreated id
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
	a.SecretRotatedAt = time.Now().UTC() // revokes management tokens issued earlier (L4)
	if err := h.store.UpdateApp(a); err != nil {
		jsonError(w, "failed to rotate secret", http.StatusInternalServerError)
		return
	}
	h.store.DeleteConfigValue(migrationTokenKey(a.AppID)) // rotating credentials invalidates a pending migration token
	h.audit("app_secret_rotated", "admin", getClientIP(r), map[string]interface{}{"app_id": a.AppID})
	jsonResp(w, map[string]interface{}{"app_id": a.AppID, "app_secret": secret}, http.StatusOK)
}

// handleGetAppAuthz returns an app's per-app authorization: its role catalog,
// role→permission map, and user/group assignments (v2 M3).
// GET /api/admin/apps/{app_id}/authz
func (h *Handler) handleGetAppAuthz(w http.ResponseWriter, r *http.Request) {
	appID := pathParam(r, "app_id")
	// The default app's authz is not its token source (the home app reads global
	// roles); refuse the per-app authz surface for it, matching the PUT guard.
	if h.defaultAppAuthzForbidden(w, appID) {
		return
	}
	if _, err := h.store.GetApp(appID); err != nil {
		jsonError(w, "app not found", http.StatusNotFound)
		return
	}
	authz, err := h.store.GetAppAuthz(appID)
	if err != nil {
		jsonError(w, "failed to read app authz", http.StatusInternalServerError)
		return
	}
	jsonResp(w, authz, http.StatusOK)
}

// handleSetAppAuthz replaces an app's per-app authorization.
// PUT /api/admin/apps/{app_id}/authz
func (h *Handler) handleSetAppAuthz(w http.ResponseWriter, r *http.Request) {
	appID := pathParam(r, "app_id")
	// The default ("home") app's roles live in the global per-user store, not its
	// AppAuthz (resolveTokenRoles ignores the home app's AppAuthz). Writing it here
	// would be dead config, so refuse it and point to the right surface.
	if h.defaultAppAuthzForbidden(w, appID) {
		return
	}
	if _, err := h.store.GetApp(appID); err != nil {
		jsonError(w, "app not found", http.StatusNotFound)
		return
	}
	var authz store.AppAuthz
	if err := readJSON(r, &authz); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	authz.AppID = appID // path is authoritative
	if err := h.store.SaveAppAuthz(&authz); err != nil {
		jsonError(w, "failed to save app authz", http.StatusInternalServerError)
		return
	}
	h.audit("app_authz_updated", "admin", getClientIP(r), map[string]interface{}{"app_id": appID})
	jsonResp(w, &authz, http.StatusOK)
}
