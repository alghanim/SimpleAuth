package handler

import (
	"net/http"

	"simpleauth/internal/auth"
	"simpleauth/internal/store"
)

// ctxAppID carries the authenticated app's id for /api/app/* handlers.
const ctxAppID contextKey = "app_id"

// requireApp authenticates the calling app (HTTP Basic app_id:app_secret, or a
// Bearer app-management token) and scopes the request to that app — the app_id
// is derived from the credential and put in context, never read from the path,
// so an app can only ever act on its own scope (v2 M4).
func (h *Handler) requireApp(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		appID, ok := h.authenticateApp(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="simpleauth-app"`)
			jsonError(w, "invalid app credentials", http.StatusUnauthorized)
			return
		}
		next(w, r.WithContext(setContext(r.Context(), ctxAppID, appID)))
	}
}

// authenticateApp resolves the app from HTTP Basic (app_id:app_secret) or a
// Bearer app-management token. Returns (app_id, ok).
func (h *Handler) authenticateApp(r *http.Request) (string, bool) {
	if appID, secret, ok := r.BasicAuth(); ok && appID != "" {
		if app, err := h.store.GetApp(appID); err == nil && !app.Disabled &&
			app.SecretHash != "" && auth.CheckPassword(app.SecretHash, secret) {
			return appID, true
		}
		return "", false
	}
	if tok := extractBearerToken(r); tok != "" {
		if claims, err := h.jwt.ValidateToken(tok); err == nil && claims.Typ == "app-mgmt" && claims.Azp != "" {
			if app, err := h.store.GetApp(claims.Azp); err == nil && !app.Disabled {
				return claims.Azp, true
			}
		}
	}
	return "", false
}

func appIDFromContext(r *http.Request) string {
	return getContext(r.Context(), ctxAppID)
}

// handleAppToken exchanges app_id + app_secret for a short-lived app-management
// token (usable as a Bearer on /api/app/*). Accepts HTTP Basic or form fields.
// POST /api/app/token
func (h *Handler) handleAppToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	appID := r.FormValue("app_id")
	secret := r.FormValue("app_secret")
	if appID == "" {
		if id, sec, ok := r.BasicAuth(); ok {
			appID, secret = id, sec
		}
	}
	app, err := h.store.GetApp(appID)
	if err != nil || app.Disabled || app.SecretHash == "" || !auth.CheckPassword(app.SecretHash, secret) {
		w.Header().Set("WWW-Authenticate", `Basic realm="simpleauth-app"`)
		jsonError(w, "invalid app credentials", http.StatusUnauthorized)
		return
	}
	claims := auth.Claims{Typ: "app-mgmt", Azp: appID}
	claims.Subject = appID
	tok, err := h.jwt.IssueAccessToken(claims, h.cfg.AccessTTL)
	if err != nil {
		jsonError(w, "token generation failed", http.StatusInternalServerError)
		return
	}
	jsonResp(w, map[string]interface{}{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   int(h.cfg.AccessTTL.Seconds()),
	}, http.StatusOK)
}

// handleGetOwnAuthz returns the calling app's authorization. GET /api/app/authz
func (h *Handler) handleGetOwnAuthz(w http.ResponseWriter, r *http.Request) {
	authz, err := h.store.GetAppAuthz(appIDFromContext(r))
	if err != nil {
		jsonError(w, "failed to read authz", http.StatusInternalServerError)
		return
	}
	jsonResp(w, authz, http.StatusOK)
}

// handleSetOwnAuthz replaces the calling app's authorization. PUT /api/app/authz
func (h *Handler) handleSetOwnAuthz(w http.ResponseWriter, r *http.Request) {
	appID := appIDFromContext(r)
	var authz store.AppAuthz
	if err := readJSON(r, &authz); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	authz.AppID = appID // the credential is authoritative; ignore any body app_id
	if err := h.store.SaveAppAuthz(&authz); err != nil {
		jsonError(w, "failed to save authz", http.StatusInternalServerError)
		return
	}
	h.audit("app_authz_updated", appID, getClientIP(r), map[string]interface{}{"app_id": appID, "via": "self"})
	jsonResp(w, &authz, http.StatusOK)
}

// handleAppBootstrap is idempotent authz-as-code for the calling app: it
// declares the app's roles, role→permission map, and assignments. Safe to call
// on every deploy. POST /api/app/bootstrap
func (h *Handler) handleAppBootstrap(w http.ResponseWriter, r *http.Request) {
	appID := appIDFromContext(r)
	var req struct {
		Roles           []string            `json:"roles"`
		Permissions     []string            `json:"permissions"`
		RolePermissions map[string][]string `json:"role_permissions"`
		Assignments     []struct {
			User  string   `json:"user"`
			Group string   `json:"group"`
			Roles []string `json:"roles"`
		} `json:"assignments"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	authz := &store.AppAuthz{
		AppID:            appID,
		Roles:            req.Roles,
		Permissions:      req.Permissions,
		RolePermissions:  req.RolePermissions,
		UserAssignments:  map[string][]string{},
		GroupAssignments: map[string][]string{},
	}
	for _, a := range req.Assignments {
		if a.User != "" {
			authz.UserAssignments[a.User] = a.Roles
		}
		if a.Group != "" {
			authz.GroupAssignments[a.Group] = a.Roles
		}
	}
	if err := h.store.SaveAppAuthz(authz); err != nil {
		jsonError(w, "bootstrap failed", http.StatusInternalServerError)
		return
	}
	h.audit("app_bootstrap", appID, getClientIP(r), map[string]interface{}{"app_id": appID})
	jsonResp(w, map[string]interface{}{
		"status":            "ok",
		"app_id":            appID,
		"roles_count":       len(authz.Roles),
		"assignments_count": len(authz.UserAssignments) + len(authz.GroupAssignments),
	}, http.StatusOK)
}

// handleAppSettings returns the calling app's own settings (no secret).
// GET /api/app/settings
func (h *Handler) handleAppSettings(w http.ResponseWriter, r *http.Request) {
	app, err := h.store.GetApp(appIDFromContext(r))
	if err != nil {
		jsonError(w, "app not found", http.StatusNotFound)
		return
	}
	jsonResp(w, appView(app), http.StatusOK)
}
