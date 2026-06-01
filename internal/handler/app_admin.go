package handler

import (
	"fmt"
	"net/http"
	"strings"
)

// Context keys for the per-app-admin path. ctxActor carries the audit principal
// (a human GUID for an app-admin request); ctxPrincipal distinguishes an
// app-admin (human, own login) request from an app-secret/token request.
const (
	ctxActor     contextKey = "actor"
	ctxPrincipal contextKey = "principal"
)

const principalAppAdmin = "app-admin"

// requireAppAdmin gates the app-management surface (/api/app-admin/...) for a
// HUMAN app admin using their own login, as an alternative to the app secret.
// Per-app login model: the app being managed is the app the caller logged INTO —
// carried in the token's Azp claim — never a path parameter, so a token can only
// ever manage its own app. It (1) requires a genuine, non-impersonated user access
// token (validateAccessToken rejects app-mgmt/refresh/id_token + revoked); (2)
// resolves that app and rejects unknown/disabled; (3) resolves the human and
// rejects disabled/merged accounts; (4) verifies LIVE per-app admin membership.
// The feature is implicitly OFF until a user is assigned to some app's admin list
// (an empty list denies everyone). Every denial returns an identical 403.
func (h *Handler) requireAppAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		deny := func() { jsonError(w, "forbidden", http.StatusForbidden) }

		// (1) Genuine, non-impersonated user access token. Azp identifies the app
		// the caller logged into — and thus the only app this token may manage.
		claims, err := h.validateAccessToken(extractBearerToken(r))
		if err != nil || claims.Impersonated || claims.Azp == "" {
			deny()
			return
		}

		// (2) That app must exist and be enabled (resolveApp rejects disabled/unknown).
		targetApp, err := h.resolveApp(claims.Azp)
		if err != nil {
			deny()
			return
		}

		// (3) Resolve the human; reject disabled or merged-away accounts (the token
		// could still be within TTL after the account was disabled/merged).
		user, err := h.store.ResolveUser(claims.Subject)
		if err != nil || user == nil || user.Disabled || user.MergedInto != "" {
			deny()
			return
		}

		// (4) Live, atomic per-app admin membership check for the token's own app.
		isAdmin, err := h.store.IsAppAdmin(targetApp.AppID, user.GUID)
		if err != nil || !isAdmin {
			deny()
			return
		}

		ctx := setContext(r.Context(), ctxAppID, targetApp.AppID)
		ctx = setContext(ctx, ctxActor, user.GUID)
		ctx = setContext(ctx, ctxPrincipal, principalAppAdmin)
		next(w, r.WithContext(ctx))
	}
}

// appActor returns the audit principal for an /api/app/* mutation: the human GUID
// for an app-admin request, or the app_id for an app-secret/token request. It
// fails closed for the app-admin case — it returns the human GUID (empty only if
// the gate failed to set it) and never falls back to the app id, so an app-admin
// action can never be silently mis-attributed to the app principal.
func (h *Handler) appActor(r *http.Request) string {
	if getContext(r.Context(), ctxPrincipal) == principalAppAdmin {
		return getContext(r.Context(), ctxActor)
	}
	return appIDFromContext(r)
}

// appActorKind reports whether the /api/app/* caller is a human app admin
// ("user") or the app credential ("app"), for audit data.
func (h *Handler) appActorKind(r *http.Request) string {
	if getContext(r.Context(), ctxPrincipal) == principalAppAdmin {
		return "user"
	}
	return "app"
}

// resolveUserRef resolves a user reference (a GUID, or a username/external id) to
// a canonical user GUID. Admin membership is stored by GUID — the strong,
// non-spoofable key — so callers resolve at grant time. A username is matched
// against identity mappings and must resolve to exactly one user.
func (h *Handler) resolveUserRef(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", fmt.Errorf("user reference required")
	}
	if u, err := h.store.ResolveUser(ref); err == nil && u != nil {
		return u.GUID, nil // ref was a GUID
	}
	mappings, err := h.store.ListAllMappings()
	if err != nil {
		return "", err
	}
	var found string
	for _, m := range mappings {
		if strings.EqualFold(m.ExternalID, ref) {
			if found != "" && found != m.UserGUID {
				return "", fmt.Errorf("ambiguous user %q — specify user_guid", ref)
			}
			found = m.UserGUID
		}
	}
	if found == "" {
		return "", fmt.Errorf("unknown user %q", ref)
	}
	return found, nil
}

// --- shared app-admin membership handlers (actor/appID supplied by the wrappers) ---

func (h *Handler) addAppAdmin(w http.ResponseWriter, r *http.Request, appID, actor, actorKind string) {
	var req struct {
		User     string `json:"user"`
		UserGUID string `json:"user_guid"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	ref := req.UserGUID
	if ref == "" {
		ref = req.User
	}
	guid, err := h.resolveUserRef(ref)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.store.AddAppAdmin(appID, guid, actor); err != nil {
		jsonError(w, "failed to add app admin", http.StatusInternalServerError)
		return
	}
	h.audit("app_admin_added", actor, getClientIP(r), map[string]interface{}{"app_id": appID, "target_guid": guid, "actor_kind": actorKind})
	jsonResp(w, map[string]string{"status": "added", "user_guid": guid}, http.StatusOK)
}

func (h *Handler) removeAppAdmin(w http.ResponseWriter, r *http.Request, appID, actor, actorKind string) {
	ref := pathParam(r, "user")
	// Resolve to a GUID; fall back to the raw reference so a dangling membership
	// (whose user record was deleted) can still be cleaned up by GUID.
	guid, err := h.resolveUserRef(ref)
	if err != nil {
		guid = strings.TrimSpace(ref)
	}
	if err := h.store.RemoveAppAdmin(appID, guid); err != nil {
		jsonError(w, "failed to remove app admin", http.StatusInternalServerError)
		return
	}
	h.audit("app_admin_removed", actor, getClientIP(r), map[string]interface{}{"app_id": appID, "target_guid": guid, "actor_kind": actorKind})
	jsonResp(w, map[string]string{"status": "removed", "user_guid": guid}, http.StatusOK)
}

func (h *Handler) listAppAdmins(w http.ResponseWriter, r *http.Request, appID string) {
	admins, err := h.store.ListAppAdmins(appID)
	if err != nil {
		jsonError(w, "failed to list app admins", http.StatusInternalServerError)
		return
	}
	jsonResp(w, map[string]interface{}{"app_id": appID, "admins": admins}, http.StatusOK)
}

// --- master-admin wrappers: /api/admin/apps/{app_id}/admins (requireMasterAdmin) ---

func (h *Handler) handleListAppAdminsMaster(w http.ResponseWriter, r *http.Request) {
	app, err := h.resolveApp(pathParam(r, "app_id"))
	if err != nil {
		jsonError(w, "unknown app", http.StatusNotFound)
		return
	}
	h.listAppAdmins(w, r, app.AppID)
}

func (h *Handler) handleAddAppAdminMaster(w http.ResponseWriter, r *http.Request) {
	app, err := h.resolveApp(pathParam(r, "app_id"))
	if err != nil {
		jsonError(w, "unknown app", http.StatusNotFound)
		return
	}
	h.addAppAdmin(w, r, app.AppID, "admin", "master")
}

func (h *Handler) handleRemoveAppAdminMaster(w http.ResponseWriter, r *http.Request) {
	app, err := h.resolveApp(pathParam(r, "app_id"))
	if err != nil {
		jsonError(w, "unknown app", http.StatusNotFound)
		return
	}
	h.removeAppAdmin(w, r, app.AppID, "admin", "master")
}

// --- app-secret wrappers: /api/app/admins (requireApp) — app_id from credential ---

func (h *Handler) handleListOwnAdmins(w http.ResponseWriter, r *http.Request) {
	h.listAppAdmins(w, r, appIDFromContext(r))
}

func (h *Handler) handleAddOwnAdmin(w http.ResponseWriter, r *http.Request) {
	appID := appIDFromContext(r)
	h.addAppAdmin(w, r, appID, "app:"+appID, "app")
}

func (h *Handler) handleRemoveOwnAdmin(w http.ResponseWriter, r *http.Request) {
	appID := appIDFromContext(r)
	h.removeAppAdmin(w, r, appID, "app:"+appID, "app")
}
