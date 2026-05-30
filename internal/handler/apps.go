package handler

import (
	"fmt"
	"sort"

	"simpleauth/internal/store"
)

// defaultAppID is the app_id of the default app (wraps the legacy single
// client). Used when a request carries no explicit app/client_id.
func (h *Handler) defaultAppID() string {
	if h.cfg.ClientID != "" {
		return h.cfg.ClientID
	}
	return "simpleauth"
}

// resolveApp returns the app a request is for. An empty clientID resolves to the
// default app; if the default app row doesn't exist yet (e.g. a fresh store
// before the startup migration ran, or in tests), a transient default is
// synthesized so tokens still issue. A named-but-unknown or disabled app is an
// error.
func (h *Handler) resolveApp(clientID string) (*store.App, error) {
	id := clientID
	if id == "" {
		id = h.defaultAppID()
	}
	a, err := h.store.GetApp(id)
	if err != nil {
		if id == h.defaultAppID() {
			return &store.App{AppID: id, Audience: id, RedirectURIs: h.cfg.RedirectURIs}, nil
		}
		return nil, fmt.Errorf("unknown app: %s", id)
	}
	if a.Disabled {
		return nil, fmt.Errorf("app disabled: %s", id)
	}
	return a, nil
}

// appAudience returns the audience string for an app (defaults to app_id).
func appAudience(a *store.App) string {
	if a.Audience != "" {
		return a.Audience
	}
	return a.AppID
}

// appAllowsRedirect reports whether redirectURI is permitted for app a. If the
// app declares its own redirect_uris, those are authoritative; otherwise it
// falls back to the global runtime allowlist.
func (h *Handler) appAllowsRedirect(a *store.App, redirectURI string) bool {
	if len(a.RedirectURIs) > 0 {
		return isAllowedRedirect(a.RedirectURIs, redirectURI)
	}
	return isAllowedRedirect(h.getRedirectURIs(), redirectURI)
}

// userAssignmentKeys returns the identifiers a user may be assigned to an app
// by: GUID, sAMAccountName, and preferred username.
func (h *Handler) userAssignmentKeys(user *store.User) []string {
	keys := make([]string, 0, 3)
	seen := map[string]bool{}
	for _, k := range []string{user.GUID, user.SAMAccountName, h.resolvePreferredUsername(user)} {
		if k != "" && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	return keys
}

// resolveTokenRoles computes the roles + permissions a token for `app` should
// carry for `user` (v2 M3). When the app has no per-app authorization configured
// it falls back to the global (v1) roles, so existing deployments keep working
// until they define per-app authz. `denied` is true when the app has
// require_assignment set and the user has no direct or group assignment.
func (h *Handler) resolveTokenRoles(app *store.App, user *store.User) (roles, perms []string, denied bool) {
	authz, _ := h.store.GetAppAuthz(app.AppID)
	hasPerApp := authz != nil && (len(authz.Roles) > 0 || len(authz.UserAssignments) > 0 || len(authz.GroupAssignments) > 0)

	if !hasPerApp {
		// v1 back-compat: the app hasn't defined its own authz yet, so carry the
		// global roles/permissions exactly as v1 did.
		gRoles, _ := h.store.GetUserRoles(user.GUID)
		return gRoles, h.resolveUserPermissions(user.GUID, gRoles), false
	}

	roleSet := map[string]struct{}{}
	assigned := false
	add := func(rs []string) {
		for _, r := range rs {
			roleSet[r] = struct{}{}
			assigned = true
		}
	}
	for _, key := range h.userAssignmentKeys(user) {
		add(authz.UserAssignments[key])
	}
	for _, g := range user.Groups {
		add(authz.GroupAssignments[g])
	}

	roles = sortedKeys(roleSet)

	permSet := map[string]struct{}{}
	for _, r := range roles {
		for _, p := range authz.RolePermissions[r] {
			permSet[p] = struct{}{}
		}
	}
	perms = sortedKeys(permSet)

	// require_assignment denies directory users with no assignment. App-local
	// users (owned by this app) are exempt — handled in M5.
	if app.RequireAssignment && !assigned {
		denied = true
	}
	return roles, perms, denied
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
