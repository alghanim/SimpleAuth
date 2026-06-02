package handler

import (
	"errors"
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
		// Only synthesize the transient default app when the row genuinely does
		// not exist. A real store error (e.g. a DB outage) must fail closed rather
		// than return a default app with RequireAssignment=false, which would
		// silently drop a configured require_assignment (F26).
		if errors.Is(err, store.ErrAppNotFound) && id == h.defaultAppID() {
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

// userAssignmentKeys returns every identifier a user may be assigned to an app
// by: GUID, sAMAccountName, and all of the user's identity-mapping usernames
// (local, applocal, ldap, …). This lets an app assign a user by whatever name it
// knows them as (e.g. an app-local user's username).
func (h *Handler) userAssignmentKeys(user *store.User) []string {
	keys := make([]string, 0, 4)
	seen := map[string]bool{}
	add := func(k string) {
		if k != "" && !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	add(user.GUID)
	add(user.SAMAccountName)
	mappings, _ := h.store.GetMappingsForUser(user.GUID)
	for _, m := range mappings {
		add(m.ExternalID)
	}
	return keys
}

// resolveTokenRoles computes the roles + permissions a token for `app` should
// carry for `user` (v2).
//
// Two distinct authorization worlds, split on the app:
//
//   - The default ("home") app IS the v1 global world. Its roles are the user's
//     global per-user roles (GetUserRoles); an unassigned user falls back to the
//     global default_roles baseline; permissions resolve from the global
//     role→permission catalog plus the user's direct permissions. This is exactly
//     v1 behavior — but it now applies ONLY to the home app.
//   - A NAMED app is strictly per-app: roles come only from that app's AppAuthz
//     (direct user assignment + AD-group assignment) and permissions only from its
//     own role→permission map. Global per-user roles/permissions NEVER leak into a
//     named app's token (the v1 global-roles fallback is gone for named apps).
//
// Keeping the home app's per-user roles in the independent global role store
// (rather than the shared, whole-document-replaced AppAuthz blob) is deliberate:
// it keeps that data atomic per-user and out of reach of the self-service authz
// surface — the same isolation the codebase applies to AppAdmin.
//
// `denied` is true when require_assignment is set and the user has no qualifying
// assignment (a global role for the home app; a per-app assignment for a named
// app), so the app fails CLOSED rather than admitting users with no grant.
func (h *Handler) resolveTokenRoles(app *store.App, user *store.User) (roles, perms []string, denied bool) {
	if app.AppID == h.defaultAppID() {
		return h.resolveHomeAppRoles(app, user)
	}

	authz, _ := h.store.GetAppAuthz(app.AppID)
	roleSet := map[string]struct{}{}
	assigned := false
	if authz != nil {
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
	}

	// require_assignment denies directory users with no per-app assignment (H6).
	// App-local users owned by this app are inherently the app's and exempt (M5).
	if app.RequireAssignment && !assigned && user.OwnerAppID != app.AppID {
		return nil, nil, true
	}

	roles = sortedKeys(roleSet)
	permSet := map[string]struct{}{}
	if authz != nil {
		for _, r := range roles {
			for _, p := range authz.RolePermissions[r] {
				permSet[p] = struct{}{}
			}
		}
	}
	perms = sortedKeys(permSet)
	return roles, perms, false
}

// resolveHomeAppRoles resolves roles+perms for the default ("home") app from the
// global v1 stores: per-user roles, the role→permission catalog, direct perms,
// and the default_roles baseline. See resolveTokenRoles for the rationale.
func (h *Handler) resolveHomeAppRoles(app *store.App, user *store.User) (roles, perms []string, denied bool) {
	gRoles, _ := h.store.GetUserRoles(user.GUID)
	assigned := len(gRoles) > 0

	// require_assignment on the home app means "explicit role grant required": an
	// admin must have assigned the user a global role. The default_roles baseline
	// does NOT satisfy it, so the app still fails CLOSED for users with no grant.
	if app.RequireAssignment && !assigned && user.OwnerAppID != app.AppID {
		return nil, nil, true
	}

	roleSet := map[string]struct{}{}
	for _, r := range gRoles {
		roleSet[r] = struct{}{}
	}
	if !assigned {
		if def, _ := h.store.GetDefaultRoles(); len(def) > 0 {
			for _, r := range def {
				roleSet[r] = struct{}{}
			}
		}
	}
	roles = sortedKeys(roleSet)

	permSet := map[string]struct{}{}
	global, _ := h.store.GetRolePermissions()
	for _, r := range roles {
		for _, p := range global[r] {
			permSet[p] = struct{}{}
		}
	}
	directPerms, _ := h.store.GetUserPermissions(user.GUID)
	for _, p := range directPerms {
		permSet[p] = struct{}{}
	}
	perms = sortedKeys(permSet)
	return roles, perms, false
}

// matchAutoProvisionUser finds a directory user whose display name or email equals
// a verified Kerberos principal's username, for first-login auto-provisioning.
// App-local users (OwnerAppID set) are excluded: their display_name/email are
// attacker-controlled (set via /api/app/users), so a match must never bind a
// directory principal to an app-owned account (M12).
func matchAutoProvisionUser(users []*store.User, username string) string {
	for _, u := range users {
		if u.OwnerAppID != "" {
			continue
		}
		if u.DisplayName == username || u.Email == username {
			return u.GUID
		}
	}
	return ""
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
