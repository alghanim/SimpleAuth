package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"simpleauth/internal/auth"
	"simpleauth/internal/store"
)

func tokenPerms(t *testing.T, jwtStr string) []string {
	t.Helper()
	parts := strings.Split(jwtStr, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var c struct {
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatalf("unmarshal perms: %v", err)
	}
	return c.Permissions
}

// TestHomeAppRoleModel covers the v2 reshape: the default ("home") app IS the v1
// global world — a user's per-user global roles, the global role→permission
// catalog, direct perms, and default_roles all flow into the home token. The same
// global roles must NEVER leak into a NAMED app's token (named apps are strictly
// per-app; the global-roles fallback is gone for them).
func TestHomeAppRoleModel(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()

	// Global registry: define the role→permission catalog + permission registry.
	doJSON(h, "PUT", "/api/admin/permissions", []string{"invoice:write", "extra:perm"}, adm)
	doJSON(h, "PUT", "/api/admin/role-permissions", map[string][]string{
		"admin":  {"invoice:write"},
		"viewer": {},
	}, adm)

	// Alice gets the global role "admin" via the per-user roles editor (= her
	// home-app role).
	w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{
		"display_name": "Alice", "password": "pass1234",
	}, adm)
	var alice map[string]interface{}
	parseJSON(t, w, &alice)
	aliceGUID := alice["guid"].(string)
	s.SetIdentityMapping("local", "alice", aliceGUID)

	if w := doJSON(h, "PUT", "/api/admin/users/"+aliceGUID+"/roles", []string{"admin"}, adm); w.Code != http.StatusOK {
		t.Fatalf("set roles: %d %s", w.Code, w.Body.String())
	}
	// ...stored in the global per-user role store, and reads back through the API.
	if w := doJSON(h, "GET", "/api/admin/users/"+aliceGUID+"/roles", nil, adm); w.Code != http.StatusOK {
		t.Fatalf("get roles: %d", w.Code)
	} else {
		var roles []string
		parseJSON(t, w, &roles)
		if len(roles) != 1 || roles[0] != "admin" {
			t.Fatalf("get roles = %v, want [admin]", roles)
		}
	}
	// Direct (non-role) permission for Alice — inherited by the home app only.
	doJSON(h, "PUT", "/api/admin/users/"+aliceGUID+"/permissions", []string{"extra:perm"}, adm)

	login := func(appID string) map[string]interface{} {
		body := map[string]interface{}{"username": "alice", "password": "pass1234"}
		if appID != "" {
			body["app_id"] = appID
		}
		w := doJSON(h, "POST", "/api/auth/login", body, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("login app=%q: %d %s", appID, w.Code, w.Body.String())
		}
		var tok map[string]interface{}
		parseJSON(t, w, &tok)
		return tok
	}

	// Home app (no app_id): token carries the assigned role + role-derived perm
	// (inherited from the global catalog) + the direct perm.
	at := login("")["access_token"].(string)
	if roles := tokenRoles(t, at); !hasAud(roles, "admin") {
		t.Fatalf("home token should carry [admin], got %v", roles)
	}
	if perms := tokenPerms(t, at); !hasAud(perms, "invoice:write") || !hasAud(perms, "extra:perm") {
		t.Fatalf("home token perms should include invoice:write + extra:perm, got %v", perms)
	}

	// Named app "billing" with its own authz that does NOT assign alice: her
	// home-app role must NOT leak into the billing token.
	doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "billing", "audience": "billing"}, adm)
	doJSON(h, "PUT", "/api/admin/apps/billing/authz", map[string]interface{}{"roles": []string{"clerk"}}, adm)
	bt := login("billing")["access_token"].(string)
	if roles := tokenRoles(t, bt); len(roles) != 0 {
		t.Fatalf("billing token must have no roles for unassigned alice (no global leak), got %v", roles)
	}
	if perms := tokenPerms(t, bt); len(perms) != 0 {
		t.Fatalf("billing token must not inherit home/direct perms, got %v", perms)
	}
}

// TestHomeAppDefaultRolesBaseline: default_roles are the home app's baseline for
// users with no explicit assignment, and an explicit assignment overrides it.
func TestHomeAppDefaultRolesBaseline(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()

	doJSON(h, "PUT", "/api/admin/role-permissions", map[string][]string{"viewer": {}, "admin": {}}, adm)
	doJSON(h, "PUT", "/api/admin/defaults/roles", []string{"viewer"}, adm)

	mkLogin := func(username string) string {
		w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{
			"display_name": username, "password": "pass1234",
		}, adm)
		var u map[string]interface{}
		parseJSON(t, w, &u)
		guid := u["guid"].(string)
		s.SetIdentityMapping("local", username, guid)
		return guid
	}

	// Unassigned user -> gets the default_roles baseline in the home token.
	mkLogin("newbie")
	w := doJSON(h, "POST", "/api/auth/login", map[string]interface{}{"username": "newbie", "password": "pass1234"}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("newbie login: %d %s", w.Code, w.Body.String())
	}
	var tok map[string]interface{}
	parseJSON(t, w, &tok)
	if roles := tokenRoles(t, tok["access_token"].(string)); !hasAud(roles, "viewer") {
		t.Fatalf("unassigned user should get default_roles [viewer], got %v", roles)
	}

	// Explicitly-assigned user -> exact roles, NOT the default baseline.
	guid := mkLogin("boss")
	doJSON(h, "PUT", "/api/admin/users/"+guid+"/roles", []string{"admin"}, adm)
	w = doJSON(h, "POST", "/api/auth/login", map[string]interface{}{"username": "boss", "password": "pass1234"}, nil)
	parseJSON(t, w, &tok)
	if roles := tokenRoles(t, tok["access_token"].(string)); !hasAud(roles, "admin") || hasAud(roles, "viewer") {
		t.Fatalf("assigned user should get [admin] only (no default baseline), got %v", roles)
	}
}

// TestDefaultAppAuthzSurfaceForbidden: the per-app authz surfaces (admin editor +
// self-service GET/PUT/bootstrap) refuse the default app, since the home app's
// roles live in the global store, not its AppAuthz. This keeps the legacy client
// secret / a home-app admin from touching that surface. Named apps are unaffected.
func TestDefaultAppAuthzSurfaceForbidden(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()
	defID := h.defaultAppID()

	// Admin per-app authz editor on the default app -> 403.
	if w := doJSON(h, "PUT", "/api/admin/apps/"+defID+"/authz", map[string]interface{}{"roles": []string{"x"}}, adm); w.Code != http.StatusForbidden {
		t.Fatalf("admin authz PUT on default app: want 403, got %d %s", w.Code, w.Body.String())
	}

	// Self-service surface on the default app -> 403 (needs the app to exist with a
	// secret so requireApp authenticates before the guard fires).
	secret := "home-secret-1234"
	hash, _ := auth.HashPassword(secret)
	if err := s.CreateApp(&store.App{AppID: defID, Audience: defID, SecretHash: hash}); err != nil {
		t.Fatalf("create default app: %v", err)
	}
	creds := basicAuth(defID, secret)
	cases := []struct {
		method, path string
		body         interface{}
	}{
		{"GET", "/api/app/authz", nil},
		{"PUT", "/api/app/authz", map[string]interface{}{"roles": []string{"x"}}},
		{"POST", "/api/app/bootstrap", map[string]interface{}{"roles": []string{"x"}}},
	}
	for _, tc := range cases {
		if w := doJSON(h, tc.method, tc.path, tc.body, creds); w.Code != http.StatusForbidden {
			t.Fatalf("%s %s on default app: want 403, got %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
	}

	// Sanity: a NAMED app's self-service authz still works (guard is default-only).
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "billing", "audience": "billing"}, adm)
	var app map[string]interface{}
	parseJSON(t, w, &app)
	if w := doJSON(h, "GET", "/api/app/authz", nil, basicAuth("billing", app["app_secret"].(string))); w.Code != http.StatusOK {
		t.Fatalf("named app self-service authz GET: want 200, got %d %s", w.Code, w.Body.String())
	}
}

// TestHomeAppRequireAssignment: require_assignment on the home app means an
// explicit global-role grant is required. The default_roles baseline does NOT
// satisfy it (fails closed); an explicitly-assigned user is granted exactly their
// roles with no baseline added.
func TestHomeAppRequireAssignment(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()
	defID := h.defaultAppID()

	if err := s.CreateApp(&store.App{AppID: defID, Audience: defID, RequireAssignment: true}); err != nil {
		t.Fatalf("create default app: %v", err)
	}
	doJSON(h, "PUT", "/api/admin/role-permissions", map[string][]string{"viewer": {}, "admin": {}}, adm)
	doJSON(h, "PUT", "/api/admin/defaults/roles", []string{"viewer"}, adm)

	mk := func(name string, roles []string) {
		w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{"display_name": name, "password": "pass1234"}, adm)
		var u map[string]interface{}
		parseJSON(t, w, &u)
		guid := u["guid"].(string)
		s.SetIdentityMapping("local", name, guid)
		if roles != nil {
			doJSON(h, "PUT", "/api/admin/users/"+guid+"/roles", roles, adm)
		}
	}

	// No global role -> default_roles do NOT satisfy require_assignment -> DENIED.
	mk("nobody", nil)
	if w := doJSON(h, "POST", "/api/auth/login", map[string]interface{}{"username": "nobody", "password": "pass1234"}, nil); w.Code != http.StatusForbidden {
		t.Fatalf("require_assignment home app: unassigned user must be denied, got %d %s", w.Code, w.Body.String())
	}

	// Explicit global role -> granted with exactly that role (no default baseline).
	mk("somebody", []string{"admin"})
	w := doJSON(h, "POST", "/api/auth/login", map[string]interface{}{"username": "somebody", "password": "pass1234"}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("require_assignment home app: user with global role must be granted, got %d %s", w.Code, w.Body.String())
	}
	var tok map[string]interface{}
	parseJSON(t, w, &tok)
	if roles := tokenRoles(t, tok["access_token"].(string)); !hasAud(roles, "admin") || hasAud(roles, "viewer") {
		t.Fatalf("want [admin] only (no default baseline), got %v", roles)
	}
}

// TestDefaultAppReservedAndUndeletable: the default ("home") app is first-class —
// it cannot be deleted, its id cannot be re-registered as a named app, it cannot
// enable local users, and its per-app authz GET is refused. Named apps are
// unaffected. This keeps the home/named split (which keys off the default app id)
// from being subverted by re-registering or repurposing that id.
func TestDefaultAppReservedAndUndeletable(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()
	defID := h.defaultAppID()

	if w := doJSON(h, "DELETE", "/api/admin/apps/"+defID, nil, adm); w.Code != http.StatusForbidden {
		t.Fatalf("delete default app: want 403, got %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": defID, "audience": defID}, adm); w.Code != http.StatusBadRequest {
		t.Fatalf("create app with reserved default id: want 400, got %d %s", w.Code, w.Body.String())
	}

	// allow_local_users cannot be enabled on the default app (would be dead config).
	if err := s.CreateApp(&store.App{AppID: defID, Audience: defID}); err != nil {
		t.Fatalf("seed default app: %v", err)
	}
	if w := doJSON(h, "PUT", "/api/admin/apps/"+defID, map[string]interface{}{"allow_local_users": true}, adm); w.Code != http.StatusBadRequest {
		t.Fatalf("enable local users on default app: want 400, got %d %s", w.Code, w.Body.String())
	}
	// ...but other updates to the default app still work.
	if w := doJSON(h, "PUT", "/api/admin/apps/"+defID, map[string]interface{}{"name": "Home"}, adm); w.Code != http.StatusOK {
		t.Fatalf("rename default app: want 200, got %d %s", w.Code, w.Body.String())
	}
	// admin GET authz on the default app -> 403 (matches the PUT guard).
	if w := doJSON(h, "GET", "/api/admin/apps/"+defID+"/authz", nil, adm); w.Code != http.StatusForbidden {
		t.Fatalf("admin GET authz on default app: want 403, got %d %s", w.Code, w.Body.String())
	}

	// A NAMED app is fully manageable (create + delete).
	if w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "billing", "audience": "billing"}, adm); w.Code != http.StatusCreated {
		t.Fatalf("create named app: want 201, got %d %s", w.Code, w.Body.String())
	}
	if w := doJSON(h, "DELETE", "/api/admin/apps/billing", nil, adm); w.Code != http.StatusOK {
		t.Fatalf("delete named app: want 200, got %d %s", w.Code, w.Body.String())
	}
}
