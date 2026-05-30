package handler

import (
	"net/http"
	"testing"
)

// TestH5_RefreshKeepsPerAppScope covers Audit Pass 2 / H5: refreshing an
// app-scoped token must recompute per-app roles + the require_assignment gate, not
// re-stamp the app audience onto the user's GLOBAL roles (privilege escalation) and
// not survive de-assignment.
func TestH5_RefreshKeepsPerAppScope(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()

	doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"app_id": "billing", "audience": "billing", "require_assignment": true,
	}, adm)
	doJSON(h, "PUT", "/api/admin/apps/billing/authz", map[string]interface{}{
		"user_assignments": map[string][]string{"carol": {"viewer"}},
	}, adm)

	w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{
		"display_name": "Dir Carol", "password": "carolpass123",
	}, adm)
	var carol map[string]interface{}
	parseJSON(t, w, &carol)
	guid := carol["guid"].(string)
	s.SetIdentityMapping("local", "carol", guid)
	s.SetUserRoles(guid, []string{"superadmin"}) // global role must never appear in a billing token

	login := func() map[string]interface{} {
		w := doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
			"username": "carol", "password": "carolpass123", "app_id": "billing",
		}, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("login: %d %s", w.Code, w.Body.String())
		}
		var tok map[string]interface{}
		parseJSON(t, w, &tok)
		return tok
	}

	tok := login()
	at := tok["access_token"].(string)
	if roles := tokenRoles(t, at); !hasAud(roles, "viewer") || hasAud(roles, "superadmin") {
		t.Fatalf("login token roles want [viewer], got %v", roles)
	}

	// refresh: roles must stay [viewer], NOT escalate to the global superadmin
	w = doJSON(h, "POST", "/api/auth/refresh", map[string]interface{}{"refresh_token": tok["refresh_token"].(string)}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", w.Code, w.Body.String())
	}
	var rt map[string]interface{}
	parseJSON(t, w, &rt)
	rat := rt["access_token"].(string)
	if roles := tokenRoles(t, rat); !hasAud(roles, "viewer") || hasAud(roles, "superadmin") {
		t.Fatalf("refresh must keep per-app roles [viewer], got %v (escalation = H5)", roles)
	}
	if auds := tokenAudiences(t, rat); !hasAud(auds, "billing") {
		t.Fatalf("refresh must keep aud [billing], got %v", auds)
	}

	// de-assign carol, then refresh again -> require_assignment denies on refresh
	doJSON(h, "PUT", "/api/admin/apps/billing/authz", map[string]interface{}{
		"user_assignments": map[string][]string{},
	}, adm)
	if w := doJSON(h, "POST", "/api/auth/refresh", map[string]interface{}{"refresh_token": rt["refresh_token"].(string)}, nil); w.Code != http.StatusForbidden {
		t.Fatalf("refresh after de-assignment must be denied, got %d %s", w.Code, w.Body.String())
	}
}

// TestH6_RequireAssignmentFailsClosed covers Audit Pass 2 / H6: an app that sets
// require_assignment=true but has NOT defined any per-app authz must DENY directory
// users (fail closed), not fall back to admitting them with their global roles.
func TestH6_RequireAssignmentFailsClosed(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()

	// app with require_assignment=true and NO authz populated
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"app_id": "reqasn", "audience": "reqasn", "require_assignment": true,
	}, adm)
	if w.Code != http.StatusCreated {
		t.Fatalf("create app: %d %s", w.Code, w.Body.String())
	}

	// a directory user with a global role
	w = doJSON(h, "POST", "/api/admin/users", map[string]interface{}{
		"display_name": "Dir Bob", "password": "bobpass123",
	}, adm)
	var bob map[string]interface{}
	parseJSON(t, w, &bob)
	guid := bob["guid"].(string)
	s.SetIdentityMapping("local", "bob", guid)
	s.SetUserRoles(guid, []string{"superadmin"}) // global role must NOT leak through

	// require_assignment + no assignment => DENIED (was: 200 with global roles)
	if w := doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "bob", "password": "bobpass123", "app_id": "reqasn",
	}, nil); w.Code != http.StatusForbidden {
		t.Fatalf("unassigned directory user must be denied at a require_assignment app, got %d %s", w.Code, w.Body.String())
	}

	// once assigned, login succeeds with the per-app role only
	if w := doJSON(h, "PUT", "/api/admin/apps/reqasn/authz", map[string]interface{}{
		"user_assignments": map[string][]string{"bob": {"viewer"}},
	}, adm); w.Code != http.StatusOK {
		t.Fatalf("set authz: %d %s", w.Code, w.Body.String())
	}
	w = doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "bob", "password": "bobpass123", "app_id": "reqasn",
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("assigned user should log in: %d %s", w.Code, w.Body.String())
	}
	var tok map[string]interface{}
	parseJSON(t, w, &tok)
	at := tok["access_token"].(string)
	roles := tokenRoles(t, at)
	if !hasAud(roles, "viewer") {
		t.Fatalf("want per-app role viewer, got %v", roles)
	}
	if hasAud(roles, "superadmin") {
		t.Fatalf("global role superadmin must not leak into app token, got %v", roles)
	}
}
