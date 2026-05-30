package handler

import (
	"net/http"
	"testing"
)

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
