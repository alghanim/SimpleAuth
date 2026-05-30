package handler

import (
	"net/http"
	"testing"
)

// TestAppLocalUsers covers v2 M5: an app provisions its own local users (not in
// the directory), they authenticate scoped to that app only, app-local users
// shadow directory users of the same name at that app, the allow_local_users
// flag gates provisioning, and app-local users are exempt from
// require_assignment.
func TestAppLocalUsers(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()

	// portal: allows local users AND requires assignment
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"app_id": "portal", "audience": "portal",
		"allow_local_users": true, "require_assignment": true,
	}, adm)
	var app map[string]interface{}
	parseJSON(t, w, &app)
	secret := app["app_secret"].(string)

	// provision app-local user customer1 with role member
	if w := doJSON(h, "POST", "/api/app/users", map[string]interface{}{
		"username": "customer1", "password": "custpass", "display_name": "Customer One", "roles": []string{"member"},
	}, basicAuth("portal", secret)); w.Code != http.StatusCreated {
		t.Fatalf("provision customer1: %d %s", w.Code, w.Body.String())
	}

	// customer1 logs in scoped to portal -> aud=portal, role member
	w = doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "customer1", "password": "custpass", "app_id": "portal",
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("portal login: %d %s", w.Code, w.Body.String())
	}
	var tok map[string]interface{}
	parseJSON(t, w, &tok)
	at := tok["access_token"].(string)
	if auds := tokenAudiences(t, at); !hasAud(auds, "portal") {
		t.Fatalf("aud should be portal, got %v", auds)
	}
	if roles := tokenRoles(t, at); !hasAud(roles, "member") {
		t.Fatalf("role should be member, got %v", roles)
	}

	// app-local user is scoped: it does NOT authenticate against the default app
	if w := doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "customer1", "password": "custpass",
	}, nil); w.Code == http.StatusOK {
		t.Fatal("app-local customer1 must not authenticate against another app")
	}

	// require_assignment exemption: an app-local user with NO roles still gets in
	doJSON(h, "POST", "/api/app/users", map[string]interface{}{"username": "customer2", "password": "p2"}, basicAuth("portal", secret))
	if w := doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "customer2", "password": "p2", "app_id": "portal",
	}, nil); w.Code != http.StatusOK {
		t.Fatalf("app-local user should be exempt from require_assignment, got %d %s", w.Code, w.Body.String())
	}

	// app-local-first shadowing: a directory alice AND an app-local alice@portal
	w = doJSON(h, "POST", "/api/admin/users", map[string]interface{}{"display_name": "Dir Alice", "password": "dirpass"}, adm)
	var da map[string]interface{}
	parseJSON(t, w, &da)
	s.SetIdentityMapping("local", "alice", da["guid"].(string))
	doJSON(h, "POST", "/api/app/users", map[string]interface{}{"username": "alice", "password": "localpass", "roles": []string{"member"}}, basicAuth("portal", secret))

	// at portal, the app-local password works...
	if w := doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "alice", "password": "localpass", "app_id": "portal",
	}, nil); w.Code != http.StatusOK {
		t.Fatalf("app-local alice should log in at portal: %d %s", w.Code, w.Body.String())
	}
	// ...and the directory password does NOT (shadowed)
	if w := doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "alice", "password": "dirpass", "app_id": "portal",
	}, nil); w.Code == http.StatusOK {
		t.Fatal("directory password must not authenticate the shadowed app-local alice at portal")
	}

	// allow_local_users=false -> provisioning is forbidden
	w = doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "nolocal", "audience": "nl"}, adm)
	var app2 map[string]interface{}
	parseJSON(t, w, &app2)
	if w := doJSON(h, "POST", "/api/app/users", map[string]interface{}{"username": "x", "password": "y"},
		basicAuth("nolocal", app2["app_secret"].(string))); w.Code != http.StatusForbidden {
		t.Fatalf("provisioning on a non-local app should 403, got %d", w.Code)
	}
}
