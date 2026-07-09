package handler

import (
	"net/http"
	"testing"
)

// mkAppWithURL creates a require_assignment app with a base_url and a viewer role.
func mkAppWithURL(t *testing.T, h *Handler, adm map[string]string, id string, requireAssignment bool) {
	t.Helper()
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"app_id": id, "audience": id, "base_url": "https://" + id + ".example.com",
		"icon": "/.well-known/ops-module-icon.svg", "require_assignment": requireAssignment,
	}, adm)
	if w.Code != http.StatusCreated {
		t.Fatalf("create %s: %d %s", id, w.Code, w.Body.String())
	}
	doJSON(h, "PUT", "/api/admin/apps/"+id+"/authz", map[string]interface{}{
		"roles":            []string{"viewer"},
		"role_permissions": map[string][]string{"viewer": {id + ":read"}},
	}, adm)
}

// TestSA2_UserApps covers SA-2's acceptance: a user assigned to A and C (not B)
// gets exactly A and C; an open (require_assignment=false) app is included; a
// non-launchable app (no base_url) is excluded; a token of any audience works;
// disabling an app removes it; and the ETag supports 304 revalidation.
func TestSA2_UserApps(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()

	// user alice
	w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{"display_name": "Alice", "password": "pass1234"}, adm)
	var user map[string]interface{}
	parseJSON(t, w, &user)
	s.SetIdentityMapping("local", "alice", user["guid"].(string))

	// apps: a-app, b-app, c-app require assignment; open-app is open; nourl-app has no base_url
	mkAppWithURL(t, h, adm, "a-app", true)
	mkAppWithURL(t, h, adm, "b-app", true)
	mkAppWithURL(t, h, adm, "c-app", true)
	mkAppWithURL(t, h, adm, "open-app", false)
	// non-launchable: open but no base_url
	doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "nourl-app", "audience": "nourl-app"}, adm)

	// alice is assigned to a-app and c-app only
	for _, id := range []string{"a-app", "c-app"} {
		doJSON(h, "PUT", "/api/admin/apps/"+id+"/authz", map[string]interface{}{
			"roles":            []string{"viewer"},
			"role_permissions": map[string][]string{"viewer": {id + ":read"}},
			"user_assignments": map[string][]string{"alice": {"viewer"}},
		}, adm)
	}

	// login with NO app_id -> a default-audience token; SA-2 must accept any audience
	w = doJSON(h, "POST", "/api/auth/login", map[string]interface{}{"username": "alice", "password": "pass1234"}, nil)
	var tok map[string]interface{}
	parseJSON(t, w, &tok)
	bearer := map[string]string{"Authorization": "Bearer " + tok["access_token"].(string)}

	got := func(hdr map[string]string) ([]string, string) {
		w := doJSON(h, "GET", "/api/user/apps", nil, hdr)
		if w.Code != http.StatusOK {
			t.Fatalf("GET /api/user/apps: %d %s", w.Code, w.Body.String())
		}
		var apps []map[string]interface{}
		parseJSON(t, w, &apps)
		ids := make([]string, 0, len(apps))
		for _, a := range apps {
			ids = append(ids, a["app_id"].(string))
		}
		return ids, w.Header().Get("ETag")
	}

	ids, etag := got(bearer)
	// expect exactly a-app, c-app, open-app (sorted); NOT b-app (unassigned) or nourl-app (non-launchable)
	want := map[string]bool{"a-app": true, "c-app": true, "open-app": true}
	if len(ids) != 3 || !want[ids[0]] || !want[ids[1]] || !want[ids[2]] {
		t.Fatalf("SA-2 apps = %v, want exactly [a-app c-app open-app]", ids)
	}
	if etag == "" {
		t.Fatal("expected an ETag header")
	}

	// ETag revalidation -> 304
	if w := doJSON(h, "GET", "/api/user/apps", nil, map[string]string{
		"Authorization": "Bearer " + tok["access_token"].(string), "If-None-Match": etag,
	}); w.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match should 304, got %d", w.Code)
	}

	// disabling c-app removes it
	doJSON(h, "PUT", "/api/admin/apps/c-app", map[string]interface{}{"disabled": true}, adm)
	ids2, _ := got(bearer)
	for _, id := range ids2 {
		if id == "c-app" {
			t.Fatalf("disabled c-app must not appear: %v", ids2)
		}
	}

	// token-class + auth discipline
	if w := doJSON(h, "GET", "/api/user/apps", nil, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token must be 401, got %d", w.Code)
	}
	if w := doJSON(h, "GET", "/api/user/apps", nil, map[string]string{"Authorization": "Bearer " + tok["refresh_token"].(string)}); w.Code != http.StatusUnauthorized {
		t.Fatalf("refresh token as bearer must be 401, got %d", w.Code)
	}
}

// TestSA2_AppLocalUserSeesOnlyOwnApp covers the eligibility gate: an app-local
// user can only ever authenticate into their owner app, so GET /api/user/apps
// must not show them other (even open) apps they could never enter.
func TestSA2_AppLocalUserSeesOnlyOwnApp(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()

	// owner app (allows local users) + an unrelated open app
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"app_id": "shop", "audience": "shop", "allow_local_users": true, "base_url": "https://shop.example.com",
	}, adm)
	var app map[string]interface{}
	parseJSON(t, w, &app)
	secret := app["app_secret"].(string)
	mkAppWithURL(t, h, adm, "open-app", false) // require_assignment=false, launchable

	// an app-local user of "shop"
	doJSON(h, "POST", "/api/app/users", map[string]interface{}{"username": "shopper", "password": "shoppass1"}, basicAuth("shop", secret))
	w = doJSON(h, "POST", "/api/auth/login", map[string]interface{}{"username": "shopper", "password": "shoppass1", "app_id": "shop"}, nil)
	var tok map[string]interface{}
	parseJSON(t, w, &tok)

	w = doJSON(h, "GET", "/api/user/apps", nil, map[string]string{"Authorization": "Bearer " + tok["access_token"].(string)})
	var apps []map[string]interface{}
	parseJSON(t, w, &apps)
	if len(apps) != 1 || apps[0]["app_id"] != "shop" {
		ids := []string{}
		for _, a := range apps {
			ids = append(ids, a["app_id"].(string))
		}
		t.Fatalf("app-local user must see only their owner app, got %v", ids)
	}
}

// TestSA2_DisabledUserRejected covers the fail-closed gate: a disabled user with
// a still-live token cannot enumerate apps.
func TestSA2_DisabledUserRejected(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()
	w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{"display_name": "Dan", "password": "pass1234"}, adm)
	var user map[string]interface{}
	parseJSON(t, w, &user)
	guid := user["guid"].(string)
	s.SetIdentityMapping("local", "dan", guid)
	w = doJSON(h, "POST", "/api/auth/login", map[string]interface{}{"username": "dan", "password": "pass1234"}, nil)
	var tok map[string]interface{}
	parseJSON(t, w, &tok)

	// disable the user directly, then try to enumerate with the still-live token
	u, _ := s.GetUser(guid)
	u.Disabled = true
	if err := s.UpdateUser(u); err != nil {
		t.Fatalf("disable user: %v", err)
	}
	if w := doJSON(h, "GET", "/api/user/apps", nil, map[string]string{"Authorization": "Bearer " + tok["access_token"].(string)}); w.Code != http.StatusUnauthorized {
		t.Fatalf("disabled user must be 401 at /api/user/apps, got %d", w.Code)
	}
}
