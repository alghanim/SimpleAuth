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
