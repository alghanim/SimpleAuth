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

// TestH8_DeleteAppPurgesLocalUsers covers Audit Pass 2 / H8: deleting an app must
// remove its app-local users + their identity mappings, so re-registering the same
// app_id cannot resurrect the old accounts (or their passwords) under a new owner.
func TestH8_DeleteAppPurgesLocalUsers(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()

	mkApp := func() string {
		w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
			"app_id": "tenant", "audience": "tenant", "allow_local_users": true,
		}, adm)
		if w.Code != http.StatusCreated {
			t.Fatalf("create app: %d %s", w.Code, w.Body.String())
		}
		var app map[string]interface{}
		parseJSON(t, w, &app)
		return app["app_secret"].(string)
	}

	secret := mkApp()
	if w := doJSON(h, "POST", "/api/app/users", map[string]interface{}{"username": "ghost", "password": "ghostpass1"}, basicAuth("tenant", secret)); w.Code != http.StatusCreated {
		t.Fatalf("provision: %d %s", w.Code, w.Body.String())
	}

	// delete the app
	if w := doJSON(h, "DELETE", "/api/admin/apps/tenant", nil, adm); w.Code != http.StatusOK && w.Code != http.StatusNoContent {
		t.Fatalf("delete app: %d %s", w.Code, w.Body.String())
	}
	// the app-local user + its applocal mapping must be gone
	if _, err := s.ResolveMapping("applocal:tenant", "ghost"); err == nil {
		t.Fatal("applocal mapping survived app deletion (H8 resurrection risk)")
	}

	// re-register the same app_id under a (notionally) new owner; the old account
	// must NOT authenticate
	secret2 := mkApp()
	if w := doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "ghost", "password": "ghostpass1", "app_id": "tenant",
	}, nil); w.Code == http.StatusOK {
		t.Fatal("resurrected app-local user authenticated at the reused app_id (H8)")
	}
	// and the new owner can cleanly re-provision the same username
	if w := doJSON(h, "POST", "/api/app/users", map[string]interface{}{"username": "ghost", "password": "newpass12"}, basicAuth("tenant", secret2)); w.Code != http.StatusCreated {
		t.Fatalf("re-provision after reuse should succeed, got %d %s", w.Code, w.Body.String())
	}
}

// TestH7_MgmtTokenIsNotAUserToken covers Audit Pass 2 / H7: an app-management
// token must not validate at user-resource boundaries, even when the app_id is
// chosen to collide with a victim's user GUID (the worst case — direct profile read).
func TestH7_MgmtTokenIsNotAUserToken(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()

	// a victim directory user
	w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{
		"display_name": "Victim Secret Name", "password": "victimpass1",
	}, adm)
	var victim map[string]interface{}
	parseJSON(t, w, &victim)
	guid := victim["guid"].(string) // a UUID, which is a valid app_id slug

	// an app whose id == the victim's GUID, so a mgmt token's sub == victim GUID
	w = doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": guid, "audience": "x"}, adm)
	if w.Code != http.StatusCreated {
		t.Fatalf("create colliding app: %d %s", w.Code, w.Body.String())
	}
	var app map[string]interface{}
	parseJSON(t, w, &app)
	secret := app["app_secret"].(string)

	// mint the management token
	w = doJSON(h, "POST", "/api/app/token", nil, basicAuth(guid, secret))
	if w.Code != http.StatusOK {
		t.Fatalf("mint mgmt token: %d %s", w.Code, w.Body.String())
	}
	var mt map[string]interface{}
	parseJSON(t, w, &mt)
	mgmt := mt["access_token"].(string)

	// it must be rejected as a user token at userinfo (not return the victim profile)
	w = doJSON(h, "GET", "/api/auth/userinfo", nil, map[string]string{"Authorization": "Bearer " + mgmt})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("mgmt token must be rejected at userinfo, got %d %s", w.Code, w.Body.String())
	}
	// it still works for its real purpose (app self-service)
	if w := doJSON(h, "GET", "/api/app/authz", nil, map[string]string{"Authorization": "Bearer " + mgmt}); w.Code != http.StatusOK {
		t.Fatalf("mgmt token should still authorize /api/app/*, got %d %s", w.Code, w.Body.String())
	}
}

// TestM10_DisabledAppStopsRefresh covers Audit Pass 2 / M10: refreshing a token
// whose app has been disabled/deleted must return a clean error, not mint a token
// (the disable kill switch) and not nil-deref/500 in resolveTokenRoles.
func TestM10_DisabledAppStopsRefresh(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()

	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"app_id": "shop", "audience": "shop", "allow_local_users": true,
	}, adm)
	var app map[string]interface{}
	parseJSON(t, w, &app)
	secret := app["app_secret"].(string)
	doJSON(h, "POST", "/api/app/users", map[string]interface{}{"username": "shopper", "password": "shoppass1"}, basicAuth("shop", secret))

	w = doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "shopper", "password": "shoppass1", "app_id": "shop",
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	var tok map[string]interface{}
	parseJSON(t, w, &tok)

	// disable the app, then refresh -> clean 401, no 500/panic
	sa, _ := s.GetApp("shop")
	sa.Disabled = true
	if err := s.UpdateApp(sa); err != nil {
		t.Fatalf("disable app: %v", err)
	}
	if w := doJSON(h, "POST", "/api/auth/refresh", map[string]interface{}{"refresh_token": tok["refresh_token"].(string)}, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("refresh into a disabled app must be 401, got %d %s", w.Code, w.Body.String())
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
