package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"simpleauth/internal/auth"
	"simpleauth/internal/store"
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

// TestL5_AppCredentialAuthOutcomes covers Audit Pass 2 / L5: the constant-time app
// credential check still returns the right outcomes (unknown app, wrong secret, and
// correct secret) — the dummy-hash path must not change behavior.
func TestL5_AppCredentialAuthOutcomes(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "known", "audience": "known"}, adm)
	var app map[string]interface{}
	parseJSON(t, w, &app)
	secret := app["app_secret"].(string)

	// unknown app_id -> 401 (and no panic from the dummy-hash branch)
	if w := doJSON(h, "POST", "/api/app/token", nil, basicAuth("does-not-exist", "whatever")); w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown app_id must be 401, got %d", w.Code)
	}
	// known app, wrong secret -> 401
	if w := doJSON(h, "POST", "/api/app/token", nil, basicAuth("known", "wrong")); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret must be 401, got %d", w.Code)
	}
	// known app, correct secret -> 200
	if w := doJSON(h, "POST", "/api/app/token", nil, basicAuth("known", secret)); w.Code != http.StatusOK {
		t.Fatalf("correct secret must be 200, got %d %s", w.Code, w.Body.String())
	}
}

// TestL4_RotateSecretRevokesMgmtTokens covers Audit Pass 2 / L4: rotating an app's
// secret must invalidate management tokens minted before the rotation.
func TestL4_RotateSecretRevokesMgmtTokens(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "rot", "audience": "rot"}, adm)
	var app map[string]interface{}
	parseJSON(t, w, &app)
	secret1 := app["app_secret"].(string)

	// mint a management token under the current secret
	w = doJSON(h, "POST", "/api/app/token", nil, basicAuth("rot", secret1))
	var mt map[string]interface{}
	parseJSON(t, w, &mt)
	mgmt := map[string]string{"Authorization": "Bearer " + mt["access_token"].(string)}
	if w := doJSON(h, "GET", "/api/app/authz", nil, mgmt); w.Code != http.StatusOK {
		t.Fatalf("mgmt token should work before rotation, got %d", w.Code)
	}

	// rotate the secret
	if w := doJSON(h, "POST", "/api/admin/apps/rot/rotate-secret", nil, adm); w.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", w.Code, w.Body.String())
	}
	// the pre-rotation management token is now rejected
	if w := doJSON(h, "GET", "/api/app/authz", nil, mgmt); w.Code != http.StatusUnauthorized {
		t.Fatalf("mgmt token minted before rotation must be revoked, got %d", w.Code)
	}
}

// TestL2_ImpersonationTokenIsScoped covers Audit Pass 2 / L2: impersonation tokens
// must carry an audience (default app when unspecified) and be scopable to a named
// app, rather than being aud-less with global roles.
func TestL2_ImpersonationTokenIsScoped(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()
	w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{"display_name": "Target", "password": "tpass1234"}, adm)
	var u map[string]interface{}
	parseJSON(t, w, &u)
	guid := u["guid"].(string)

	// default: token carries the default app's audience (test-client), not aud-less
	w = doJSON(h, "POST", "/api/auth/impersonate", map[string]interface{}{"target_guid": guid}, adm)
	if w.Code != http.StatusOK {
		t.Fatalf("impersonate: %d %s", w.Code, w.Body.String())
	}
	var tok map[string]interface{}
	parseJSON(t, w, &tok)
	if auds := tokenAudiences(t, tok["access_token"].(string)); len(auds) == 0 {
		t.Fatal("impersonation token must carry an audience (L2)")
	}

	// scoped to a named app
	doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "scoped", "audience": "scoped"}, adm)
	w = doJSON(h, "POST", "/api/auth/impersonate", map[string]interface{}{"target_guid": guid, "app_id": "scoped"}, adm)
	parseJSON(t, w, &tok)
	if auds := tokenAudiences(t, tok["access_token"].(string)); !hasAud(auds, "scoped") {
		t.Fatalf("impersonation token should be scoped to the named app, got %v", auds)
	}
}

// TestL1_SSORedirectUsesPerAppAllowlist covers Audit Pass 2 / L1: /login/sso must
// validate redirect_uri against the resolved app's own allowlist, not the global one.
func TestL1_SSORedirectUsesPerAppAllowlist(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()
	doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"app_id": "portal2", "audience": "portal2",
		"redirect_uris": []string{"https://portal.example.com/cb"},
	}, adm)

	// a URI outside portal2's allowlist is rejected up front
	if w := doJSON(h, "GET", "/login/sso?client_id=portal2&redirect_uri=https://evil.example.com", nil, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("redirect_uri outside the app's allowlist must be 400, got %d %s", w.Code, w.Body.String())
	}
	// a URI in portal2's allowlist passes the redirect check (the flow then continues
	// past it — Kerberos is unconfigured here, so it is NOT a 400 redirect rejection)
	if w := doJSON(h, "GET", "/login/sso?client_id=portal2&redirect_uri=https://portal.example.com/cb", nil, nil); w.Code == http.StatusBadRequest {
		t.Fatalf("redirect_uri inside the app's allowlist must not be rejected, got 400 %s", w.Body.String())
	}
}

// TestM16_AppCredentialRateLimit covers Audit Pass 2 / M16: the app_secret surface
// (token exchange + Basic auth) must be rate-limited to brake brute-force.
func TestM16_AppCredentialRateLimit(t *testing.T) {
	h, _ := testSetup(t)
	h.loginLimiter = newRateLimiter(3, time.Minute)
	adm := adminHeaders()
	doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "rl", "audience": "rl"}, adm)

	got429 := false
	for i := 0; i < 8; i++ {
		w := doJSON(h, "POST", "/api/app/token", nil, basicAuth("rl", "wrong-secret"))
		if w.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("app_secret brute-force on /api/app/token must be rate-limited (M16)")
	}
}

// TestM15_AppLocalPasswordPolicy covers Audit Pass 2 / M15: app-local provisioning
// and password reset must enforce the configured password policy.
func TestM15_AppLocalPasswordPolicy(t *testing.T) {
	h, _ := testSetup(t)
	// the effective policy comes from the runtime-settings cache (seeded from cfg
	// at construction), so bump it there rather than on cfg.
	rs := h.runtimeSettings.get()
	rs.PasswordMinLength = 10
	h.runtimeSettings.set(rs)
	adm := adminHeaders()
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"app_id": "pol", "audience": "pol", "allow_local_users": true,
	}, adm)
	var app map[string]interface{}
	parseJSON(t, w, &app)
	cred := basicAuth("pol", app["app_secret"].(string))

	// weak password rejected on create
	if w := doJSON(h, "POST", "/api/app/users", map[string]interface{}{"username": "weak", "password": "short"}, cred); w.Code != http.StatusBadRequest {
		t.Fatalf("weak app-local password must be rejected, got %d %s", w.Code, w.Body.String())
	}
	// compliant password accepted
	w = doJSON(h, "POST", "/api/app/users", map[string]interface{}{"username": "weak", "password": "longenough1"}, cred)
	if w.Code != http.StatusCreated {
		t.Fatalf("compliant password should be accepted, got %d %s", w.Code, w.Body.String())
	}
	var u map[string]interface{}
	parseJSON(t, w, &u)
	// weak password rejected on reset too
	if w := doJSON(h, "PUT", "/api/app/users/"+u["guid"].(string)+"/password", map[string]interface{}{"password": "x"}, cred); w.Code != http.StatusBadRequest {
		t.Fatalf("weak reset password must be rejected, got %d %s", w.Code, w.Body.String())
	}
}

// TestM13_EmptyGroupsClearStaleGroups covers Audit Pass 2 / M13: an LDAP re-sync
// that returns no groups (user removed from all groups) must clear the cached
// groups, not leave the stale set that keeps awarding group-derived roles.
func TestM13_EmptyGroupsClearStaleGroups(t *testing.T) {
	h, s := testSetup(t)
	u := &store.User{DisplayName: "Grouped User", Email: "g@corp", SAMAccountName: "guser", Groups: []string{"admins", "vpn"}}
	if err := s.CreateUser(u); err != nil {
		t.Fatalf("create: %v", err)
	}
	// re-sync after the user was removed from every group
	h.syncUserFromLDAP(u, &auth.LDAPResult{Username: "guser", DisplayName: "Grouped User", Email: "g@corp", Groups: nil})
	got, _ := s.GetUser(u.GUID)
	if len(got.Groups) != 0 {
		t.Fatalf("stale groups must be cleared on an empty LDAP result, got %v", got.Groups)
	}
}

// TestM12_AutoProvisionSkipsAppLocalUsers covers Audit Pass 2 / M12: Kerberos
// first-login auto-provisioning must not bind a verified directory principal to an
// app-local user whose (attacker-controlled) email/display_name happens to match.
func TestM12_AutoProvisionSkipsAppLocalUsers(t *testing.T) {
	users := []*store.User{
		{GUID: "app-owned", OwnerAppID: "shop", Email: "alice@corp"},
		{GUID: "dir-user", DisplayName: "alice@corp"},
	}
	// an app-local user must never be chosen, even if listed first
	if guid := matchAutoProvisionUser(users, "alice@corp"); guid != "dir-user" {
		t.Fatalf("auto-provision must pick the directory user, got %q", guid)
	}
	// with ONLY an app-local match, there is no binding at all
	onlyLocal := []*store.User{{GUID: "app-owned", OwnerAppID: "shop", Email: "bob@corp"}}
	if guid := matchAutoProvisionUser(onlyLocal, "bob@corp"); guid != "" {
		t.Fatalf("app-local match must not bind a principal, got %q", guid)
	}
}

// TestM11_ConfidentialGrantUsesPerAppSecret covers Audit Pass 2 / M11: a
// confidential grant (client_credentials) must authenticate against the named app's
// OWN secret, so neither another app's secret nor the global secret can mint a token
// scoped to an app the caller can't authenticate for.
func TestM11_ConfidentialGrantUsesPerAppSecret(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()
	tokenURL := "/realms/test-issuer/protocol/openid-connect/token"

	mk := func(id string) string {
		w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": id, "audience": id}, adm)
		var a map[string]interface{}
		parseJSON(t, w, &a)
		return a["app_secret"].(string)
	}
	secretA := mk("svca")
	secretB := mk("svcb")

	doForm := func(form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	cc := func(clientID, secret string) *httptest.ResponseRecorder {
		return doForm(url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}, "client_secret": {secret}})
	}

	// correct per-app secret -> 200, aud=svca
	w := cc("svca", secretA)
	if w.Code != http.StatusOK {
		t.Fatalf("client_credentials with svca's own secret: %d %s", w.Code, w.Body.String())
	}
	var tok map[string]interface{}
	parseJSON(t, w, &tok)
	if auds := tokenAudiences(t, tok["access_token"].(string)); !hasAud(auds, "svca") {
		t.Fatalf("aud should be svca, got %v", auds)
	}
	// app B's secret must NOT mint a token scoped to app A
	if w := cc("svca", secretB); w.Code == http.StatusOK {
		t.Fatal("app B's secret must not mint a token for app A (M11)")
	}
	// the global secret must NOT mint a token for a named app
	if w := cc("svca", "test-secret"); w.Code == http.StatusOK {
		t.Fatal("the global secret must not mint a token for a named app (M11)")
	}
}

// TestL3_ConcurrentLocalUserCreateIsAtomic covers Audit Pass 2 / L3: concurrent
// creates of the same app-local username must produce exactly one user, not race
// past the existence check and orphan duplicates.
func TestL3_ConcurrentLocalUserCreateIsAtomic(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"app_id": "race", "audience": "race", "allow_local_users": true,
	}, adm)
	var app map[string]interface{}
	parseJSON(t, w, &app)
	cred := basicAuth("race", app["app_secret"].(string))

	const n = 8
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := doJSON(h, "POST", "/api/app/users", map[string]interface{}{"username": "dup", "password": "racepass1"}, cred)
			codes <- w.Code
		}()
	}
	wg.Wait()
	close(codes)
	created := 0
	for c := range codes {
		if c == http.StatusCreated {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("exactly one concurrent create should succeed, got %d", created)
	}
	// confirm the store holds exactly one such user
	w = doJSON(h, "GET", "/api/app/users", nil, cred)
	var list struct {
		Users []map[string]interface{} `json:"users"`
	}
	parseJSON(t, w, &list)
	if len(list.Users) != 1 {
		t.Fatalf("want 1 provisioned user, got %d", len(list.Users))
	}
}

// TestM14_DeleteLocalUserFreesUsername covers Audit Pass 2 / M14: deleting an
// app-local user must remove its identity mapping so the username can be
// re-provisioned (previously the dangling mapping made create 409 forever).
func TestM14_DeleteLocalUserFreesUsername(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()

	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"app_id": "desk", "audience": "desk", "allow_local_users": true,
	}, adm)
	var app map[string]interface{}
	parseJSON(t, w, &app)
	secret := app["app_secret"].(string)
	cred := basicAuth("desk", secret)

	w = doJSON(h, "POST", "/api/app/users", map[string]interface{}{"username": "agent1", "password": "deskpass1"}, cred)
	var u map[string]interface{}
	parseJSON(t, w, &u)
	guid := u["guid"].(string)

	if w := doJSON(h, "DELETE", "/api/app/users/"+guid, nil, cred); w.Code != http.StatusOK {
		t.Fatalf("delete local user: %d %s", w.Code, w.Body.String())
	}
	// the same username must be re-provisionable (was 409 forever)
	if w := doJSON(h, "POST", "/api/app/users", map[string]interface{}{"username": "agent1", "password": "deskpass2"}, cred); w.Code != http.StatusCreated {
		t.Fatalf("re-provision after delete should succeed, got %d %s", w.Code, w.Body.String())
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

// TestM10_DisabledAppStopsOIDCRefresh pins the M10 guarantee on the SECOND
// refresh path — the OIDC `refresh_token` grant at the /realms/.../token
// endpoint — which resolves the app the same way (oidc.go handleOIDCTokenRefresh
// -> resolveApp) and must likewise refuse a disabled app. This closes the
// "both refresh paths" gap the ops-platform SA-6 review flagged: the sibling
// test above covers /api/auth/refresh; this covers the OIDC grant.
func TestM10_DisabledAppStopsOIDCRefresh(t *testing.T) {
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
	refreshToken := tok["refresh_token"].(string)

	// Sanity: the refresh token works at the OIDC grant BEFORE disabling — proving
	// the later 401 is the disabled-app guard, not a bad-token or wiring failure.
	// (Refresh is single-use, so mint a fresh one for the negative case below.)
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}
	req := httptest.NewRequest("POST", "/realms/test-issuer/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pre := httptest.NewRecorder()
	h.ServeHTTP(pre, req)
	if pre.Code != http.StatusOK {
		t.Fatalf("OIDC refresh before disable should succeed, got %d %s", pre.Code, pre.Body.String())
	}
	var refreshed map[string]interface{}
	parseJSON(t, pre, &refreshed)
	rt2 := refreshed["refresh_token"].(string)

	// Disable the app, then refresh via the OIDC grant -> clean 401, no mint/500.
	sa, _ := s.GetApp("shop")
	sa.Disabled = true
	if err := s.UpdateApp(sa); err != nil {
		t.Fatalf("disable app: %v", err)
	}
	form2 := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt2}}
	req2 := httptest.NewRequest("POST", "/realms/test-issuer/protocol/openid-connect/token", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("OIDC refresh into a disabled app must be 401, got %d %s", w2.Code, w2.Body.String())
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
