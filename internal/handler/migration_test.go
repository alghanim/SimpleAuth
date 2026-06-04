package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"simpleauth/internal/migrate"
	"simpleauth/internal/store"
)

// TestCentralMigrationFlow covers the receiving (central) side end-to-end: a
// master mints a token on a target app, the standalone preflights + commits with
// it, the import lands, and the token is single-use.
func TestCentralMigrationFlow(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()

	// Target named app.
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "billing", "audience": "billing"}, adm)
	if w.Code != http.StatusCreated {
		t.Fatalf("create app: %d %s", w.Code, w.Body.String())
	}

	// Default app can't be a migration target.
	if w := doJSON(h, "POST", "/api/admin/apps/"+h.defaultAppID()+"/migration-token", nil, adm); w.Code != http.StatusForbidden {
		t.Fatalf("token on default app: want 403, got %d", w.Code)
	}

	// Mint a migration token (shown once).
	w = doJSON(h, "POST", "/api/admin/apps/billing/migration-token", nil, adm)
	if w.Code != http.StatusOK {
		t.Fatalf("mint token: %d %s", w.Code, w.Body.String())
	}
	var tokResp map[string]interface{}
	parseJSON(t, w, &tokResp)
	token := tokResp["migration_token"].(string)
	if token == "" {
		t.Fatal("no token returned")
	}

	// A standalone-style bundle: one local user (no AD, so nothing blocked).
	bundle := &migrate.Bundle{
		SchemaRev:     migrate.SchemaRev,
		SourceVersion: "2.2.0-test",
		App: migrate.AppConfig{
			Audience:     "billing-aud",
			RedirectURIs: []string{"https://app.example/cb"},
			SecretHash:   "carried-hash",
		},
		Catalog: migrate.Catalog{RolePermissions: map[string][]string{"admin": {"x:write"}}},
		Users: []migrate.UserEntry{
			{Kind: migrate.KindLocal, Key: "bob", Roles: []string{"admin"}, DisplayName: "Bob", PasswordHash: "bob-hash"},
		},
	}
	body := map[string]interface{}{"app_id": "billing", "bundle": bundle, "carry_secret": true}

	// Bad token -> 401.
	if w := doJSON(h, "POST", "/api/migration/preflight", body, bearer("sa_mig_wrong")); w.Code != http.StatusUnauthorized {
		t.Fatalf("bad token preflight: want 401, got %d", w.Code)
	}

	// Preflight (dry run) with the real token.
	w = doJSON(h, "POST", "/api/migration/preflight", body, bearer(token))
	if w.Code != http.StatusOK {
		t.Fatalf("preflight: %d %s", w.Code, w.Body.String())
	}
	var rep migrate.Report
	parseJSON(t, w, &rep)
	if rep.LocalUsers != 1 || !rep.OK() {
		t.Fatalf("preflight report wrong: %+v", rep)
	}

	// Commit.
	w = doJSON(h, "POST", "/api/migration/commit", body, bearer(token))
	if w.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", w.Code, w.Body.String())
	}
	var res migrate.ApplyResult
	parseJSON(t, w, &res)
	if res.AssignmentsSet != 1 || res.LocalUsersCreated != 1 {
		t.Fatalf("apply result wrong: %+v", res)
	}

	// The import landed: app config carried, authz set, local user materialized.
	app, _ := s.GetApp("billing")
	if app.Audience != "billing-aud" || app.SecretHash != "carried-hash" || !app.AllowLocalUsers {
		t.Fatalf("target app not carried: %+v", app)
	}
	authz, _ := s.GetAppAuthz("billing")
	if got := authz.UserAssignments["bob"]; len(got) != 1 || got[0] != "admin" {
		t.Fatalf("bob assignment: %v", got)
	}
	guid, _ := s.ResolveMapping("applocal:billing", "bob")
	if cu, _ := s.GetUser(guid); cu == nil || cu.PasswordHash != "bob-hash" {
		t.Fatalf("local user not materialized with hash: %+v", cu)
	}

	// Token is single-use: a second commit is rejected.
	if w := doJSON(h, "POST", "/api/migration/commit", body, bearer(token)); w.Code != http.StatusUnauthorized {
		t.Fatalf("reused token: want 401, got %d %s", w.Code, w.Body.String())
	}
}

// TestCentralMigrationBlocksADWithoutLDAP: committing an AD-user bundle to a
// central with no LDAP is refused (409), nothing is imported.
func TestCentralMigrationBlocksADWithoutLDAP(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()
	doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "billing", "audience": "billing"}, adm)
	w := doJSON(h, "POST", "/api/admin/apps/billing/migration-token", nil, adm)
	var tokResp map[string]interface{}
	parseJSON(t, w, &tokResp)
	token := tokResp["migration_token"].(string)

	bundle := &migrate.Bundle{
		SchemaRev: migrate.SchemaRev,
		SourceAD:  &migrate.ADInfo{Domain: "corp.local"},
		Users:     []migrate.UserEntry{{Kind: migrate.KindAD, Key: "ada", Roles: []string{"admin"}}},
	}
	body := map[string]interface{}{"app_id": "billing", "bundle": bundle}

	if w := doJSON(h, "POST", "/api/migration/commit", body, bearer(token)); w.Code != http.StatusConflict {
		t.Fatalf("AD user, central without LDAP: want 409, got %d %s", w.Code, w.Body.String())
	}
}

// TestMigrationEndToEnd drives the full cross-install flow: a standalone packages
// its directory and pushes it over real HTTP to a separate central install.
func TestMigrationEndToEnd(t *testing.T) {
	// Central install + a target app + a token, exposed over HTTP.
	central, cs := testSetup(t)
	adm := adminHeaders()
	if w := doJSON(central, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "billing", "audience": "billing"}, adm); w.Code != http.StatusCreated {
		t.Fatalf("create central app: %d %s", w.Code, w.Body.String())
	}
	w := doJSON(central, "POST", "/api/admin/apps/billing/migration-token", nil, adm)
	var tokResp map[string]interface{}
	parseJSON(t, w, &tokResp)
	token := tokResp["migration_token"].(string)

	srv := httptest.NewServer(central)
	defer srv.Close()

	// Standalone install: home app + catalog + a local directory user with a role.
	standalone, ss := testSetup(t)
	homeID := standalone.defaultAppID()
	if err := ss.CreateApp(&store.App{AppID: homeID, Audience: "home-aud", RedirectURIs: []string{"https://app/cb"}, SecretHash: "src-hash"}); err != nil {
		t.Fatalf("seed home app: %v", err)
	}
	ss.SetRolePermissions(map[string][]string{"admin": {"x:write"}})
	if err := ss.CreateUser(&store.User{GUID: "g-bob", DisplayName: "Bob", PasswordHash: "bob-hash"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	ss.SetIdentityMapping("local", "bob", "g-bob")
	ss.SetUserRoles("g-bob", []string{"admin"})

	call := func(path string) map[string]interface{} {
		w := doJSON(standalone, "POST", path, map[string]interface{}{
			"central_url": srv.URL, "app_id": "billing", "token": token, "carry_secret": true,
		}, adm)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		var out map[string]interface{}
		parseJSON(t, w, &out)
		return out
	}

	// Dry run, then commit — both proxied standalone -> central over HTTP.
	rep := call("/api/admin/migrate-to-central/preflight")
	if rep["local_users"].(float64) != 1 {
		t.Fatalf("preflight should see 1 local user: %+v", rep)
	}
	call("/api/admin/migrate-to-central/commit")

	// The central now has the app config carried + bob assigned + materialized.
	app, _ := cs.GetApp("billing")
	if app.Audience != "home-aud" || app.SecretHash != "src-hash" || !app.AllowLocalUsers {
		t.Fatalf("central app not carried: %+v", app)
	}
	authz, _ := cs.GetAppAuthz("billing")
	if got := authz.UserAssignments["bob"]; len(got) != 1 || got[0] != "admin" {
		t.Fatalf("bob not assigned on central: %v", got)
	}
	guid, _ := cs.ResolveMapping("applocal:billing", "bob")
	if cu, _ := cs.GetUser(guid); cu == nil || cu.PasswordHash != "bob-hash" {
		t.Fatalf("bob not materialized on central: %+v", cu)
	}
}
