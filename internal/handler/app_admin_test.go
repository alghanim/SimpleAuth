package handler

import (
	"net/http"
	"testing"
	"time"

	"simpleauth/internal/auth"
	"simpleauth/internal/store"
)

// appAdminSetup builds a handler with two apps ("billing", "payroll") and a user
// "alice-guid". Per-app login model: an admin manages the app they logged INTO,
// so there is no central management app to configure.
func appAdminSetup(t *testing.T) (*Handler, store.Store) {
	t.Helper()
	h, s := testSetup(t)
	for _, id := range []string{"billing", "payroll"} {
		if err := s.CreateApp(&store.App{AppID: id, Audience: id, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatalf("create app %s: %v", id, err)
		}
	}
	if err := s.CreateUser(&store.User{GUID: "alice-guid", DisplayName: "Alice", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return h, s
}

// mintUserToken issues a user access token for guid as if they logged into app
// `azp` — the app the token is therefore allowed to manage.
func mintUserToken(t *testing.T, h *Handler, guid, azp string) string {
	t.Helper()
	c := auth.Claims{Azp: azp}
	c.Subject = guid
	c.Audience = []string{azp}
	tok, err := h.jwt.IssueAccessToken(c, time.Hour)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	return tok
}

func bearer(tok string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + tok}
}

func TestAppAdmin_NonAdminDenied(t *testing.T) {
	h, _ := appAdminSetup(t)
	tok := mintUserToken(t, h, "alice-guid", "billing") // logged into billing, but not an admin
	if w := doJSON(h, "GET", "/api/app-admin/authz", nil, bearer(tok)); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin must be denied (403), got %d", w.Code)
	}
}

func TestAppAdmin_GrantedCanManage(t *testing.T) {
	h, s := appAdminSetup(t)
	if err := s.AddAppAdmin("billing", "alice-guid", "admin"); err != nil {
		t.Fatal(err)
	}
	tok := mintUserToken(t, h, "alice-guid", "billing")
	if w := doJSON(h, "GET", "/api/app-admin/authz", nil, bearer(tok)); w.Code != http.StatusOK {
		t.Fatalf("granted admin GET authz expected 200, got %d (%s)", w.Code, w.Body)
	}
	body := map[string]interface{}{"app_id": "billing", "roles": []string{"viewer"}}
	if w := doJSON(h, "PUT", "/api/app-admin/authz", body, bearer(tok)); w.Code != http.StatusOK {
		t.Fatalf("granted admin PUT authz expected 200, got %d (%s)", w.Code, w.Body)
	}
}

// A token only manages the app it was minted for, and only if the holder admins
// THAT app — so an admin of billing holding a payroll token manages nothing.
func TestAppAdmin_TokenForUnadministeredAppDenied(t *testing.T) {
	h, s := appAdminSetup(t)
	if err := s.AddAppAdmin("billing", "alice-guid", "admin"); err != nil {
		t.Fatal(err)
	}
	tok := mintUserToken(t, h, "alice-guid", "payroll") // logged into payroll, admin of billing
	if w := doJSON(h, "PUT", "/api/app-admin/authz", map[string]interface{}{"roles": []string{"x"}}, bearer(tok)); w.Code != http.StatusForbidden {
		t.Fatalf("billing admin with a payroll token must be denied (403), got %d", w.Code)
	}
}

func TestAppAdmin_AppMgmtTokenRejected(t *testing.T) {
	h, s := appAdminSetup(t)
	if err := s.AddAppAdmin("billing", "alice-guid", "admin"); err != nil {
		t.Fatal(err)
	}
	c := auth.Claims{Typ: "app-mgmt", Azp: "billing"}
	c.Subject = "alice-guid"
	c.Audience = []string{"billing"}
	tok, _ := h.jwt.IssueAccessToken(c, time.Hour)
	if w := doJSON(h, "GET", "/api/app-admin/authz", nil, bearer(tok)); w.Code != http.StatusForbidden {
		t.Fatalf("app-mgmt token must be rejected (403), got %d", w.Code)
	}
}

func TestAppAdmin_DisabledUserRejected(t *testing.T) {
	h, s := appAdminSetup(t)
	if err := s.AddAppAdmin("billing", "alice-guid", "admin"); err != nil {
		t.Fatal(err)
	}
	u, err := s.GetUser("alice-guid")
	if err != nil {
		t.Fatal(err)
	}
	u.Disabled = true
	if err := s.UpdateUser(u); err != nil {
		t.Fatal(err)
	}
	tok := mintUserToken(t, h, "alice-guid", "billing")
	if w := doJSON(h, "GET", "/api/app-admin/authz", nil, bearer(tok)); w.Code != http.StatusForbidden {
		t.Fatalf("disabled user must be denied (403), got %d", w.Code)
	}
}

// Core design property: app-admin authz/bootstrap writes go to AppAuthz, a
// SEPARATE store from admin membership, so they can never clobber the admin set.
func TestAppAdmin_AuthzWritesDoNotClobberAdmins(t *testing.T) {
	h, s := appAdminSetup(t)
	if err := s.AddAppAdmin("billing", "alice-guid", "admin"); err != nil {
		t.Fatal(err)
	}
	tok := mintUserToken(t, h, "alice-guid", "billing")
	doJSON(h, "PUT", "/api/app-admin/authz", map[string]interface{}{"roles": []string{"r1"}}, bearer(tok))
	doJSON(h, "POST", "/api/app-admin/bootstrap", map[string]interface{}{"roles": []string{"r2"}}, bearer(tok))
	if ok, _ := s.IsAppAdmin("billing", "alice-guid"); !ok {
		t.Fatal("authz/bootstrap writes clobbered the admin membership")
	}
}

func TestAppAdmin_MasterGrantRevokeImmediate(t *testing.T) {
	h, s := appAdminSetup(t)
	if w := doJSON(h, "POST", "/api/admin/apps/billing/admins", map[string]interface{}{"user_guid": "alice-guid"}, adminHeaders()); w.Code != http.StatusOK {
		t.Fatalf("master grant expected 200, got %d (%s)", w.Code, w.Body)
	}
	if ok, _ := s.IsAppAdmin("billing", "alice-guid"); !ok {
		t.Fatal("grant not persisted")
	}
	tok := mintUserToken(t, h, "alice-guid", "billing")
	if w := doJSON(h, "GET", "/api/app-admin/authz", nil, bearer(tok)); w.Code != http.StatusOK {
		t.Fatalf("post-grant manage expected 200, got %d", w.Code)
	}
	if w := doJSON(h, "DELETE", "/api/admin/apps/billing/admins/alice-guid", nil, adminHeaders()); w.Code != http.StatusOK {
		t.Fatalf("master revoke expected 200, got %d", w.Code)
	}
	// Live store check => revoke is immediate, even with the same valid token.
	if w := doJSON(h, "GET", "/api/app-admin/authz", nil, bearer(tok)); w.Code != http.StatusForbidden {
		t.Fatalf("revoked admin must be denied immediately (403), got %d", w.Code)
	}
}

func TestAppAdmin_DeleteAppCascadesAdmins(t *testing.T) {
	_, s := appAdminSetup(t)
	if err := s.AddAppAdmin("billing", "alice-guid", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteApp("billing"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.IsAppAdmin("billing", "alice-guid"); ok {
		t.Fatal("DeleteApp must cascade-delete app admins (app_id-reuse safety)")
	}
}

// Decision 2: an app admin cannot manage the admin set — /api/app/admins is gated
// by requireApp (app secret / app-mgmt token), which a plain user token can't pass.
func TestAppAdmin_UserTokenCannotManageAdmins(t *testing.T) {
	h, s := appAdminSetup(t)
	if err := s.AddAppAdmin("billing", "alice-guid", "admin"); err != nil {
		t.Fatal(err)
	}
	tok := mintUserToken(t, h, "alice-guid", "billing")
	if w := doJSON(h, "POST", "/api/app/admins", map[string]interface{}{"user_guid": "alice-guid"}, bearer(tok)); w.Code != http.StatusUnauthorized {
		t.Fatalf("a user token must not pass requireApp on /api/app/admins (401), got %d", w.Code)
	}
}

func TestAppAdmin_AuditAttributedToUser(t *testing.T) {
	h, s := appAdminSetup(t)
	if err := s.AddAppAdmin("billing", "alice-guid", "admin"); err != nil {
		t.Fatal(err)
	}
	tok := mintUserToken(t, h, "alice-guid", "billing")
	doJSON(h, "PUT", "/api/app-admin/authz", map[string]interface{}{"roles": []string{"v"}}, bearer(tok))
	entries, err := s.QueryAuditLog(store.AuditQuery{Event: "app_authz_updated", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Actor == "alice-guid" {
			found = true
		}
	}
	if !found {
		t.Fatal("app-admin authz update must be audited with the user GUID as actor")
	}
}
