package handler

import (
	"encoding/base64"
	"net/http"
	"testing"
)

func basicAuth(id, secret string) map[string]string {
	return map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret)),
	}
}

// TestAppSelfService covers v2 M4: an app manages its own authz with its
// app_id/app_secret (HTTP Basic and an exchanged management token), scoped to
// itself; wrong secrets are rejected; and the bootstrap actually drives token
// role resolution.
func TestAppSelfService(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()

	// user bob
	w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{
		"display_name": "Bob", "password": "pass1234",
	}, adm)
	var u map[string]interface{}
	parseJSON(t, w, &u)
	s.SetIdentityMapping("local", "bob", u["guid"].(string))

	// app billing -> secret (shown once)
	w = doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "billing", "audience": "billing"}, adm)
	var app map[string]interface{}
	parseJSON(t, w, &app)
	secret := app["app_secret"].(string)
	if secret == "" {
		t.Fatal("no app_secret")
	}

	// self bootstrap via Basic
	w = doJSON(h, "POST", "/api/app/bootstrap", map[string]interface{}{
		"roles":            []string{"admin"},
		"role_permissions": map[string][]string{"admin": {"invoice:write"}},
		"assignments":      []map[string]interface{}{{"user": "bob", "roles": []string{"admin"}}},
	}, basicAuth("billing", secret))
	if w.Code != http.StatusOK {
		t.Fatalf("bootstrap: %d %s", w.Code, w.Body.String())
	}

	// wrong secret -> 401
	if w := doJSON(h, "GET", "/api/app/authz", nil, basicAuth("billing", "nope")); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret should 401, got %d", w.Code)
	}
	// no creds -> 401
	if w := doJSON(h, "GET", "/api/app/authz", nil, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("no creds should 401, got %d", w.Code)
	}

	// the bootstrap actually drives token resolution: bob logs in -> admin
	w = doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "bob", "password": "pass1234", "app_id": "billing",
	}, nil)
	var tok map[string]interface{}
	parseJSON(t, w, &tok)
	if roles := tokenRoles(t, tok["access_token"].(string)); !hasAud(roles, "admin") {
		t.Fatalf("self-bootstrap should make bob admin, got %v", roles)
	}

	// exchange creds for a management token, use it as Bearer
	w = doJSON(h, "POST", "/api/app/token", nil, basicAuth("billing", secret))
	if w.Code != http.StatusOK {
		t.Fatalf("app token: %d %s", w.Code, w.Body.String())
	}
	var mt map[string]interface{}
	parseJSON(t, w, &mt)
	mgmt := mt["access_token"].(string)
	w = doJSON(h, "GET", "/api/app/authz", nil, map[string]string{"Authorization": "Bearer " + mgmt})
	if w.Code != http.StatusOK {
		t.Fatalf("authz via mgmt token: %d", w.Code)
	}
	var authz map[string]interface{}
	parseJSON(t, w, &authz)
	if ua, _ := authz["user_assignments"].(map[string]interface{}); ua == nil || ua["bob"] == nil {
		t.Fatalf("authz should carry bob assignment, got %v", authz)
	}

	// scoping: a second app's credential cannot affect billing. Create app2,
	// bootstrap it, and confirm billing's authz is untouched.
	w = doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "other", "audience": "other"}, adm)
	var app2 map[string]interface{}
	parseJSON(t, w, &app2)
	secret2 := app2["app_secret"].(string)
	doJSON(h, "POST", "/api/app/bootstrap", map[string]interface{}{
		"roles": []string{"x"}, "assignments": []map[string]interface{}{{"user": "someone", "roles": []string{"x"}}},
	}, basicAuth("other", secret2))
	// billing still has only bob
	billingAuthz, _ := s.GetAppAuthz("billing")
	if _, ok := billingAuthz.UserAssignments["someone"]; ok {
		t.Fatal("app 'other' leaked an assignment into 'billing'")
	}
	if _, ok := billingAuthz.UserAssignments["bob"]; !ok {
		t.Fatal("billing lost its own assignment")
	}
}
