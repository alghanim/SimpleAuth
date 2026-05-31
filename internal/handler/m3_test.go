package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func tokenRoles(t *testing.T, jwtStr string) []string {
	t.Helper()
	parts := strings.Split(jwtStr, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var c struct {
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatalf("unmarshal roles: %v", err)
	}
	return c.Roles
}

// TestPerAppAuthz covers v2 M3: roles in a token are resolved per app (direct
// user assignment and AD-group assignment), unassigned users get empty roles,
// and require_assignment denies unassigned users.
func TestPerAppAuthz(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()

	w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{
		"display_name": "Alice", "password": "pass1234",
	}, adm)
	var u map[string]interface{}
	parseJSON(t, w, &u)
	guid := u["guid"].(string)
	s.SetIdentityMapping("local", "alice", guid)

	// app: billing, with per-app authz assigning alice -> admin
	if w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "billing", "audience": "billing"}, adm); w.Code != http.StatusCreated {
		t.Fatalf("create billing: %d", w.Code)
	}
	if w := doJSON(h, "PUT", "/api/admin/apps/billing/authz", map[string]interface{}{
		"roles":            []string{"admin", "viewer"},
		"role_permissions": map[string][]string{"admin": {"invoice:write"}},
		"user_assignments": map[string][]string{"alice": {"admin"}},
	}, adm); w.Code != http.StatusOK {
		t.Fatalf("set billing authz: %d %s", w.Code, w.Body.String())
	}

	login := func(app string) (*httptest.ResponseRecorder, map[string]interface{}) {
		w := doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
			"username": "alice", "password": "pass1234", "app_id": app,
		}, nil)
		var tok map[string]interface{}
		if w.Code == http.StatusOK {
			parseJSON(t, w, &tok)
		}
		return w, tok
	}

	// billing: alice is admin
	if w, tok := login("billing"); w.Code != http.StatusOK {
		t.Fatalf("billing login: %d %s", w.Code, w.Body.String())
	} else if roles := tokenRoles(t, tok["access_token"].(string)); !hasAud(roles, "admin") {
		t.Fatalf("billing should give admin, got %v", roles)
	}

	// support: has per-app config but no assignment for alice → empty roles, still allowed
	doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "support", "audience": "support"}, adm)
	doJSON(h, "PUT", "/api/admin/apps/support/authz", map[string]interface{}{"roles": []string{"agent"}}, adm)
	if w, tok := login("support"); w.Code != http.StatusOK {
		t.Fatalf("support login: %d", w.Code)
	} else if roles := tokenRoles(t, tok["access_token"].(string)); len(roles) != 0 {
		t.Fatalf("support should give no roles to alice, got %v", roles)
	}

	// secure: require_assignment + alice unassigned → 403
	doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "secure", "audience": "secure", "require_assignment": true}, adm)
	doJSON(h, "PUT", "/api/admin/apps/secure/authz", map[string]interface{}{"roles": []string{"admin"}}, adm)
	if w, _ := login("secure"); w.Code != http.StatusForbidden {
		t.Fatalf("require_assignment should 403, got %d %s", w.Code, w.Body.String())
	}

	// group assignment: give alice group "Finance", assign group → viewer (drop direct)
	user, _ := s.GetUser(guid)
	user.Groups = []string{"Finance"}
	s.UpdateUser(user)
	doJSON(h, "PUT", "/api/admin/apps/billing/authz", map[string]interface{}{
		"roles":             []string{"admin", "viewer"},
		"group_assignments": map[string][]string{"Finance": {"viewer"}},
	}, adm)
	if w, tok := login("billing"); w.Code != http.StatusOK {
		t.Fatalf("billing group login: %d", w.Code)
	} else if roles := tokenRoles(t, tok["access_token"].(string)); !hasAud(roles, "viewer") {
		t.Fatalf("group assignment should give viewer, got %v", roles)
	}
}
