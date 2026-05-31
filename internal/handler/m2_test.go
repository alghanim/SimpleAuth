package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// tokenAudiences decodes a JWT (without verifying) and returns its `aud` claim
// as a slice (handling both the string and array encodings).
func tokenAudiences(t *testing.T, jwtStr string) []string {
	t.Helper()
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed jwt")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var c struct {
		Aud json.RawMessage `json:"aud"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if len(c.Aud) == 0 {
		return nil
	}
	var single string
	if json.Unmarshal(c.Aud, &single) == nil {
		return []string{single}
	}
	var multi []string
	_ = json.Unmarshal(c.Aud, &multi)
	return multi
}

func hasAud(auds []string, want string) bool {
	for _, a := range auds {
		if a == want {
			return true
		}
	}
	return false
}

// TestAudienceScopedTokens verifies v2 M2: direct-login tokens are stamped with
// the resolved app's audience, refresh preserves it, an absent app_id falls back
// to the default app, and an unknown app is rejected.
func TestAudienceScopedTokens(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()

	// user
	w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{
		"display_name": "Alice", "password": "pass1234",
	}, adm)
	var user map[string]interface{}
	parseJSON(t, w, &user)
	s.SetIdentityMapping("local", "alice", user["guid"].(string))

	// app
	if w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"name": "Billing", "audience": "billing",
	}, adm); w.Code != http.StatusCreated {
		t.Fatalf("create app: %d %s", w.Code, w.Body.String())
	}

	// login scoped to billing -> aud=billing
	w = doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "alice", "password": "pass1234", "app_id": "billing",
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("login billing: %d %s", w.Code, w.Body.String())
	}
	var tok map[string]interface{}
	parseJSON(t, w, &tok)
	accessToken := tok["access_token"].(string)
	refreshToken := tok["refresh_token"].(string)
	if auds := tokenAudiences(t, accessToken); !hasAud(auds, "billing") {
		t.Fatalf("expected aud=billing, got %v", auds)
	}

	// refresh keeps aud=billing
	w = doJSON(h, "POST", "/api/auth/refresh", map[string]interface{}{"refresh_token": refreshToken}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", w.Code, w.Body.String())
	}
	var rtok map[string]interface{}
	parseJSON(t, w, &rtok)
	if auds := tokenAudiences(t, rtok["access_token"].(string)); !hasAud(auds, "billing") {
		t.Fatalf("refresh should keep aud=billing, got %v", auds)
	}

	// login with no app_id -> default app (test cfg ClientID = "test-client")
	w = doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "alice", "password": "pass1234",
	}, nil)
	parseJSON(t, w, &tok)
	if auds := tokenAudiences(t, tok["access_token"].(string)); !hasAud(auds, "test-client") {
		t.Fatalf("default login should have aud=test-client, got %v", auds)
	}

	// unknown app -> 400
	if w := doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "alice", "password": "pass1234", "app_id": "does-not-exist",
	}, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown app should 400, got %d", w.Code)
	}
}
