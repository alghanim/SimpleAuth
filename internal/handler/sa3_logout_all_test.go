package handler

import (
	"net/http"
	"testing"
)

// TestSA3_UserLogoutAll covers SA-3: a user, with their own access token,
// terminates their whole presence — refresh tokens revoked, access tokens
// blacklisted, SSO sessions gone — and can only ever log themselves out.
func TestSA3_UserLogoutAll(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()

	w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{
		"display_name": "Alice", "password": "pass1234",
	}, adm)
	var user map[string]interface{}
	parseJSON(t, w, &user)
	s.SetIdentityMapping("local", "alice", user["guid"].(string))

	w = doJSON(h, "POST", "/api/auth/login", map[string]interface{}{
		"username": "alice", "password": "pass1234",
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	var tok map[string]interface{}
	parseJSON(t, w, &tok)
	access := tok["access_token"].(string)
	refresh := tok["refresh_token"].(string)
	bearer := map[string]string{"Authorization": "Bearer " + access}

	// Sanity: the access token works before logout.
	if w := doJSON(h, "GET", "/api/auth/userinfo", nil, bearer); w.Code != http.StatusOK {
		t.Fatalf("userinfo before logout should be 200, got %d", w.Code)
	}

	// Log out everywhere with the user's own access token.
	if w := doJSON(h, "POST", "/api/user/logout-all", nil, bearer); w.Code != http.StatusOK {
		t.Fatalf("logout-all: %d %s", w.Code, w.Body.String())
	}

	// The refresh token no longer mints (family revoked): no silent re-mint.
	if w := doJSON(h, "POST", "/api/auth/refresh", map[string]interface{}{"refresh_token": refresh}, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("refresh after logout-all must be 401, got %d %s", w.Code, w.Body.String())
	}
	// The access token is blacklisted until it expires (IsUserAccessRevoked).
	if w := doJSON(h, "GET", "/api/auth/userinfo", nil, bearer); w.Code != http.StatusUnauthorized {
		t.Fatalf("access token after logout-all must be rejected, got %d", w.Code)
	}
}

// TestSA3_LogoutAllTokenClassAndAuth covers SA-3's auth discipline: no bearer,
// and non-access token classes (a refresh token presented as bearer), are
// rejected — a user can't be logged out by anything but a genuine user access
// token, and there is no user-id parameter to target someone else.
func TestSA3_LogoutAllTokenClassAndAuth(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()

	w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{
		"display_name": "Bob", "password": "pass1234",
	}, adm)
	var user map[string]interface{}
	parseJSON(t, w, &user)
	s.SetIdentityMapping("local", "bob", user["guid"].(string))
	w = doJSON(h, "POST", "/api/auth/login", map[string]interface{}{"username": "bob", "password": "pass1234"}, nil)
	var tok map[string]interface{}
	parseJSON(t, w, &tok)

	// No Authorization header -> 401.
	if w := doJSON(h, "POST", "/api/user/logout-all", nil, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("logout-all without a token must be 401, got %d", w.Code)
	}
	// A refresh token presented as the bearer -> 401 (token-class discipline);
	// and because it's rejected, bob's real session is untouched.
	refreshBearer := map[string]string{"Authorization": "Bearer " + tok["refresh_token"].(string)}
	if w := doJSON(h, "POST", "/api/user/logout-all", nil, refreshBearer); w.Code != http.StatusUnauthorized {
		t.Fatalf("logout-all with a refresh token must be 401, got %d", w.Code)
	}
	if w := doJSON(h, "POST", "/api/auth/refresh", map[string]interface{}{"refresh_token": tok["refresh_token"].(string)}, nil); w.Code != http.StatusOK {
		t.Fatalf("bob's refresh should still work (rejected logout-all left it intact), got %d %s", w.Code, w.Body.String())
	}
}
