package handler

import (
	"net/http"
	"strings"
	"testing"
)

// loginUser creates a local user and returns a bearer-header map for its token.
func loginUser(t *testing.T, h *Handler, s interface {
	SetIdentityMapping(string, string, string) error
}, name string) (string, map[string]string) {
	t.Helper()
	w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{"display_name": name, "password": "pass1234"}, adminHeaders())
	var u map[string]interface{}
	parseJSON(t, w, &u)
	guid := u["guid"].(string)
	s.SetIdentityMapping("local", strings.ToLower(name), guid)
	w = doJSON(h, "POST", "/api/auth/login", map[string]interface{}{"username": strings.ToLower(name), "password": "pass1234"}, nil)
	var tok map[string]interface{}
	parseJSON(t, w, &tok)
	return guid, map[string]string{"Authorization": "Bearer " + tok["access_token"].(string)}
}

// TestSA4_PreferencesRoundTrip covers SA-4: GET before any set returns defaults;
// PUT persists and echoes; GET returns the stored values.
func TestSA4_PreferencesRoundTrip(t *testing.T) {
	h, s := testSetup(t)
	_, bearer := loginUser(t, h, s, "Alice")

	// GET of never-set prefs -> 200 defaults.
	w := doJSON(h, "GET", "/api/user/preferences", nil, bearer)
	if w.Code != http.StatusOK {
		t.Fatalf("get defaults: %d %s", w.Code, w.Body.String())
	}
	var def UserPreferences
	parseJSON(t, w, &def)
	if def.Theme != "system" || def.Lang != "en" || def.Dir != "ltr" || def.RailCollapsed {
		t.Fatalf("unexpected defaults: %+v", def)
	}

	// PUT a valid document.
	w = doJSON(h, "PUT", "/api/user/preferences", map[string]interface{}{
		"theme": "dark", "lang": "ar", "dir": "rtl", "rail_collapsed": true,
	}, bearer)
	if w.Code != http.StatusOK {
		t.Fatalf("put: %d %s", w.Code, w.Body.String())
	}

	// GET returns the stored values.
	w = doJSON(h, "GET", "/api/user/preferences", nil, bearer)
	var got UserPreferences
	parseJSON(t, w, &got)
	if got.Theme != "dark" || got.Lang != "ar" || got.Dir != "rtl" || !got.RailCollapsed {
		t.Fatalf("prefs not persisted: %+v", got)
	}
}

// TestSA4_PreferencesValidation covers the strict schema: unknown keys, bad
// enums, and an oversized body are all 400; token discipline is enforced.
func TestSA4_PreferencesValidation(t *testing.T) {
	h, s := testSetup(t)
	guid, bearer := loginUser(t, h, s, "Bob")

	bad := []struct {
		name string
		body map[string]interface{}
	}{
		{"unknown key", map[string]interface{}{"theme": "dark", "evil": "<script>"}},
		{"bad theme", map[string]interface{}{"theme": "neon"}},
		{"bad dir", map[string]interface{}{"dir": "sideways"}},
		{"bad lang", map[string]interface{}{"lang": "not a tag!!"}},
	}
	for _, tc := range bad {
		if w := doJSON(h, "PUT", "/api/user/preferences", tc.body, bearer); w.Code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d %s", tc.name, w.Code, w.Body.String())
		}
	}

	// Oversized body (> 2 KiB) -> 400.
	big := map[string]interface{}{"lang": strings.Repeat("a", 3000)}
	if w := doJSON(h, "PUT", "/api/user/preferences", big, bearer); w.Code != http.StatusBadRequest {
		t.Fatalf("oversized body: want 400, got %d", w.Code)
	}

	// No token -> 401.
	if w := doJSON(h, "GET", "/api/user/preferences", nil, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: want 401, got %d", w.Code)
	}

	// After a valid set, deleting the user clears the prefs (GET as admin path is
	// gone; we assert the stored key is removed via a fresh default GET is moot —
	// instead confirm the delete-cascade removed the config key).
	doJSON(h, "PUT", "/api/user/preferences", map[string]interface{}{"theme": "dark"}, bearer)
	doJSON(h, "DELETE", "/api/admin/users/"+guid, nil, adminHeaders())
	if data, _ := s.GetConfigValue(userPrefsKeyPrefix + guid); data != nil {
		t.Fatalf("preferences must be deleted with the user, got %s", data)
	}
}
