package handler

import (
	"net/http"
	"testing"
)

// TestSA1_AppPresentationRoundTrip covers SA-1: base_url + display_name +
// category + icon are settable at create and update and round-trip through the
// admin GET, with base_url normalized and never dereferenced.
func TestSA1_AppPresentationRoundTrip(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()

	// Create with the full presentation set; base_url carries a trailing slash to
	// prove normalization strips it.
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"app_id":       "billing",
		"audience":     "billing",
		"base_url":     "https://billing.example.com/",
		"display_name": map[string]string{"en": "Billing", "ar": "الفوترة"},
		"category":     "finance",
		"icon":         "/.well-known/ops-module-icon.svg",
	}, adm)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created map[string]interface{}
	parseJSON(t, w, &created)
	if created["base_url"] != "https://billing.example.com" {
		t.Fatalf("base_url not normalized on create: %v", created["base_url"])
	}
	if created["category"] != "finance" || created["icon"] != "/.well-known/ops-module-icon.svg" {
		t.Fatalf("category/icon not stored: %v / %v", created["category"], created["icon"])
	}
	if dn, _ := created["display_name"].(map[string]interface{}); dn == nil || dn["en"] != "Billing" || dn["ar"] != "الفوترة" {
		t.Fatalf("display_name not stored: %v", created["display_name"])
	}

	// GET round-trips the same values.
	w = doJSON(h, "GET", "/api/admin/apps/billing", nil, adm)
	var got map[string]interface{}
	parseJSON(t, w, &got)
	if got["base_url"] != "https://billing.example.com" || got["category"] != "finance" {
		t.Fatalf("GET did not round-trip presentation: %+v", got)
	}

	// PUT updates a subset (partial merge) without clobbering the rest.
	w = doJSON(h, "PUT", "/api/admin/apps/billing", map[string]interface{}{
		"category": "billing-and-payments",
	}, adm)
	if w.Code != http.StatusOK {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	var updated map[string]interface{}
	parseJSON(t, w, &updated)
	if updated["category"] != "billing-and-payments" {
		t.Fatalf("category not updated: %v", updated["category"])
	}
	if updated["base_url"] != "https://billing.example.com" {
		t.Fatalf("partial PUT clobbered base_url: %v", updated["base_url"])
	}
}

// TestSA1_BaseURLValidation covers SA-1's syntactic guard: base_url must be an
// absolute https origin with no userinfo/query/fragment (it is a launch target
// SimpleAuth stores but never dereferences), and icon must be a relative path.
func TestSA1_BaseURLValidation(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()

	bad := []struct {
		name string
		body map[string]interface{}
	}{
		{"http scheme", map[string]interface{}{"app_id": "a1", "base_url": "http://x.example.com"}},
		{"no host", map[string]interface{}{"app_id": "a2", "base_url": "https:///path"}},
		{"userinfo", map[string]interface{}{"app_id": "a3", "base_url": "https://user:pw@x.example.com"}},
		{"query", map[string]interface{}{"app_id": "a4", "base_url": "https://x.example.com?a=1"}},
		{"fragment", map[string]interface{}{"app_id": "a5", "base_url": "https://x.example.com#f"}},
		{"icon absolute url", map[string]interface{}{"app_id": "a6", "base_url": "https://x.example.com", "icon": "https://evil.example.com/i.svg"}},
		{"icon traversal", map[string]interface{}{"app_id": "a7", "base_url": "https://x.example.com", "icon": "/../secret"}},
		{"icon encoded traversal", map[string]interface{}{"app_id": "a8", "base_url": "https://x.example.com", "icon": "/%2E%2E/bar/x.svg"}},
		{"icon encoded slashes", map[string]interface{}{"app_id": "a9", "base_url": "https://x.example.com", "icon": "/%2F%2Fevil"}},
	}
	for _, tc := range bad {
		if w := doJSON(h, "POST", "/api/admin/apps", tc.body, adm); w.Code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d %s", tc.name, w.Code, w.Body.String())
		}
	}

	// A valid https origin with a path prefix is accepted and normalized.
	if w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"app_id": "ok", "base_url": "https://apps.example.com/billing/",
	}, adm); w.Code != http.StatusCreated {
		t.Fatalf("valid base_url rejected: %d %s", w.Code, w.Body.String())
	}

	// A percent-encoded reserved char in the path must be PRESERVED, not decoded
	// into a delimiter (would corrupt the stored URL and break icon_url).
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"app_id": "enc", "base_url": "https://apps.example.com/team%23finance",
	}, adm)
	if w.Code != http.StatusCreated {
		t.Fatalf("encoded base_url path rejected: %d %s", w.Code, w.Body.String())
	}
	var created map[string]interface{}
	parseJSON(t, w, &created)
	if created["base_url"] != "https://apps.example.com/team%23finance" {
		t.Fatalf("base_url must preserve %%23, got %v", created["base_url"])
	}
}
