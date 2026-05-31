package handler

import (
	"net/http"
	"testing"
)

// TestAppsAPI exercises the v2 apps registry over HTTP: create (secret shown
// once, hash never leaked), duplicate rejection, list/get, secret rotation,
// update, admin gating, and delete.
func TestAppsAPI(t *testing.T) {
	h, _ := testSetup(t)

	// create — app_id derived from name
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"name": "Billing", "require_assignment": true,
	}, adminHeaders())
	if w.Code != http.StatusCreated {
		t.Fatalf("create code %d: %s", w.Code, w.Body.String())
	}
	var created map[string]interface{}
	parseJSON(t, w, &created)
	if created["app_id"] != "billing" {
		t.Fatalf("app_id = %v", created["app_id"])
	}
	secret, _ := created["app_secret"].(string)
	if secret == "" {
		t.Fatal("expected app_secret returned once")
	}
	if _, leaked := created["secret_hash"]; leaked {
		t.Fatal("secret_hash must never be returned")
	}

	// duplicate -> 409
	if w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "billing"}, adminHeaders()); w.Code != http.StatusConflict {
		t.Fatalf("duplicate create code = %d", w.Code)
	}

	// list -> contains billing, no secret leak
	w = doJSON(h, "GET", "/api/admin/apps", nil, adminHeaders())
	var list struct {
		Apps []map[string]interface{} `json:"apps"`
	}
	parseJSON(t, w, &list)
	found := false
	for _, a := range list.Apps {
		if a["app_id"] == "billing" {
			found = true
			if _, leaked := a["secret_hash"]; leaked {
				t.Fatal("list leaked secret_hash")
			}
		}
	}
	if !found {
		t.Fatal("billing not in list")
	}

	// rotate -> a different secret
	w = doJSON(h, "POST", "/api/admin/apps/billing/rotate-secret", nil, adminHeaders())
	if w.Code != http.StatusOK {
		t.Fatalf("rotate code %d", w.Code)
	}
	var rot map[string]interface{}
	parseJSON(t, w, &rot)
	if ns, _ := rot["app_secret"].(string); ns == "" || ns == secret {
		t.Fatal("rotate should return a new non-empty secret")
	}

	// update -> allow_local_users
	if w := doJSON(h, "PUT", "/api/admin/apps/billing", map[string]interface{}{"allow_local_users": true}, adminHeaders()); w.Code != http.StatusOK {
		t.Fatalf("update code %d", w.Code)
	}
	w = doJSON(h, "GET", "/api/admin/apps/billing", nil, adminHeaders())
	var got map[string]interface{}
	parseJSON(t, w, &got)
	if got["allow_local_users"] != true {
		t.Fatalf("update not reflected: %v", got["allow_local_users"])
	}

	// admin-gated
	if w := doJSON(h, "GET", "/api/admin/apps", nil, map[string]string{"Authorization": "Bearer wrong"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without admin key, got %d", w.Code)
	}

	// delete -> gone
	if w := doJSON(h, "DELETE", "/api/admin/apps/billing", nil, adminHeaders()); w.Code != http.StatusOK {
		t.Fatalf("delete code %d", w.Code)
	}
	if w := doJSON(h, "GET", "/api/admin/apps/billing", nil, adminHeaders()); w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", w.Code)
	}
}
