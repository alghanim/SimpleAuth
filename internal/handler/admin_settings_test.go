package handler

import (
	"net/http"
	"testing"

	"simpleauth/internal/store"
)

// putSettings drives the real admin flow (full GET-then-PUT document, like the
// UI) and fails the test on a non-200.
func putSettings(t *testing.T, h *Handler, mutate func(*store.RuntimeSettings)) {
	t.Helper()
	rs := *h.runtimeSettings.get() // copy the current document
	mutate(&rs)
	if w := doJSON(h, "PUT", "/api/admin/settings", &rs, adminHeaders()); w.Code != http.StatusOK {
		t.Fatalf("PUT /api/admin/settings -> %d: %s", w.Code, w.Body.String())
	}
}

// hammer fires bad app-credential requests and reports whether a 429 appeared
// within n attempts (and fails on anything other than 401/429).
func hammer(t *testing.T, h *Handler, appID string, n int) bool {
	t.Helper()
	for i := 0; i < n; i++ {
		w := doJSON(h, "POST", "/api/app/token", nil, basicAuth(appID, "wrong-secret"))
		switch w.Code {
		case http.StatusTooManyRequests:
			return true
		case http.StatusUnauthorized:
			// expected while under the limit
		default:
			t.Fatalf("attempt %d: want 401 or 429, got %d: %s", i+1, w.Code, w.Body.String())
		}
	}
	return false
}

// TestRateLimitAdminRuntimeControl: the admin decides the rate limit at
// runtime — tightening it, disabling it, and re-enabling it must all take
// effect on the LIVE limiter through PUT /api/admin/settings, no restart.
// (Before this feature the PUT persisted the values but never applied them.)
func TestRateLimitAdminRuntimeControl(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()
	doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "rl-rt", "audience": "rl-rt"}, adm)

	// Tighten to 2/min at runtime: the live limiter must start returning 429.
	putSettings(t, h, func(rs *store.RuntimeSettings) {
		rs.RateLimitMax = 2
		rs.RateLimitWindowS = 60
		rs.RateLimitDisabled = false
	})
	if !hammer(t, h, "rl-rt", 5) {
		t.Fatal("runtime rate_limit_max=2 must produce a 429 on the live limiter")
	}

	// The admin turns the limiter OFF: unlimited attempts, still 401, never 429.
	putSettings(t, h, func(rs *store.RuntimeSettings) { rs.RateLimitDisabled = true })
	if hammer(t, h, "rl-rt", 10) {
		t.Fatal("rate_limit_disabled=true must turn the limiter into a pass-through")
	}

	// The admin turns it back ON: the guard must come back immediately.
	putSettings(t, h, func(rs *store.RuntimeSettings) { rs.RateLimitDisabled = false })
	if !hammer(t, h, "rl-rt", 5) {
		t.Fatal("re-enabling the rate limit must restore 429s")
	}
}

// TestRateLimitSettingsZeroValueSafety: a settings PUT that OMITS the
// rate-limit fields (an older client, a partial document) must never leave the
// limiter disabled or misconfigured — the F25 guard: zero values fall back to
// the deployment config (compiled defaults 10/60 here, since the test config
// carries no rate-limit values) and only an explicit rate_limit_disabled=true
// turns the limiter off.
func TestRateLimitSettingsZeroValueSafety(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()
	doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "rl-zv", "audience": "rl-zv"}, adm)

	// Admin disables the limiter, then an old client PUTs a document without
	// any rate_limit_* keys and without a version (legacy last-writer-wins).
	putSettings(t, h, func(rs *store.RuntimeSettings) {
		rs.RateLimitMax = 2
		rs.RateLimitWindowS = 60
		rs.RateLimitDisabled = true
	})
	if hammer(t, h, "rl-zv", 6) {
		t.Fatal("precondition: limiter should be disabled")
	}
	legacy := map[string]interface{}{"password_min_length": 8}
	if w := doJSON(h, "PUT", "/api/admin/settings", legacy, adm); w.Code != http.StatusOK {
		t.Fatalf("legacy settings PUT -> %d: %s", w.Code, w.Body.String())
	}

	// The omitted boolean's zero value re-enables the limiter, and the omitted
	// numbers land on the compiled defaults — persisted doc, cache, and live
	// limiter must all agree (not silently keep the previous 2/60).
	rs := h.runtimeSettings.get()
	if rs.RateLimitDisabled {
		t.Fatal("a PUT without rate_limit_disabled must leave the limiter ON")
	}
	if rs.RateLimitMax != 10 || rs.RateLimitWindowS != 60 {
		t.Fatalf("omitted numbers must fall back to defaults 10/60, got %d/%d", rs.RateLimitMax, rs.RateLimitWindowS)
	}
	// The live limiter now runs 10/60: attempts 1-10 are 401, the 11th is 429.
	if !hammer(t, h, "rl-zv", 12) {
		t.Fatal("limiter must enforce the fallback 10/60 after a legacy PUT re-enabled it")
	}
}

// TestSettingsVersionConflict: a stale tab (echoing an old version) must not
// silently clobber another admin's change — in particular it must not revert
// rate_limit_disabled. Versionless clients keep last-writer-wins.
func TestSettingsVersionConflict(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()

	putSettings(t, h, func(rs *store.RuntimeSettings) { rs.DeploymentName = "one" })
	stale := *h.runtimeSettings.get() // a second admin tab's snapshot

	putSettings(t, h, func(rs *store.RuntimeSettings) { rs.DeploymentName = "two" })

	stale.RateLimitDisabled = true
	if w := doJSON(h, "PUT", "/api/admin/settings", &stale, adm); w.Code != http.StatusConflict {
		t.Fatalf("stale-version PUT must 409, got %d: %s", w.Code, w.Body.String())
	}
	if h.runtimeSettings.get().RateLimitDisabled {
		t.Fatal("a stale PUT must not disable the limiter")
	}

	legacy := map[string]interface{}{"password_min_length": 8, "deployment_name": "legacy"}
	if w := doJSON(h, "PUT", "/api/admin/settings", legacy, adm); w.Code != http.StatusOK {
		t.Fatalf("versionless PUT must keep working (last-writer-wins), got %d: %s", w.Code, w.Body.String())
	}
}

// TestRateLimitWindowChangeResetsCounters: relaxing the window must admit a
// previously blocked IP immediately — stale counters from the old window must
// not keep returning 429 (the UI promises changes apply immediately).
func TestRateLimitWindowChangeResetsCounters(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()
	doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{"app_id": "rl-win", "audience": "rl-win"}, adm)

	putSettings(t, h, func(rs *store.RuntimeSettings) { rs.RateLimitMax = 2; rs.RateLimitWindowS = 3600 })
	if !hammer(t, h, "rl-win", 5) {
		t.Fatal("precondition: IP should be rate-limited under the 1h window")
	}
	putSettings(t, h, func(rs *store.RuntimeSettings) { rs.RateLimitWindowS = 60 })
	if w := doJSON(h, "POST", "/api/app/token", nil, basicAuth("rl-win", "wrong-secret")); w.Code != http.StatusUnauthorized {
		t.Fatalf("first attempt after the window change: want 401 (fresh window), got %d", w.Code)
	}
}
