package handler

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"simpleauth/internal/store"
)

// runtimeSettingsCache caches runtime settings in memory for fast access.
type runtimeSettingsCache struct {
	mu sync.RWMutex
	rs *store.RuntimeSettings
}

func (c *runtimeSettingsCache) get() *store.RuntimeSettings {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rs
}

func (c *runtimeSettingsCache) set(rs *store.RuntimeSettings) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rs = rs
}

// initRuntimeSettings loads or seeds runtime settings from DB.
// On first run, env/config values seed the DB. After that, DB owns the values.
func (h *Handler) initRuntimeSettings() {
	existing, _ := h.store.GetRuntimeSettings()
	if existing != nil {
		// Normalize legacy documents (pre-clamp PUTs could persist zeroed
		// rate-limit numbers) so GET/UI always report the values the limiter
		// actually runs; persist the one-time upgrade.
		oldMax, oldWin := existing.RateLimitMax, existing.RateLimitWindowS
		h.normalizeRateLimit(existing)
		if existing.RateLimitMax != oldMax || existing.RateLimitWindowS != oldWin {
			h.store.SaveRuntimeSettings(existing)
		}
		h.runtimeSettings.set(existing)
		h.applyRateLimit(existing)
		return
	}

	// First run — seed from config
	rs := &store.RuntimeSettings{
		DeploymentName:           h.cfg.DeploymentName,
		RedirectURIs:             h.cfg.RedirectURIs,
		CORSOrigins:              h.cfg.CORSOrigins,
		PasswordMinLength:        h.cfg.PasswordMinLength,
		PasswordRequireUppercase: h.cfg.PasswordRequireUppercase,
		PasswordRequireLowercase: h.cfg.PasswordRequireLowercase,
		PasswordRequireDigit:     h.cfg.PasswordRequireDigit,
		PasswordRequireSpecial:   h.cfg.PasswordRequireSpecial,
		PasswordHistoryCount:     h.cfg.PasswordHistoryCount,
		AccountLockoutThreshold:  h.cfg.AccountLockoutThreshold,
		AccountLockoutDurationS:  int(h.cfg.AccountLockoutDuration.Seconds()),
		DefaultRoles:             h.cfg.DefaultRoles,
		RateLimitMax:             h.cfg.RateLimitMax,
		RateLimitWindowS:         int(h.cfg.RateLimitWindow.Seconds()),
		AuditRetentionDays:       int(h.cfg.AuditRetention.Hours() / 24),
		AutoSSO:                  h.cfg.AutoSSO,
		AutoSSODelay:             h.cfg.AutoSSODelay,
		EnableSessionSSO:         h.cfg.EnableSessionSSO,
		SessionSSOIdleHours:      int(h.cfg.SessionSSOIdleTTL.Hours()),
		SessionSSOMaxHours:       int(h.cfg.SessionSSOMaxTTL.Hours()),
	}
	h.store.SaveRuntimeSettings(rs)
	h.runtimeSettings.set(rs)
	h.applyRateLimit(rs)
}

// Bounds for the runtime rate limit. The fallback chain for an omitted/zeroed
// number is deployment config first, then these compiled-in defaults — so a
// normalized document always carries positive values and the persisted doc,
// the cache, and the live limiter cannot diverge. The window ceiling also
// keeps time.Duration(windowS)*time.Second far away from int64 overflow.
const (
	defaultRateLimitMax     = 10
	defaultRateLimitWindowS = 60
	maxRateLimitMax         = 1_000_000_000
	maxRateLimitWindowS     = 86_400 // 1 day
)

// normalizeRateLimit clamps the rate-limit numbers into sane bounds (F25:
// omitted/zeroed values fall back, absurd values are capped). Turning the
// limiter off is only ever the explicit rate_limit_disabled boolean.
func (h *Handler) normalizeRateLimit(rs *store.RuntimeSettings) {
	if rs.RateLimitMax < 1 {
		rs.RateLimitMax = h.cfg.RateLimitMax
	}
	if rs.RateLimitMax < 1 {
		rs.RateLimitMax = defaultRateLimitMax
	}
	if rs.RateLimitMax > maxRateLimitMax {
		rs.RateLimitMax = maxRateLimitMax
	}
	if rs.RateLimitWindowS < 1 {
		rs.RateLimitWindowS = int(h.cfg.RateLimitWindow.Seconds())
	}
	if rs.RateLimitWindowS < 1 {
		rs.RateLimitWindowS = defaultRateLimitWindowS
	}
	if rs.RateLimitWindowS > maxRateLimitWindowS {
		rs.RateLimitWindowS = maxRateLimitWindowS
	}
}

// applyRateLimit pushes the persisted rate-limit settings into the live
// limiter — the admin decides at runtime whether and how tightly the
// login-shaped endpoints are limited, without a restart.
func (h *Handler) applyRateLimit(rs *store.RuntimeSettings) {
	if rs == nil {
		return
	}
	h.loginLimiter.setConfig(rs.RateLimitMax, time.Duration(rs.RateLimitWindowS)*time.Second, rs.RateLimitDisabled)
}

// --- Accessor helpers (read from cache) ---

func (h *Handler) getRedirectURIs() []string {
	if rs := h.runtimeSettings.get(); rs != nil && len(rs.RedirectURIs) > 0 {
		return rs.RedirectURIs
	}
	return h.cfg.RedirectURIs
}

func (h *Handler) getCORSOrigins() string {
	if rs := h.runtimeSettings.get(); rs != nil && rs.CORSOrigins != "" {
		return rs.CORSOrigins
	}
	return h.cfg.CORSOrigins
}

func (h *Handler) getAccountLockoutThreshold() int {
	if rs := h.runtimeSettings.get(); rs != nil {
		return rs.AccountLockoutThreshold
	}
	return h.cfg.AccountLockoutThreshold
}

func (h *Handler) getAccountLockoutDuration() time.Duration {
	if rs := h.runtimeSettings.get(); rs != nil && rs.AccountLockoutDurationS > 0 {
		return time.Duration(rs.AccountLockoutDurationS) * time.Second
	}
	return h.cfg.AccountLockoutDuration
}

func (h *Handler) getPasswordHistoryCount() int {
	if rs := h.runtimeSettings.get(); rs != nil {
		return rs.PasswordHistoryCount
	}
	return h.cfg.PasswordHistoryCount
}

func (h *Handler) getAuditRetention() time.Duration {
	if rs := h.runtimeSettings.get(); rs != nil && rs.AuditRetentionDays > 0 {
		return time.Duration(rs.AuditRetentionDays) * 24 * time.Hour
	}
	return h.cfg.AuditRetention
}

func (h *Handler) getDeploymentName() string {
	if rs := h.runtimeSettings.get(); rs != nil && rs.DeploymentName != "" {
		return rs.DeploymentName
	}
	return h.cfg.DeploymentName
}

func (h *Handler) getDefaultRedirectURI() string {
	uris := h.getRedirectURIs()
	if len(uris) > 0 {
		return uris[0]
	}
	return h.cfg.RedirectURI
}

func (h *Handler) getSessionSSOEnabled() bool {
	if rs := h.runtimeSettings.get(); rs != nil {
		return rs.EnableSessionSSO
	}
	return h.cfg.EnableSessionSSO
}

func (h *Handler) getSessionSSOIdleTTL() time.Duration {
	if rs := h.runtimeSettings.get(); rs != nil && rs.SessionSSOIdleHours > 0 {
		return time.Duration(rs.SessionSSOIdleHours) * time.Hour
	}
	if h.cfg.SessionSSOIdleTTL > 0 {
		return h.cfg.SessionSSOIdleTTL
	}
	return 8 * time.Hour
}

func (h *Handler) getSessionSSOMaxTTL() time.Duration {
	if rs := h.runtimeSettings.get(); rs != nil && rs.SessionSSOMaxHours > 0 {
		return time.Duration(rs.SessionSSOMaxHours) * time.Hour
	}
	if h.cfg.SessionSSOMaxTTL > 0 {
		return h.cfg.SessionSSOMaxTTL
	}
	return 720 * time.Hour
}

// --- Admin API: Settings ---

// handleGetSettings returns current runtime settings.
// GET /api/admin/settings
func (h *Handler) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	rs := h.runtimeSettings.get()
	if rs == nil {
		rs = &store.RuntimeSettings{}
	}
	jsonResp(w, rs, http.StatusOK)
}

// handleUpdateSettings updates runtime settings.
// PUT /api/admin/settings
func (h *Handler) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var rs store.RuntimeSettings
	if err := readJSON(r, &rs); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Guard security-relevant fields: a settings PUT must never silently weaken
	// the password policy or enable wildcard CORS (F25). Because these values are
	// read LIVE to enforce security and the UI does a full-document GET-then-PUT,
	// an omitted/zeroed field would otherwise disable a control.
	if rs.PasswordMinLength < 8 {
		rs.PasswordMinLength = 8 // hard floor; weaker policies are not supported
	}
	if strings.TrimSpace(rs.CORSOrigins) == "*" {
		jsonError(w, "cors_origins cannot be '*' — list explicit origins", http.StatusBadRequest)
		return
	}
	h.normalizeRateLimit(&rs)

	// Serialize version-check → save → cache-set → limiter-apply: concurrent
	// PUTs must not leave the store, the cache, and the live limiter with
	// different states.
	h.settingsMu.Lock()
	defer h.settingsMu.Unlock()

	old := h.runtimeSettings.get()
	// Optimistic concurrency: a client that echoes a version (the admin UI
	// always does) is rejected if the document changed since it was loaded —
	// a stale tab must not silently revert another admin's change (e.g. flip
	// rate_limit_disabled back on). A client that sends no version keeps the
	// legacy last-writer-wins behavior.
	if rs.Version != 0 && old != nil && rs.Version != old.Version {
		jsonError(w, "settings changed since they were loaded — reload and retry", http.StatusConflict)
		return
	}
	if old != nil {
		rs.Version = old.Version + 1
	} else {
		rs.Version = 1
	}

	if err := h.store.SaveRuntimeSettings(&rs); err != nil {
		jsonError(w, "failed to save settings: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Changing the rate-limit posture (on/off, limit, or window) is a
	// security event — leave a dedicated audit trail with old and new values
	// beyond the generic settings_updated event.
	if old != nil && (old.RateLimitDisabled != rs.RateLimitDisabled || old.RateLimitMax != rs.RateLimitMax || old.RateLimitWindowS != rs.RateLimitWindowS) {
		h.audit("rate_limit_changed", "admin", getClientIP(r), map[string]interface{}{
			"disabled": rs.RateLimitDisabled, "max": rs.RateLimitMax, "window_s": rs.RateLimitWindowS,
			"old_disabled": old.RateLimitDisabled, "old_max": old.RateLimitMax, "old_window_s": old.RateLimitWindowS,
		})
	}

	h.runtimeSettings.set(&rs)
	h.applyRateLimit(&rs)
	h.audit("settings_updated", "admin", getClientIP(r), nil)
	jsonResp(w, rs, http.StatusOK)
}
