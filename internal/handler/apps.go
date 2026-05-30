package handler

import (
	"fmt"

	"simpleauth/internal/store"
)

// defaultAppID is the app_id of the default app (wraps the legacy single
// client). Used when a request carries no explicit app/client_id.
func (h *Handler) defaultAppID() string {
	if h.cfg.ClientID != "" {
		return h.cfg.ClientID
	}
	return "simpleauth"
}

// resolveApp returns the app a request is for. An empty clientID resolves to the
// default app; if the default app row doesn't exist yet (e.g. a fresh store
// before the startup migration ran, or in tests), a transient default is
// synthesized so tokens still issue. A named-but-unknown or disabled app is an
// error.
func (h *Handler) resolveApp(clientID string) (*store.App, error) {
	id := clientID
	if id == "" {
		id = h.defaultAppID()
	}
	a, err := h.store.GetApp(id)
	if err != nil {
		if id == h.defaultAppID() {
			return &store.App{AppID: id, Audience: id, RedirectURIs: h.cfg.RedirectURIs}, nil
		}
		return nil, fmt.Errorf("unknown app: %s", id)
	}
	if a.Disabled {
		return nil, fmt.Errorf("app disabled: %s", id)
	}
	return a, nil
}

// appAudience returns the audience string for an app (defaults to app_id).
func appAudience(a *store.App) string {
	if a.Audience != "" {
		return a.Audience
	}
	return a.AppID
}

// appAllowsRedirect reports whether redirectURI is permitted for app a. If the
// app declares its own redirect_uris, those are authoritative; otherwise it
// falls back to the global runtime allowlist.
func (h *Handler) appAllowsRedirect(a *store.App, redirectURI string) bool {
	if len(a.RedirectURIs) > 0 {
		return isAllowedRedirect(a.RedirectURIs, redirectURI)
	}
	return isAllowedRedirect(h.getRedirectURIs(), redirectURI)
}
