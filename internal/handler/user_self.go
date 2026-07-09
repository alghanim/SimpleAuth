package handler

import (
	"net/http"
	"time"
)

// handleUserLogoutAll terminates the CALLER'S OWN presence everywhere (SA-3):
// revoke their refresh families, blacklist their outstanding access tokens until
// those tokens expire, and delete their shared __sa_sso sessions. Authenticated
// by the user's own access token of any audience — the target is always the
// token's subject, so a user can only ever log themselves out.
//
// This exposes, user-scoped, the exact composite the master-gated
// handleRevokeSessions performs. It is the user-invokable trigger for the
// existing revocation machinery — the access-token blacklist it sets is already
// consulted on both refresh paths (auth.go / oidc.go IsUserAccessRevoked), so a
// refresh cannot silently re-mint after logout. Under offline JWKS verification a
// live access token stays valid until its exp; the residual window is therefore
// bounded by the access-token TTL, which is why the blacklist is set to now+TTL.
//
// POST /api/user/logout-all   Authorization: Bearer <caller's own access token>
func (h *Handler) handleUserLogoutAll(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)
	if !h.loginLimiter.allow(ip) {
		jsonError(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	tokenStr := extractBearerToken(r)
	if tokenStr == "" {
		jsonError(w, "missing authorization header", http.StatusUnauthorized)
		return
	}
	// validateAccessToken rejects app-mgmt / refresh / id_token classes and honors
	// existing revocation, so only a genuine user access token reaches here.
	claims, err := h.validateAccessToken(tokenStr)
	if err != nil {
		jsonError(w, "invalid or revoked token", http.StatusUnauthorized)
		return
	}
	guid := claims.Subject // never a request parameter — self-scope only

	if err := h.store.RevokeUserTokens(guid); err != nil {
		jsonError(w, "failed to revoke sessions", http.StatusInternalServerError)
		return
	}
	h.store.RevokeAllUserAccessTokens(guid, time.Now().Add(h.cfg.AccessTTL))
	h.store.DeleteUserSessions(guid)

	var auditData map[string]interface{}
	if claims.Impersonated {
		auditData = map[string]interface{}{"impersonated_by": claims.ImpersonatedBy}
	}
	h.audit("user_logout_all", guid, ip, auditData)

	jsonResp(w, map[string]string{
		"status": "logged out everywhere (access + refresh tokens + SSO sessions)",
	}, http.StatusOK)
}
