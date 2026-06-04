package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"simpleauth/internal/migrate"
)

// --- Standalone side: push this deployment into a central app ---
//
// A master admin on the standalone enters the central URL, the target app_id, and
// the migration token the central minted. The standalone packages its directory +
// authz policy and calls the central's preflight (dry run) / commit. The whole
// directory (incl. local-user password hashes) crosses this link, so it goes over
// the operator-supplied URL with TLS verification ON (default http.Client).

// migrationHTTP is the outbound client for cross-install calls. It refuses to
// follow redirects: a migration target must not bounce us (a redirect could
// downgrade https->http or steer the directory bundle to an unintended host).
var migrationHTTP = &http.Client{
	Timeout: 60 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return fmt.Errorf("central must not redirect")
	},
}

// isLoopbackHost reports whether host is localhost / a loopback IP.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

type migrateOutboundReq struct {
	CentralURL  string `json:"central_url"`
	AppID       string `json:"app_id"`
	Token       string `json:"token"`
	CarrySecret bool   `json:"carry_secret"`
}

// callCentral packages this deployment and POSTs it to the central path with the
// migration token; it relays the central's status + body back to the caller.
func (h *Handler) callCentral(w http.ResponseWriter, r *http.Request, path string) {
	var req migrateOutboundReq
	if err := readJSON(r, &req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	base := strings.TrimRight(strings.TrimSpace(req.CentralURL), "/")
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		jsonError(w, "central URL must be a valid http(s) URL", http.StatusBadRequest)
		return
	}
	// The bundle carries local-user password hashes + the app secret hash, so it
	// must not cross the network in cleartext: require https for non-loopback.
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		jsonError(w, "central URL must use https:// (http is only allowed to localhost)", http.StatusBadRequest)
		return
	}

	bundle, err := migrate.Package(h.store, h.defaultAppID(), h.version)
	if err != nil {
		jsonError(w, "failed to package this deployment: "+err.Error(), http.StatusInternalServerError)
		return
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"app_id": req.AppID, "bundle": bundle, "carry_secret": req.CarrySecret,
	})

	creq, err := http.NewRequest("POST", base+path, bytes.NewReader(payload))
	if err != nil {
		jsonError(w, "bad central URL", http.StatusBadRequest)
		return
	}
	creq.Header.Set("Content-Type", "application/json")
	creq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(req.Token))

	resp, err := migrationHTTP.Do(creq)
	if err != nil {
		jsonError(w, "could not reach the central deployment: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))

	if path == "/api/migration/commit" && resp.StatusCode == http.StatusOK {
		h.audit("migration_pushed", "admin", getClientIP(r), map[string]interface{}{
			"central": base, "app_id": req.AppID,
		})
	}
	// Relay the central's verdict verbatim so the UI shows the real report/result.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	if len(body) > 0 {
		w.Write(body)
	} else {
		fmt.Fprint(w, "{}")
	}
}

// handleMigrateToCentralPreflight asks the central for a dry-run report.
// POST /api/admin/migrate-to-central/preflight  (master admin)
func (h *Handler) handleMigrateToCentralPreflight(w http.ResponseWriter, r *http.Request) {
	h.callCentral(w, r, "/api/migration/preflight")
}

// handleMigrateToCentralCommit packages + commits this deployment to the central.
// POST /api/admin/migrate-to-central/commit  (master admin)
func (h *Handler) handleMigrateToCentralCommit(w http.ResponseWriter, r *http.Request) {
	h.callCentral(w, r, "/api/migration/commit")
}
