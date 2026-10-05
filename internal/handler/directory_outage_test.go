package handler

import (
	"net"
	"net/http"
	"testing"
	"time"

	"simpleauth/internal/store"
)

// unreachableLDAP points the LDAP config at a local port with nothing listening,
// so every directory lookup fails with a connection error (an "AD outage").
func unreachableLDAP(t *testing.T, h *Handler) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if err := h.saveLDAPConfigEncrypted(&store.LDAPConfig{
		URL: "ldap://" + addr, BaseDN: "dc=corp,dc=test", AllowInsecure: true,
	}); err != nil {
		t.Fatal(err)
	}
}

func directoryUser(t *testing.T, s store.Store) *store.User {
	t.Helper()
	u := &store.User{DisplayName: "AD User", SAMAccountName: "aduser"}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	s.SetIdentityMapping("ldap", "aduser", u.GUID)
	return u
}

// TestDirectoryOutagePolicy: while AD is unreachable, the admin-chosen policy
// decides whether a directory user gets in.
func TestDirectoryOutagePolicy(t *testing.T) {
	h, s := testSetup(t)
	unreachableLDAP(t, h)
	u := directoryUser(t, s)

	// Default is grace (10h). Never confirmed active → denied.
	if p, g := h.getDirectoryOutagePolicy(); p != directoryOutageGrace || g != 10*time.Hour {
		t.Fatalf("default policy = %q/%s, want grace/10h", p, g)
	}
	if !h.directoryAccountDisabled(u) {
		t.Fatal("grace: user never confirmed by AD must be denied during an outage")
	}

	// Confirmed active 1h ago → allowed within the 10h grace window.
	s.SetConfigValue(dirCheckKeyPrefix+u.GUID, []byte(time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)))
	h.dirChecked.Delete(u.GUID) // force a read from the store (survives restart)
	if h.directoryAccountDisabled(u) {
		t.Fatal("grace: user confirmed 1h ago must be allowed during an outage")
	}

	// Confirmed 11h ago → outside the window → denied.
	h.dirChecked.Store(u.GUID, time.Now().Add(-11*time.Hour))
	if !h.directoryAccountDisabled(u) {
		t.Fatal("grace: user confirmed 11h ago must be denied (window is 10h)")
	}

	// Block: denied even when recently confirmed.
	h.dirChecked.Store(u.GUID, time.Now())
	putSettings(t, h, func(rs *store.RuntimeSettings) { rs.DirectoryOutagePolicy = "block" })
	if !h.directoryAccountDisabled(u) {
		t.Fatal("block: every directory user must be denied during an outage")
	}

	// Allow: allowed even when never confirmed.
	h.dirChecked.Delete(u.GUID)
	s.DeleteConfigValue(dirCheckKeyPrefix + u.GUID)
	putSettings(t, h, func(rs *store.RuntimeSettings) { rs.DirectoryOutagePolicy = "allow" })
	if h.directoryAccountDisabled(u) {
		t.Fatal("allow: directory users must be allowed during an outage")
	}

	// Non-directory (local-only) users are never affected by AD outages.
	local := &store.User{DisplayName: "Local"}
	s.CreateUser(local)
	s.SetIdentityMapping("local", "localuser", local.GUID)
	putSettings(t, h, func(rs *store.RuntimeSettings) { rs.DirectoryOutagePolicy = "block" })
	if h.directoryAccountDisabled(local) {
		t.Fatal("local-only users must never be checked against AD")
	}
}

// TestDirectoryOutageSettingsValidation: the settings API rejects unknown
// policies, defaults omitted values, and clamps the grace window.
func TestDirectoryOutageSettingsValidation(t *testing.T) {
	h, _ := testSetup(t)
	rs := *h.runtimeSettings.get()
	if rs.DirectoryOutagePolicy != "grace" || rs.DirectoryOutageGraceHours != 10 {
		t.Fatalf("seeded settings = %q/%d, want grace/10", rs.DirectoryOutagePolicy, rs.DirectoryOutageGraceHours)
	}

	bad := rs
	bad.DirectoryOutagePolicy = "sometimes"
	if w := doJSON(h, "PUT", "/api/admin/settings", &bad, adminHeaders()); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown policy: want 400, got %d", w.Code)
	}

	putSettings(t, h, func(rs *store.RuntimeSettings) {
		rs.DirectoryOutagePolicy = ""
		rs.DirectoryOutageGraceHours = 0
	})
	if got := h.runtimeSettings.get(); got.DirectoryOutagePolicy != "grace" || got.DirectoryOutageGraceHours != 10 {
		t.Fatalf("omitted values = %q/%d, want grace/10", got.DirectoryOutagePolicy, got.DirectoryOutageGraceHours)
	}

	putSettings(t, h, func(rs *store.RuntimeSettings) { rs.DirectoryOutageGraceHours = 10000 })
	if got := h.runtimeSettings.get().DirectoryOutageGraceHours; got != 168 {
		t.Fatalf("grace clamp = %d, want 168", got)
	}
}
