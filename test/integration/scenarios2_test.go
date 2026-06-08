//go:build integration

package integration

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"simpleauth/internal/migrate"
)

func basicAuth(id, secret string) map[string]string {
	return map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))}
}

// rawReq issues a request with explicit headers only (no admin bearer), for the
// app-credential (Basic) flow.
func rawReq(t *testing.T, c *http.Client, method, url string, headers map[string]string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func mintToken(t *testing.T, central *node, appID string) string {
	t.Helper()
	var tok struct {
		Token string `json:"migration_token"`
	}
	json.Unmarshal(central.must(t, "POST", "/api/admin/apps/"+appID+"/migration-token", nil), &tok)
	if tok.Token == "" {
		t.Fatalf("no migration token for %s", appID)
	}
	return tok.Token
}

// TestMoreScenarios extends the matrix: the seamless-secret round-trip, the
// central-not-on-AD block, the live security guards (single-use token +
// fresh-target), and a mixed AD+local population migrating in one shot.
func TestMoreScenarios(t *testing.T) {
	central := &node{centralURL, centralKey, caClient()}
	local := &node{standaloneURL, standaloneKey, &http.Client{Timeout: 20 * time.Second}}
	sAD := &node{env("ITEST_STANDALONE_AD_URL", "http://127.0.0.1:9445"), "ad-admin-key", &http.Client{Timeout: 20 * time.Second}}

	waitReady(t, "central", centralURL, central.c)
	waitReady(t, "standalone-local", local.base, local.c)
	waitReady(t, "standalone-ad", sAD.base, sAD.c)

	corpCfg := ldapConfig("ldap://ldap-corp:389", "dc=corp,dc=local", "corp.local")
	central.must(t, "PUT", "/api/admin/ldap", corpCfg)
	sAD.must(t, "PUT", "/api/admin/ldap", corpCfg)

	// The consumer app keeps its OWN secret after cutover: carry_secret moves the
	// source home app's secret hash, so the same secret authenticates on the central.
	t.Run("carry_secret_roundtrip", func(t *testing.T) {
		var rot struct {
			Secret string `json:"app_secret"`
		}
		json.Unmarshal(local.must(t, "POST", "/api/admin/apps/simpleauth/rotate-secret", nil), &rot)
		if rot.Secret == "" {
			t.Fatal("no rotated secret")
		}
		central.must(t, "POST", "/api/admin/apps", map[string]any{"app_id": "secretapp", "audience": "secretapp"})
		mig := map[string]any{"central_url": centralInternal, "app_id": "secretapp", "token": mintToken(t, central, "secretapp"), "carry_secret": true}
		local.must(t, "POST", "/api/admin/migrate-to-central/commit", mig)

		if code, data := rawReq(t, central.c, "POST", centralURL+"/api/app/token", basicAuth("secretapp", rot.Secret)); code != http.StatusOK {
			t.Fatalf("carried secret must authenticate on the central, got %d: %s", code, data)
		}
		if code, _ := rawReq(t, central.c, "POST", centralURL+"/api/app/token", basicAuth("secretapp", "wrong-secret")); code != http.StatusUnauthorized {
			t.Fatalf("a wrong secret must be rejected (401), got %d", code)
		}
		t.Log("OK carry_secret: the consumer's original secret authenticates the migrated central app")
	})

	// An AD standalone cannot migrate into a central that has no AD.
	t.Run("central_not_on_ad", func(t *testing.T) {
		loginRetry(t, sAD, "bob", "bobpass", "")
		bob := findGUIDBySAM(t, sAD, "bob")
		sAD.must(t, "PUT", "/api/admin/role-permissions", map[string][]string{"editor": {}})
		sAD.must(t, "PUT", "/api/admin/users/"+bob+"/roles", []string{"editor"})

		central.must(t, "DELETE", "/api/admin/ldap", nil)
		defer central.must(t, "PUT", "/api/admin/ldap", corpCfg) // restore for any later use

		central.must(t, "POST", "/api/admin/apps", map[string]any{"app_id": "noad", "audience": "noad"})
		mig := map[string]any{"central_url": centralInternal, "app_id": "noad", "token": mintToken(t, central, "noad")}
		var rep migrate.Report
		json.Unmarshal(sAD.must(t, "POST", "/api/admin/migrate-to-central/preflight", mig), &rep)
		if rep.OK() || len(rep.Blocked) == 0 {
			t.Fatalf("AD users must be blocked when the central has no AD; got %+v", rep)
		}
		t.Logf("OK central_not_on_ad: %d AD user(s) blocked", len(rep.Blocked))
	})

	// The cross-install security guards: single-use token + fresh-target.
	t.Run("migration_guards", func(t *testing.T) {
		local.must(t, "PUT", "/api/admin/role-permissions", map[string][]string{"r": {}}) // ensure the bundle carries some authz
		central.must(t, "POST", "/api/admin/apps", map[string]any{"app_id": "guardapp", "audience": "guardapp"})
		tok := mintToken(t, central, "guardapp")
		mig := map[string]any{"central_url": centralInternal, "app_id": "guardapp", "token": tok}

		local.must(t, "POST", "/api/admin/migrate-to-central/commit", mig) // first commit OK
		if code, _ := local.do(t, "POST", "/api/admin/migrate-to-central/commit", mig); code != http.StatusUnauthorized {
			t.Fatalf("a reused single-use token must be 401, got %d", code)
		}
		// A brand-new token cannot re-migrate into the now-populated app.
		mig2 := map[string]any{"central_url": centralInternal, "app_id": "guardapp", "token": mintToken(t, central, "guardapp")}
		var rep migrate.Report
		json.Unmarshal(local.must(t, "POST", "/api/admin/migrate-to-central/preflight", mig2), &rep)
		if rep.OK() {
			t.Fatalf("fresh-target guard must block migrating into a non-empty app; got %+v", rep)
		}
		t.Log("OK migration_guards: token single-use + fresh-target enforced across containers")
	})

	// A standalone with BOTH an AD user and a local break-glass account: the AD
	// user migrates policy-only, the local one carries its hash — in one bundle.
	t.Run("mixed_population", func(t *testing.T) {
		sAD.must(t, "PUT", "/api/admin/permissions", []string{"x:read", "x:write"})
		sAD.must(t, "PUT", "/api/admin/role-permissions", map[string][]string{"editor": {"x:write"}, "ops": {"x:read"}})
		loginRetry(t, sAD, "bob", "bobpass", "")
		bob := findGUIDBySAM(t, sAD, "bob")
		sAD.must(t, "PUT", "/api/admin/users/"+bob+"/roles", []string{"editor"})
		var bg struct {
			GUID string `json:"guid"`
		}
		json.Unmarshal(sAD.must(t, "POST", "/api/admin/users", map[string]any{"display_name": "Breakglass", "password": "bgpass123"}), &bg)
		sAD.must(t, "PUT", "/api/admin/users/"+bg.GUID+"/mappings", map[string]any{"provider": "local", "external_id": "breakglass"})
		sAD.must(t, "PUT", "/api/admin/users/"+bg.GUID+"/roles", []string{"ops"})

		central.must(t, "POST", "/api/admin/apps", map[string]any{"app_id": "mixedapp", "audience": "mixedapp"})
		mig := map[string]any{"central_url": centralInternal, "app_id": "mixedapp", "token": mintToken(t, central, "mixedapp"), "carry_secret": true}

		var rep migrate.Report
		json.Unmarshal(sAD.must(t, "POST", "/api/admin/migrate-to-central/preflight", mig), &rep)
		if !rep.OK() || rep.ADUsersSameDomain != 1 || rep.LocalUsers != 1 {
			t.Fatalf("mixed preflight: want 1 AD + 1 local, none blocked; got %+v", rep)
		}
		var res migrate.ApplyResult
		json.Unmarshal(sAD.must(t, "POST", "/api/admin/migrate-to-central/commit", mig), &res)
		if res.LocalUsersCreated != 1 {
			t.Fatalf("mixed: want exactly the break-glass user materialized; got %+v", res)
		}

		// AD user re-binds from AD; local break-glass uses its carried hash.
		if rb, _, _ := tokenClaims(t, loginRetry(t, central, "bob", "bobpass", "mixedapp")); !has(rb, "editor") {
			t.Fatalf("bob (AD) on central roles = %v, want editor", rb)
		}
		if rl, _, _ := tokenClaims(t, loginRetry(t, central, "breakglass", "bgpass123", "mixedapp")); !has(rl, "ops") {
			t.Fatalf("break-glass (local) on central roles = %v, want ops", rl)
		}
		t.Log("OK mixed_population: AD (policy-only) + local (carried hash) migrated together; both authenticate on central")
	})

	// An AD user gets a role on a central app purely via GROUP membership (no
	// per-user assignment) — bob is in "Finance" (his ou attr; see ldap/corp.ldif).
	t.Run("group_to_role", func(t *testing.T) {
		central.must(t, "POST", "/api/admin/apps", map[string]any{"app_id": "fin", "audience": "fin"})
		central.must(t, "PUT", "/api/admin/apps/fin/authz", map[string]any{
			"roles":             []string{"analyst"},
			"role_permissions":  map[string][]string{"analyst": {"fin:read"}},
			"group_assignments": map[string][]string{"Finance": {"analyst"}},
		})
		roles, perms, _ := tokenClaims(t, loginRetry(t, central, "bob", "bobpass", "fin"))
		if !has(roles, "analyst") || !has(perms, "fin:read") {
			t.Fatalf("group->role: bob via Finance should be analyst/fin:read; got roles=%v perms=%v", roles, perms)
		}
		t.Log("OK group_to_role: bob gets 'analyst' on central via Finance group membership (no per-user assignment)")
	})
}
