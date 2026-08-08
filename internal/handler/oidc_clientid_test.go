package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// decodeJWTPayload returns the full decoded claim set of a JWT without verifying
// it. The package already has claim-specific decoders (tokenAudiences,
// tokenRoles, tokenPerms); this one exists because these tests assert on azp and
// resource_access, which none of those expose. Audience assertions below reuse
// tokenAudiences rather than adding a second audience matcher.
func decodeJWTPayload(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a JWT, got %q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

// TestOIDCClientIDRoundTrip pins the SA fix on the OIDC authorization-code flow:
// the client_id an app sends on GET /realms/.../auth must survive into (a) the
// rendered form's hidden field, (b) the Kerberos SSO link, (c) the credential
// POST, and (d) the audience/azp of every token the resulting code yields.
//
// Before the fix, showOIDCLoginPage stamped a hardcoded h.oidcClientID() ==
// "simpleauth" into the form. Where that literal matches defaultAppID(), the POST
// resolved the DEFAULT app rather than the requested one — so the auth code bound
// to the wrong app and the tokens carried the default app's audience and the
// user's global roles, silently bypassing the requested app's per-app authz.
// Where AUTH_CLIENT_ID names a different default, the POST 400s "unknown client".
//
// This is the OIDC sibling of TestHostedLoginClientIDRoundTrip (handler_test.go),
// which pins the same round trip for the hosted-login flow. Both flows render a
// credential form whose hidden client_id decides which app the POST resolves; a
// fix to one is not a fix to the other.
func TestOIDCClientIDRoundTrip(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()

	const realm = "test-issuer"
	const authzPath = "/realms/" + realm + "/protocol/openid-connect/auth"
	const tokenPath = "/realms/" + realm + "/protocol/openid-connect/token"
	const introspectPath = tokenPath + "/introspect"
	const cb = "https://shop2.example/cb"

	// Enable the Kerberos SSO branch so the SSO link's client_id carry is exercised.
	// The path never gets dereferenced — only its emptiness gates the link.
	h.cfg.KRB5Keytab = "/nonexistent/test.keytab"

	// An app with its OWN redirect allowlist (the v2 way) and a local user.
	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"app_id": "shop2", "audience": "shop2", "allow_local_users": true,
		"redirect_uris": []string{cb},
	}, adm)
	if w.Code != http.StatusCreated {
		t.Fatalf("create app: %d %s", w.Code, w.Body.String())
	}
	var app map[string]interface{}
	parseJSON(t, w, &app)
	secret := app["app_secret"].(string)
	doJSON(h, "POST", "/api/app/users", map[string]interface{}{
		"username": "buyer", "password": "buypass1",
	}, basicAuth("shop2", secret))

	// (a) + (b) GET the authorize endpoint: the form and the SSO link must both
	// carry shop2, never the hardcoded default app.
	req := httptest.NewRequest("GET",
		authzPath+"?client_id=shop2&response_type=code&scope=openid&redirect_uri="+url.QueryEscape(cb), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorize page: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `name="client_id" value="shop2"`) {
		t.Fatal("OIDC login form must carry the REQUESTED client_id as a hidden field")
	}
	if strings.Contains(body, `name="client_id" value="simpleauth"`) {
		t.Fatal("OIDC login form must not stamp the hardcoded default app id")
	}
	if !strings.Contains(body, "client_id=shop2") {
		t.Fatal("Kerberos SSO link must carry client_id so the SPNEGO path resolves the same app")
	}

	// (c) the credential POST redirects to shop2's OWN callback with a code.
	form := url.Values{}
	form.Set("client_id", "shop2")
	form.Set("redirect_uri", cb)
	form.Set("scope", "openid")
	form.Set("username", "buyer")
	form.Set("password", "buypass1")
	form.Set("_csrf", "tok123")
	preq := httptest.NewRequest("POST", authzPath, strings.NewReader(form.Encode()))
	preq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	preq.AddCookie(&http.Cookie{Name: "__csrf", Value: "tok123"})
	prec := httptest.NewRecorder()
	h.ServeHTTP(prec, preq)
	if prec.Code != http.StatusFound {
		t.Fatalf("authorize POST: expected 302, got %d %s", prec.Code, prec.Body.String())
	}
	loc := prec.Header().Get("Location")
	if !strings.HasPrefix(loc, cb+"?code=") {
		t.Fatalf("expected a code redirect to the app's own callback, got %q", loc)
	}
	locURL, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := locURL.Query().Get("code")
	if code == "" {
		t.Fatal("expected an auth code in the redirect")
	}

	// (d) the code exchanges for tokens bound to shop2 — the payoff. Before the
	// fix these carried aud/azp "simpleauth".
	ex := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cb}}
	treq := httptest.NewRequest("POST", tokenPath, strings.NewReader(ex.Encode()))
	treq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	trec := httptest.NewRecorder()
	h.ServeHTTP(trec, treq)
	if trec.Code != http.StatusOK {
		t.Fatalf("token exchange: %d %s", trec.Code, trec.Body.String())
	}
	var tok map[string]interface{}
	parseJSON(t, trec, &tok)

	accessToken, _ := tok["access_token"].(string)
	if accessToken == "" {
		t.Fatal("expected an access_token")
	}
	access := decodeJWTPayload(t, accessToken)
	if auds := tokenAudiences(t, accessToken); !slices.Contains(auds, "shop2") {
		t.Fatalf("access token must carry shop2 audience, got aud=%v", auds)
	}
	if access["azp"] != "shop2" {
		t.Fatalf("access token azp must be shop2, got %v", access["azp"])
	}
	if _, ok := access["resource_access"].(map[string]interface{})["shop2"]; !ok {
		t.Fatalf("resource_access must be keyed by shop2, got %v", access["resource_access"])
	}

	idToken, _ := tok["id_token"].(string)
	if idToken == "" {
		t.Fatal("expected an id_token")
	}
	id := decodeJWTPayload(t, idToken)
	if auds := tokenAudiences(t, idToken); !slices.Contains(auds, "shop2") {
		t.Fatalf("id_token must carry shop2 audience, got aud=%v", auds)
	}
	if id["azp"] != "shop2" {
		t.Fatalf("id_token azp must be shop2, got %v", id["azp"])
	}

	// (e) introspection reports the token's OWN app, not a hardcoded default.
	in := url.Values{"token": {accessToken}, "client_secret": {"test-secret"}}
	ireq := httptest.NewRequest("POST", introspectPath, strings.NewReader(in.Encode()))
	ireq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	irec := httptest.NewRecorder()
	h.ServeHTTP(irec, ireq)
	if irec.Code != http.StatusOK {
		t.Fatalf("introspect: %d %s", irec.Code, irec.Body.String())
	}
	var intro map[string]interface{}
	parseJSON(t, irec, &intro)
	if intro["active"] != true {
		t.Fatalf("introspected token should be active: %v", intro)
	}
	if intro["client_id"] != "shop2" {
		t.Fatalf("introspection must report the token's own client_id, got %v", intro["client_id"])
	}
	// A single audience is encoded as a bare string (Keycloak compatibility), not
	// a 1-element array — migrated RPs string-compare this field.
	if aud, ok := intro["aud"].(string); !ok || aud != "shop2" {
		t.Fatalf("introspection aud must be the bare string \"shop2\", got %#v", intro["aud"])
	}
}

// TestOIDCLoginPageEscapesReflectedValues pins the html/template conversion: the
// authorize page reflects several attacker-supplied values into three different
// escaping contexts (HTML attribute, href URL, JS string literal). None may break
// out. The `error` parameter is the one with real history — it is reflected into
// the page body, and the .error div's presence is also read by the inline script.
func TestOIDCLoginPageEscapesReflectedValues(t *testing.T) {
	h, _ := testSetup(t)
	adm := adminHeaders()

	const realm = "test-issuer"
	const authzPath = "/realms/" + realm + "/protocol/openid-connect/auth"
	const cb = "https://shop3.example/cb"

	w := doJSON(h, "POST", "/api/admin/apps", map[string]interface{}{
		"app_id": "shop3", "audience": "shop3", "redirect_uris": []string{cb},
	}, adm)
	if w.Code != http.StatusCreated {
		t.Fatalf("create app: %d %s", w.Code, w.Body.String())
	}

	// Every one of these lands in the rendered page. The payloads close an
	// attribute, a script block, and a JS string respectively.
	const attrBreak = `" onerror="alert(1)`
	const tagBreak = `</script><script>alert(1)</script>`
	q := url.Values{}
	q.Set("client_id", "shop3")
	q.Set("redirect_uri", cb)
	q.Set("response_type", "code")
	q.Set("state", attrBreak)
	q.Set("nonce", tagBreak)
	q.Set("scope", attrBreak)
	q.Set("error", tagBreak)

	req := httptest.NewRequest("GET", authzPath+"?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorize page: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	// No payload may survive as live markup anywhere in the response.
	for _, bad := range []string{
		`</script><script>`,
		`" onerror="`,
		`onerror="alert(1)"`,
	} {
		if strings.Contains(body, bad) {
			t.Fatalf("reflected value escaped its context: found %q in the rendered page", bad)
		}
	}

	// The error banner must still render (the inline script keys off .error to
	// decide whether to show the manual form), with the payload inert.
	if !strings.Contains(body, `class="error"`) {
		t.Fatal("error banner must render when ?error= is present")
	}
	if !strings.Contains(body, "&lt;/script&gt;") {
		t.Fatal("reflected error must appear HTML-escaped, not raw")
	}

	// And with no ?error=, no banner — the conditional must actually be conditional.
	q.Del("error")
	req2 := httptest.NewRequest("GET", authzPath+"?"+q.Encode(), nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if strings.Contains(rec2.Body.String(), `class="error"`) {
		t.Fatal("error banner must not render when ?error= is absent")
	}
}

// TestOIDCDefaultAppStillWorks guards the fix against over-correction: a request
// that genuinely omits client_id must still resolve the default app and mint a
// usable token, exactly as before.
func TestOIDCDefaultAppStillWorks(t *testing.T) {
	h, s := testSetup(t)
	adm := adminHeaders()

	const realm = "test-issuer"
	const authzPath = "/realms/" + realm + "/protocol/openid-connect/auth"
	const cb = "https://home.example/cb"

	// The default app id is reserved from the admin API — resolveApp synthesizes
	// it from config (apps.go), carrying the global allowlist, so seed that.
	h.cfg.RedirectURIs = []string{cb}

	w := doJSON(h, "POST", "/api/admin/users", map[string]interface{}{
		"display_name": "Home User", "password": "pass1234",
	}, adm)
	var user map[string]interface{}
	parseJSON(t, w, &user)
	s.SetIdentityMapping("local", "homeuser", user["guid"].(string))

	// No client_id at all -> the form should stamp the default app id.
	req := httptest.NewRequest("GET", authzPath+"?response_type=code&redirect_uri="+url.QueryEscape(cb), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorize page: %d %s", rec.Code, rec.Body.String())
	}
	want := `name="client_id" value="` + h.defaultAppID() + `"`
	if !strings.Contains(rec.Body.String(), want) {
		t.Fatalf("omitted client_id must resolve to the default app; expected %s", want)
	}

	form := url.Values{}
	form.Set("redirect_uri", cb)
	form.Set("username", "homeuser")
	form.Set("password", "pass1234")
	form.Set("_csrf", "tok123")
	preq := httptest.NewRequest("POST", authzPath, strings.NewReader(form.Encode()))
	preq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	preq.AddCookie(&http.Cookie{Name: "__csrf", Value: "tok123"})
	prec := httptest.NewRecorder()
	h.ServeHTTP(prec, preq)
	if prec.Code != http.StatusFound {
		t.Fatalf("default-app authorize POST: expected 302, got %d %s", prec.Code, prec.Body.String())
	}
	if loc := prec.Header().Get("Location"); !strings.HasPrefix(loc, cb+"?code=") {
		t.Fatalf("expected a code redirect for the default app, got %q", loc)
	}
}
