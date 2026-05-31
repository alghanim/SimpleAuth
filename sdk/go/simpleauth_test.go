package simpleauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// testSigner holds an RSA key pair and the kid it is published under.
type testSigner struct {
	key *rsa.PrivateKey
	kid string
}

func newTestSigner(t *testing.T, kid string) *testSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &testSigner{key: key, kid: kid}
}

// sign builds an RS256 JWT for the given claims signed with the test key.
func (s *testSigner) sign(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": s.kid}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	signingInput := enc(hb) + "." + enc(cb)
	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + enc(sig)
}

// jwksHandler returns an http.HandlerFunc serving the signer's public key as a
// JWKS document, incrementing *hits on every request.
func (s *testSigner) jwksHandler(hits *int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(hits, 1)
		pub := s.key.Public().(*rsa.PublicKey)
		n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		eBytes := []byte{byte(pub.E >> 16), byte(pub.E >> 8), byte(pub.E)}
		// Trim leading zero bytes from the exponent.
		for len(eBytes) > 1 && eBytes[0] == 0 {
			eBytes = eBytes[1:]
		}
		e := base64.RawURLEncoding.EncodeToString(eBytes)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"keys":[{"kty":"RSA","kid":%q,"use":"sig","alg":"RS256","n":%q,"e":%q}]}`, s.kid, n, e)
	}
}

// newTestClient wires a Client to an httptest server that serves the signer's
// JWKS at /.well-known/jwks.json. It returns the client and a pointer to the
// JWKS hit counter.
func newTestClient(t *testing.T, signer *testSigner, opts Options) (*Client, *int64) {
	t.Helper()
	var hits int64
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", signer.jwksHandler(&hits))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	opts.URL = srv.URL
	c := New(opts)
	return c, &hits
}

func validAccessClaims() map[string]interface{} {
	return map[string]interface{}{
		"sub":   "user-guid-123",
		"name":  "Test User",
		"roles": []string{"admin"},
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iss":   "simpleauth",
	}
}

func TestVerify_AcceptsAccessToken(t *testing.T) {
	signer := newTestSigner(t, "k1")
	c, _ := newTestClient(t, signer, Options{})

	tok := signer.sign(t, validAccessClaims())
	user, err := c.Verify(tok)
	if err != nil {
		t.Fatalf("expected valid access token to verify, got %v", err)
	}
	if user.Sub != "user-guid-123" {
		t.Fatalf("unexpected sub %q", user.Sub)
	}
	if !user.HasRole("admin") {
		t.Fatalf("expected admin role")
	}
}

func TestVerify_RejectsRefreshToken(t *testing.T) {
	signer := newTestSigner(t, "k1")
	c, _ := newTestClient(t, signer, Options{})

	claims := validAccessClaims()
	claims["family_id"] = "fam-123" // refresh-token marker
	tok := signer.sign(t, claims)

	if _, err := c.Verify(tok); err == nil {
		t.Fatal("expected refresh token (family_id) to be rejected")
	}
}

func TestVerify_RejectsAppMgmtToken(t *testing.T) {
	signer := newTestSigner(t, "k1")
	c, _ := newTestClient(t, signer, Options{})

	claims := validAccessClaims()
	claims["typ"] = "app-mgmt"
	claims["sub"] = "app-id-xyz"
	tok := signer.sign(t, claims)

	if _, err := c.Verify(tok); err == nil {
		t.Fatal("expected app-mgmt token (typ=app-mgmt) to be rejected")
	}
}

func TestVerify_RejectsIDToken(t *testing.T) {
	signer := newTestSigner(t, "k1")
	// Even with the correct audience configured, an ID token must be rejected.
	c, _ := newTestClient(t, signer, Options{Audience: "my-app"})

	claims := validAccessClaims()
	claims["typ"] = "ID"
	claims["aud"] = "my-app"
	tok := signer.sign(t, claims)

	if _, err := c.Verify(tok); err == nil {
		t.Fatal("expected ID token (typ=ID) to be rejected even with matching aud")
	}
}

func TestVerify_RejectsExpiredToken(t *testing.T) {
	signer := newTestSigner(t, "k1")
	c, _ := newTestClient(t, signer, Options{})

	claims := validAccessClaims()
	claims["exp"] = time.Now().Add(-time.Minute).Unix()
	tok := signer.sign(t, claims)

	if _, err := c.Verify(tok); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}

func TestVerify_RejectsMissingExp(t *testing.T) {
	signer := newTestSigner(t, "k1")
	c, _ := newTestClient(t, signer, Options{})

	claims := validAccessClaims()
	delete(claims, "exp")
	tok := signer.sign(t, claims)

	if _, err := c.Verify(tok); err == nil {
		t.Fatal("expected token without exp to be rejected")
	}
}

func TestVerify_IssuerCheck(t *testing.T) {
	signer := newTestSigner(t, "k1")
	c, _ := newTestClient(t, signer, Options{ExpectedIssuer: "simpleauth"})

	// Matching issuer passes.
	if _, err := c.Verify(signer.sign(t, validAccessClaims())); err != nil {
		t.Fatalf("expected matching issuer to verify, got %v", err)
	}

	// Wrong issuer fails.
	claims := validAccessClaims()
	claims["iss"] = "evil"
	if _, err := c.Verify(signer.sign(t, claims)); err == nil {
		t.Fatal("expected wrong issuer to be rejected")
	}
}

func TestVerify_AudienceCheck(t *testing.T) {
	signer := newTestSigner(t, "k1")
	c, _ := newTestClient(t, signer, Options{Audience: "my-app"})

	// Missing audience fails when one is required.
	if _, err := c.Verify(signer.sign(t, validAccessClaims())); err == nil {
		t.Fatal("expected token without required audience to be rejected")
	}

	// Matching audience (single string) passes.
	claims := validAccessClaims()
	claims["aud"] = "my-app"
	if _, err := c.Verify(signer.sign(t, claims)); err != nil {
		t.Fatalf("expected matching audience to verify, got %v", err)
	}

	// Matching audience (array form) passes.
	claims["aud"] = []string{"other", "my-app"}
	if _, err := c.Verify(signer.sign(t, claims)); err != nil {
		t.Fatalf("expected matching audience array to verify, got %v", err)
	}

	// Wrong audience fails.
	claims["aud"] = []string{"someone-else"}
	if _, err := c.Verify(signer.sign(t, claims)); err == nil {
		t.Fatal("expected non-matching audience to be rejected")
	}
}

func TestVerify_RejectsWrongAlgorithm(t *testing.T) {
	signer := newTestSigner(t, "k1")
	c, _ := newTestClient(t, signer, Options{})

	// Forge an alg=none token (no signature).
	header := map[string]string{"alg": "none", "kid": "k1"}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(validAccessClaims())
	enc := base64.RawURLEncoding.EncodeToString
	tok := enc(hb) + "." + enc(cb) + "."

	if _, err := c.Verify(tok); err == nil {
		t.Fatal("expected alg=none token to be rejected")
	}
}

func TestVerify_RejectsBadSignature(t *testing.T) {
	signer := newTestSigner(t, "k1")
	c, _ := newTestClient(t, signer, Options{})

	// Sign with a DIFFERENT key but publish the original signer's JWKS.
	attacker := newTestSigner(t, "k1")
	tok := attacker.sign(t, validAccessClaims())

	if _, err := c.Verify(tok); err == nil {
		t.Fatal("expected token signed by an unknown key to be rejected")
	}
}

// TestGetKey_UnknownKidRefetchBounded asserts that a flood of tokens with
// unknown kids does not produce one JWKS fetch per token: after the first
// fetch within the cooldown window, subsequent unknown-kid lookups fail fast
// without an additional outbound fetch.
func TestGetKey_UnknownKidRefetchBounded(t *testing.T) {
	signer := newTestSigner(t, "k1")
	c, hits := newTestClient(t, signer, Options{})

	const attempts = 50
	for i := 0; i < attempts; i++ {
		claims := validAccessClaims()
		// Each token carries a fresh attacker-chosen kid that is not in the JWKS.
		tok := signWithKid(t, signer, fmt.Sprintf("evil-%d", i), claims)
		if _, err := c.Verify(tok); err == nil {
			t.Fatalf("expected unknown-kid token %d to be rejected", i)
		}
	}

	if got := atomic.LoadInt64(hits); got > 1 {
		t.Fatalf("expected at most 1 JWKS fetch for %d unknown-kid tokens, got %d", attempts, got)
	}
}

// signWithKid signs claims with the signer's key but stamps an arbitrary kid in
// the header (so the published JWKS will not contain it).
func signWithKid(t *testing.T, s *testSigner, kid string, claims map[string]interface{}) string {
	t.Helper()
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	signingInput := enc(hb) + "." + enc(cb)
	hash := sha256.Sum256([]byte(signingInput))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, hash[:])
	return signingInput + "." + enc(sig)
}
