package handler

import "testing"

// TestVerifyPKCE covers the S256 + plain PKCE verification added with the
// authorization-code hardening (M6). The S256 vector is from RFC 7636 App. B.
func TestVerifyPKCE(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	if !verifyPKCE(verifier, challenge, "S256") {
		t.Fatal("valid S256 verifier rejected")
	}
	if verifyPKCE("wrong-verifier", challenge, "S256") {
		t.Fatal("invalid S256 verifier accepted")
	}
	if verifyPKCE("", challenge, "S256") {
		t.Fatal("empty verifier accepted")
	}
	if !verifyPKCE("abc123", "abc123", "plain") {
		t.Fatal("valid plain verifier rejected")
	}
	if verifyPKCE("abc123", "different", "") {
		t.Fatal("mismatched plain verifier accepted")
	}
	if verifyPKCE(verifier, challenge, "unknown-method") {
		t.Fatal("unknown method accepted")
	}
}

// TestEncryptDecryptSecret covers the at-rest secret encryption for the LDAP
// bind password (H4): round-trip, legacy-plaintext passthrough, wrong-key
// failure, and empty handling.
func TestEncryptDecryptSecret(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	const plain = "s3cr3t-bind-pw"

	enc, err := encryptSecret(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	if enc == plain {
		t.Fatal("value was not encrypted")
	}
	dec, err := decryptSecret(key, enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec != plain {
		t.Fatalf("round-trip mismatch: %q", dec)
	}

	// Legacy plaintext (no prefix) passes through unchanged.
	if got, _ := decryptSecret(key, "legacy-plain"); got != "legacy-plain" {
		t.Fatalf("legacy passthrough failed: %q", got)
	}

	// Wrong key cannot decrypt.
	badKey := make([]byte, 32)
	if _, err := decryptSecret(badKey, enc); err == nil {
		t.Fatal("decrypt with wrong key should fail")
	}

	// Empty stays empty.
	if got, _ := encryptSecret(key, ""); got != "" {
		t.Fatalf("empty should encrypt to empty, got %q", got)
	}
}
