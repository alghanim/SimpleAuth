package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestStableKIDAcrossReload verifies the JWKS key ID is derived from the key and
// is therefore stable across process restarts (M2) — previously it was random
// per boot, breaking kid-matching clients.
func TestStableKIDAcrossReload(t *testing.T) {
	dir := t.TempDir()
	m1, err := NewJWTManager(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	m2, err := NewJWTManager(dir, "test") // reloads the same key from disk
	if err != nil {
		t.Fatal(err)
	}
	if m1.Kid() == "" {
		t.Fatal("empty kid")
	}
	if m1.Kid() != m2.Kid() {
		t.Fatalf("kid changed across reload: %q vs %q", m1.Kid(), m2.Kid())
	}
}

// TestValidateTokenRejectsAlgConfusion ensures a non-RSA (HS256) token is
// rejected, preventing algorithm-confusion attacks.
func TestValidateTokenRejectsAlgConfusion(t *testing.T) {
	m, err := NewJWTManager(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	claims := Claims{}
	claims.Subject = "attacker"
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte("any-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ValidateToken(signed); err == nil {
		t.Fatal("expected HS256 token to be rejected (alg confusion)")
	}
}

// TestIssueRefreshTokenReturnsFamilyID covers the signature change that removed
// the re-parse nil-deref (M4): the family ID is returned directly and preserved
// when supplied.
func TestIssueRefreshTokenReturnsFamilyID(t *testing.T) {
	m, err := NewJWTManager(t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	_, id, fam, err := m.IssueRefreshToken("user1", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if id == "" || fam == "" {
		t.Fatalf("empty id/family: %q %q", id, fam)
	}
	if _, _, fam2, _ := m.IssueRefreshToken("user1", fam, time.Hour); fam2 != fam {
		t.Fatalf("family not preserved: %q vs %q", fam2, fam)
	}
}
