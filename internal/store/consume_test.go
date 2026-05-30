package store

import (
	"errors"
	"testing"
	"time"
)

// TestConsumeRefreshToken verifies the atomic single-use semantics that close
// the rotation TOCTOU (H2): a token consumes exactly once; a second attempt is
// reported as reuse (and still carries the family for revocation); an unknown
// token reports not-found.
func TestConsumeRefreshToken(t *testing.T) {
	s := openTestStore(t)
	rt := &RefreshToken{
		TokenID:   "tok-1",
		FamilyID:  "fam-1",
		UserGUID:  "user-1",
		ExpiresAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
	}
	if err := s.SaveRefreshToken(rt); err != nil {
		t.Fatal(err)
	}

	got, err := s.ConsumeRefreshToken("tok-1")
	if err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if got.FamilyID != "fam-1" {
		t.Fatalf("family mismatch: %q", got.FamilyID)
	}

	got2, err := s.ConsumeRefreshToken("tok-1")
	if !errors.Is(err, ErrRefreshTokenReused) {
		t.Fatalf("expected ErrRefreshTokenReused, got %v", err)
	}
	if got2 == nil || got2.FamilyID != "fam-1" {
		t.Fatalf("reuse should still return the token with family, got %+v", got2)
	}

	if _, err := s.ConsumeRefreshToken("missing"); !errors.Is(err, ErrRefreshTokenNotFound) {
		t.Fatalf("expected ErrRefreshTokenNotFound, got %v", err)
	}
}
