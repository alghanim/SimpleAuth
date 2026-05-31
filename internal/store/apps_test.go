package store

import (
	"errors"
	"testing"
	"time"
)

// TestAppCRUD covers the v2 apps registry: create (with duplicate rejection),
// get, list, update, and delete.
func TestAppCRUD(t *testing.T) {
	s := openTestStore(t)

	a := &App{
		AppID:             "billing",
		Name:              "Billing",
		Audience:          "billing",
		SecretHash:        "hash",
		RequireAssignment: true,
		CreatedAt:         time.Now().UTC(),
	}
	if err := s.CreateApp(a); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.CreateApp(a); !errors.Is(err, ErrAppExists) {
		t.Fatalf("duplicate create should return ErrAppExists, got %v", err)
	}

	got, err := s.GetApp("billing")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "Billing" || !got.RequireAssignment || got.Audience != "billing" {
		t.Fatalf("unexpected app: %+v", got)
	}

	got.Name = "Billing v2"
	got.AllowLocalUsers = true
	if err := s.UpdateApp(got); err != nil {
		t.Fatalf("update: %v", err)
	}
	got2, _ := s.GetApp("billing")
	if got2.Name != "Billing v2" || !got2.AllowLocalUsers {
		t.Fatalf("update not persisted: %+v", got2)
	}

	apps, err := s.ListApps()
	if err != nil || len(apps) != 1 {
		t.Fatalf("list: %v len=%d", err, len(apps))
	}

	if err := s.DeleteApp("billing"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetApp("billing"); err == nil {
		t.Fatalf("expected not-found after delete")
	}

	// UpdateApp on a missing app should error.
	if err := s.UpdateApp(&App{AppID: "ghost"}); err == nil {
		t.Fatalf("update missing app should error")
	}
}
