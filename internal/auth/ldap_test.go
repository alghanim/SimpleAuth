package auth

import (
	"strconv"
	"testing"
	"time"
)

// toFileTime converts t to an AD FILETIME string (100ns ticks since 1601).
func toFileTime(t time.Time) string {
	return strconv.FormatInt((t.Unix()+11644473600)*1e7, 10)
}

func TestADAccountDisabled(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		uac, exp string
		want     bool
	}{
		{"non-AD directory (no attrs)", "", "", false},
		{"normal account", "512", "0", false},
		{"disabled account", "514", "0", true},
		{"disabled + dont-expire-password", "66050", "9223372036854775807", true},
		{"never expires (max)", "512", "9223372036854775807", false},
		{"expired yesterday", "512", toFileTime(now.Add(-24 * time.Hour)), true},
		{"expires tomorrow", "512", toFileTime(now.Add(24 * time.Hour)), false},
		{"garbage values ignored", "abc", "xyz", false},
	}
	for _, c := range cases {
		if got := adAccountDisabled(c.uac, c.exp, now); got != c.want {
			t.Errorf("%s: adAccountDisabled(%q, %q) = %v, want %v", c.name, c.uac, c.exp, got, c.want)
		}
	}
}
