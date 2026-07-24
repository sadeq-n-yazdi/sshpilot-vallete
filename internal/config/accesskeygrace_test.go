package config

import (
	"strings"
	"testing"
	"time"
)

// TestAccessKeyGraceWindowDefaultIsPositive pins that the shipped default is a
// real window. It is not merely a taste check: the access key service refuses
// to be constructed with a non-positive window, so a default that drifted to 0
// would stop every deployment that never named one from starting at all.
func TestAccessKeyGraceWindowDefaultIsPositive(t *testing.T) {
	t.Parallel()

	c := Default()
	if got := c.Auth.AccessKeyGraceWindow.Std(); got != 24*time.Hour {
		t.Errorf("default grace window = %v, want 24h", got)
	}
}

// TestAccessKeyGraceWindowRejectsNonPositive is the fail-closed gate, and the
// zero case is the one that matters. Zero must not be readable as "no
// deadline": a rotation performed under that reading would stamp a grace row
// whose window no clock ever closes, leaving the credential the owner rotated
// AWAY from live forever. Refusing at startup is what keeps that reading from
// existing.
func TestAccessKeyGraceWindowRejectsNonPositive(t *testing.T) {
	t.Parallel()

	const field = "auth.access_key_grace_window"

	for _, tc := range []struct {
		name   string
		window Duration
	}{
		{"zero is not no-deadline", 0},
		{"negative", Duration(-time.Second)},
		{"absurdly long", Duration(365 * 24 * time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := validConfig()
			c.Auth.AccessKeyGraceWindow = tc.window

			err := c.Validate()
			if err == nil {
				t.Fatalf("window %v was accepted; must fail closed", tc.window.Std())
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("error must name %s, got: %v", field, err)
			}
		})
	}
}
