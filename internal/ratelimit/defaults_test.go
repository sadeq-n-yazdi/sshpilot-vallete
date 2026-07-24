package ratelimit_test

import (
	"errors"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/ratelimit"
)

func TestDefaultTiersMatchTheADR(t *testing.T) {
	t.Parallel()

	tiers := ratelimit.DefaultTiers()
	if err := tiers.Validate(); err != nil {
		t.Fatalf("DefaultTiers().Validate(): %v", err)
	}

	// ADR-0023's starting defaults, asserted so a drift is a test failure
	// rather than a silent policy change.
	if tiers.Auth.Limit != 5 || tiers.Auth.Window != time.Minute {
		t.Errorf("auth tier = %+v, want ~5/min", tiers.Auth)
	}
	if tiers.Publish.Limit != 60 || tiers.Publish.Window != time.Minute {
		t.Errorf("publish tier = %+v, want ~60/min", tiers.Publish)
	}
	if tiers.Management.Limit != 120 || tiers.Management.Window != time.Minute {
		t.Errorf("management tier = %+v, want ~120/min", tiers.Management)
	}
	if tiers.Admin.Limit != 60 || tiers.Admin.Window != time.Minute {
		t.Errorf("admin tier = %+v, want ~60/min", tiers.Admin)
	}

	// The per-tier outage policy is part of the contract, not an incidental
	// field value; see DefaultTiers for the reasoning.
	if !tiers.Publish.FailOpen {
		t.Error("publish tier must fail OPEN: it is the public read path")
	}
	if tiers.Management.FailOpen || tiers.Admin.FailOpen {
		t.Error("management and admin tiers must fail CLOSED")
	}
}

func TestTiersValidateRejectsEachBadTier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mut  func(*ratelimit.Tiers)
	}{
		{"auth", func(x *ratelimit.Tiers) { x.Auth.Limit = 0 }},
		{"publish", func(x *ratelimit.Tiers) { x.Publish.Window = 0 }},
		{"management", func(x *ratelimit.Tiers) { x.Management.Limit = -1 }},
		{"admin", func(x *ratelimit.Tiers) { x.Admin.Window = -time.Second }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tiers := ratelimit.DefaultTiers()
			tc.mut(&tiers)
			if err := tiers.Validate(); !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("Validate() = %v, want domain.ErrInvalidInput", err)
			}
		})
	}
}
