package config

import (
	"strings"
	"testing"
	"time"
)

// TestAccessKeyGraceSweepIsOffByDefault pins the shipped default. The sweep
// requires a pepper, and requiring one of every non-production deployment to
// obtain a bookkeeping improvement -- the deadline itself is enforced at request
// time by accesskey.Verify, not here -- is the wrong trade. A change that turned
// this on by default would make the pepper mandatory even in development.
//
// (In production the pepper is required regardless of the sweep, for the bearer
// verifier; that is asserted in the validate tests, not here.)
func TestAccessKeyGraceSweepIsOffByDefault(t *testing.T) {
	t.Parallel()

	c := Default()
	if c.Retention.AccessKeyGraceSweepInterval.Std() != 0 {
		t.Errorf("default interval = %v, want 0 (disabled)", c.Retention.AccessKeyGraceSweepInterval.Std())
	}
	if c.Retention.AccessKeyGraceSweepBatch < 1 {
		t.Errorf("default batch = %d, want a usable positive bound even while disabled",
			c.Retention.AccessKeyGraceSweepBatch)
	}
	if !c.Auth.AccessKeyPepperRef.IsZero() {
		t.Errorf("default pepper ref = %q, want empty", c.Auth.AccessKeyPepperRef)
	}

	// With the sweep off, a development deployment is not forced to name a
	// pepper: the sweep adds no requirement of its own.
	c.Server.Environment = "development"
	if err := c.Validate(); err != nil && strings.Contains(err.Error(), "access_key") {
		t.Errorf("sweep-off development defaults must not require a pepper: %v", err)
	}
}

// TestAccessKeyGraceSweepRequiresAPepper is the fail-closed gate. An operator
// who enables the sweep and names no pepper must be told so by a config error
// naming the field, not discover it as a service that could not be constructed.
func TestAccessKeyGraceSweepRequiresAPepper(t *testing.T) {
	t.Parallel()

	// A development config, where the pepper is otherwise optional, so the only
	// thing that can require it here is the sweep. In production the pepper is
	// required anyway and would mask the sweep as the cause.
	c := validConfig()
	c.Server.Environment = "development"
	c.Auth.AccessKeyPepperRef = ""
	c.Retention.AccessKeyGraceSweepInterval = Duration(time.Hour)

	err := c.Validate()
	if err == nil {
		t.Fatal("enabling the sweep with no pepper was accepted; it must fail closed")
	}
	if !strings.Contains(err.Error(), "auth.access_key_pepper_ref") {
		t.Errorf("error must name the missing field, got: %v", err)
	}

	c.Auth.AccessKeyPepperRef = "env:VALLET_ACCESS_KEY_PEPPER"
	if err := c.Validate(); err != nil {
		t.Fatalf("sweep enabled with a pepper named should validate, got: %v", err)
	}
}

// TestAccessKeyGraceSweepRejectsBadBounds pins that a misconfigured cadence or
// batch fails startup rather than being clamped. The batch matters more here
// than on the handle sweep: the access key repository REJECTS a non-positive
// limit instead of coercing it, so a 0 that got through would fail every pass.
func TestAccessKeyGraceSweepRejectsBadBounds(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		apply func(*Config)
		field string
	}{
		{"negative interval", func(c *Config) {
			c.Retention.AccessKeyGraceSweepInterval = Duration(-time.Second)
		}, "retention.access_key_grace_sweep_interval"},
		{"zero batch", func(c *Config) {
			c.Retention.AccessKeyGraceSweepBatch = 0
		}, "retention.access_key_grace_sweep_batch"},
		{"negative batch", func(c *Config) {
			c.Retention.AccessKeyGraceSweepBatch = -1
		}, "retention.access_key_grace_sweep_batch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := validConfig()
			tc.apply(&c)

			err := c.Validate()
			if err == nil {
				t.Fatalf("%s was accepted; must fail closed", tc.name)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error must name %s, got: %v", tc.field, err)
			}
		})
	}
}

// TestAccessKeyPepperRequirementGating pins the gating in RequiredSecretRefs.
// Startup must resolve exactly the secrets this configuration needs: the pepper
// is resolved when it is referenced or the environment is production (the bearer
// verifier needs it), and never demanded from a development deployment that
// named none and left the sweep off -- doing so would break every such install.
// The grace sweep adds no separate gate: Validate requires the reference
// whenever the sweep is on, so a sweep-enabled config always carries a non-zero
// ref and is caught by the referenced clause.
func TestAccessKeyPepperRequirementGating(t *testing.T) {
	t.Parallel()

	const field = "auth.access_key_pepper_ref"

	// Development, no reference, sweep off: not required.
	c := validConfig()
	c.Server.Environment = "development"
	c.Auth.AccessKeyPepperRef = ""
	if refFields(c.RequiredSecretRefs())[field] {
		t.Error("the pepper is required with no reference and the sweep off; it must not be")
	}

	// The sweep, once on, forces the reference (Validate), so the pepper is
	// resolved: an unresolvable reference would then let the process serve with
	// the sweep silently unbuilt.
	c.Retention.AccessKeyGraceSweepInterval = Duration(time.Hour)
	c.Auth.AccessKeyPepperRef = "env:VALLET_ACCESS_KEY_PEPPER"
	if !refFields(c.RequiredSecretRefs())[field] {
		t.Error("the pepper is not required with the sweep enabled and a reference set")
	}
}

// refFields indexes a requirement list by field name.
func refFields(reqs []RefRequirement) map[string]bool {
	out := make(map[string]bool, len(reqs))
	for _, r := range reqs {
		out[r.Field] = true
	}
	return out
}
