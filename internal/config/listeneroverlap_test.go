package config

import (
	"strings"
	"testing"
)

// TestValidateListenerOverlapRefused proves the cross-listener overlap check
// (issue #113) fails closed: whenever two of the process's own active listeners
// would bind the same socket, Validate refuses and the error names BOTH
// colliding listeners. These are caught by Validate, which run() calls before
// any listener binds, so the collision never reaches net.Listen.
//
// The wildcard is always placed on the side that permits it: server.listen_addr
// has no private-bind fence, whereas the health and upstream binds are fenced to
// loopback/private (validatePrivateBindAddr) and would reject a wildcard with a
// different, confounding error.
func TestValidateListenerOverlapRefused(t *testing.T) {
	tests := []struct {
		name   string
		mut    func(c *Config)
		fieldA string
		fieldB string
	}{
		{
			name: "identical addr server and health",
			mut: func(c *Config) {
				c.Server.ListenAddr = "127.0.0.1:8443"
				c.Server.HealthListenAddr = "127.0.0.1:8443"
			},
			fieldA: "server.listen_addr",
			fieldB: "server.health_listen_addr",
		},
		{
			name: "wildcard server shadows specific health same port",
			mut: func(c *Config) {
				c.Server.ListenAddr = "0.0.0.0:8443"
				c.Server.HealthListenAddr = "127.0.0.1:8443"
			},
			fieldA: "server.listen_addr",
			fieldB: "server.health_listen_addr",
		},
		{
			name: "ipv4 wildcard server shadows ipv6 specific health same port",
			mut: func(c *Config) {
				c.Server.ListenAddr = "0.0.0.0:8443"
				c.Server.HealthListenAddr = "[::1]:8443"
			},
			fieldA: "server.listen_addr",
			fieldB: "server.health_listen_addr",
		},
		{
			name: "upstream listener overlaps health in upstream mode",
			mut: func(c *Config) {
				*c = upstreamConfig()
				c.TLS.Upstream.ListenAddr = "127.0.0.1:8080"
				c.Server.HealthListenAddr = "127.0.0.1:8080"
			},
			fieldA: "tls.upstream.listen_addr",
			fieldB: "server.health_listen_addr",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mut(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected refusal for overlapping listeners in %q", tc.name)
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.fieldA) {
				t.Errorf("error %q does not name %s", msg, tc.fieldA)
			}
			if !strings.Contains(msg, tc.fieldB) {
				t.Errorf("error %q does not name %s", msg, tc.fieldB)
			}
		})
	}
}

// TestValidateListenerOverlapMessageNamesAddresses proves the refusal names the
// offending addresses, not merely the fields, so an operator can see which two
// binds collide and why (a wildcard shadowing a specific bind on the same port).
func TestValidateListenerOverlapMessageNamesAddresses(t *testing.T) {
	c := validConfig()
	c.Server.ListenAddr = "0.0.0.0:8443"
	c.Server.HealthListenAddr = "127.0.0.1:8443"
	err := c.Validate()
	if err == nil {
		t.Fatal("expected refusal for wildcard shadowing a specific bind")
	}
	msg := err.Error()
	for _, want := range []string{"0.0.0.0:8443", "127.0.0.1:8443"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not name the offending address %q", msg, want)
		}
	}
}

// TestValidateListenerOverlapAllowed proves the check is not vacuously refusing:
// distinct binds are accepted, and — the crux of the mode-aware active set — the
// HTTPS server.listen_addr does NOT participate in upstream mode, where it is
// never bound (the composition root builds the plaintext upstream listener
// instead). Two distinct specific hosts on the same port are allowed because
// neither shadows the other.
func TestValidateListenerOverlapAllowed(t *testing.T) {
	tests := []struct {
		name string
		mut  func(c *Config)
	}{
		{
			name: "health unset leaves only the app listener",
			mut:  func(c *Config) {},
		},
		{
			name: "distinct ports never overlap",
			mut: func(c *Config) {
				c.Server.ListenAddr = ":8443"
				c.Server.HealthListenAddr = "127.0.0.1:9000"
			},
		},
		{
			name: "two distinct specific hosts same port do not shadow",
			mut: func(c *Config) {
				c.Server.ListenAddr = "127.0.0.1:8443"
				c.Server.HealthListenAddr = "10.0.0.5:8443"
			},
		},
		{
			name: "upstream mode ignores the unbound server.listen_addr on the same port",
			mut: func(c *Config) {
				*c = upstreamConfig()
				// server.listen_addr keeps its :8443 default; the upstream bind is
				// placed on the same port. In upstream mode the HTTPS server is never
				// built, so this must NOT be reported as an overlap.
				c.Server.ListenAddr = ":8443"
				c.TLS.Upstream.ListenAddr = "127.0.0.1:8443"
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mut(&c)
			if err := c.Validate(); err != nil {
				t.Fatalf("%s should be accepted, got: %v", tc.name, err)
			}
		})
	}
}
