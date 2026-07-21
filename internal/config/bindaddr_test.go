package config

import (
	"strings"
	"testing"
)

// healthConfig returns a Config that passes Validate with a given health listen
// address set, so each case exercises only the health-bind fence.
func healthConfig(addr string) Config {
	c := validConfig()
	c.Server.HealthListenAddr = addr
	return c
}

// TestValidateHealthListenAddrRejectsPublicBinds is the core fence for the
// plaintext health-probe listener (ADR-0015, Decision 43): an unauthenticated
// endpoint must never bind anywhere reachable from the internet. Every case here
// is refused fail-closed, and the wildcard/public-address cases are the ones an
// operator reaches by accident.
func TestValidateHealthListenAddrRejectsPublicBinds(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{"ipv4 wildcard", "0.0.0.0:8080"},
		{"ipv6 wildcard", "[::]:8080"},
		{"bare port wildcard", ":8080"},
		{"public ipv4", "203.0.113.5:8080"},
		{"public ipv6", "[2001:db8::1]:8080"},
		{"another public ipv4", "8.8.8.8:8080"},
		{"hostname not localhost", "health.internal:8080"},
		{"not host:port", "127.0.0.1"},
		{"empty host garbage", "not-an-address"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := healthConfig(tc.addr)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected refusal for health_listen_addr=%q", tc.addr)
			}
			if !strings.Contains(err.Error(), "server.health_listen_addr") {
				t.Errorf("error %q does not name server.health_listen_addr", err)
			}
		})
	}
}

// TestValidateHealthListenAddrAcceptsPrivateBinds proves the fence is not
// vacuously refusing everything: loopback and RFC1918/ULA binds -- the addresses
// an orchestrator actually probes on -- are accepted, and an empty value leaves
// the listener unstarted, which is the default.
func TestValidateHealthListenAddrAcceptsPrivateBinds(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{"unset", ""},
		{"ipv4 loopback", "127.0.0.1:8080"},
		{"ipv4 loopback range", "127.9.9.9:8080"},
		{"ipv6 loopback", "[::1]:8080"},
		{"localhost literal", "localhost:8080"},
		{"rfc1918 ten", "10.1.2.3:8080"},
		{"rfc1918 192", "192.168.1.10:8080"},
		{"rfc1918 172", "172.16.0.1:8080"},
		{"ula", "[fd00::1]:8080"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := healthConfig(tc.addr)
			if err := c.Validate(); err != nil {
				t.Fatalf("health_listen_addr=%q should be accepted, got: %v", tc.addr, err)
			}
		})
	}
}
