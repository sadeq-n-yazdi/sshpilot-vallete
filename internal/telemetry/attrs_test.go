package telemetry

import (
	"net/http"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/logging"
)

// TestSafeAttrsRedactsByPolicyNotBySample asserts the MECHANISM: a span
// attribute survives if and only if the shared logging policy allows its key.
//
// It deliberately does not check that one particular secret-looking string is
// absent. A test written that way passes against an implementation that
// pattern-matches for "token" and fails open on every key nobody thought of --
// which is the exact default-allow bug the allowlist exists to invert. So the
// property under test is the quantifier: for EVERY key not in the policy, the
// value is replaced, whatever the value was.
func TestSafeAttrsRedactsByPolicyNotBySample(t *testing.T) {
	policy := logging.NewPolicy()

	const secret = "ghp_AAAABBBBCCCCDDDDEEEEFFFF"
	// Keys nobody classified. The point is that none of them needs to look
	// suspicious for the value to be withheld.
	notAllowed := []string{
		"authorization", "bearer", "api_key", "pairing_code",
		"harmless_looking", "x", "session", "dsn",
	}

	for _, key := range notAllowed {
		got := SafeAttrs(policy, attribute.String(key, secret))
		if len(got) != 1 {
			t.Fatalf("SafeAttrs(%q) returned %d attributes, want 1", key, len(got))
		}
		if v := got[0].Value.AsString(); v != logging.RedactedMarker {
			t.Errorf("key %q rendered %q, want %q: the policy does not allow this key, so no value may survive",
				key, v, logging.RedactedMarker)
		}
		if string(got[0].Key) != key {
			t.Errorf("key %q was rewritten to %q; the key names the field and must be preserved", key, got[0].Key)
		}
	}
}

// TestSafeAttrsIsTheSamePolicyAsTheLog pins the reuse itself.
//
// If a future change gives spans their own allowlist, the two sinks can drift:
// a key allowed for logs but not for spans (or worse, the reverse) would make
// "we redact the same things everywhere" false while every other test still
// passes. This asserts agreement across the whole default allowlist plus a
// sample of keys outside it, in both directions.
func TestSafeAttrsIsTheSamePolicyAsTheLog(t *testing.T) {
	policy := logging.NewPolicy()
	const value = "some-value"

	for _, key := range append(append([]string{}, defaultAllowlistSample...), "not_a_known_key", "authorization") {
		spanRendered := SafeAttrs(policy, attribute.String(key, value))[0].Value.AsString() != logging.RedactedMarker
		logRendered := policy.Redact(slogString(key, value)).Value.String() != logging.RedactedMarker

		if spanRendered != logRendered {
			t.Errorf("key %q: span renders=%v but log renders=%v; the two sinks must share one policy",
				key, spanRendered, logRendered)
		}
	}
}

// defaultAllowlistSample is a handful of keys the log policy allows, used to
// check the span path agrees. It is a sample rather than the full list because
// the full list lives in internal/logging and is that package's to change; what
// this package must guarantee is agreement, not the list's contents.
var defaultAllowlistSample = []string{"route", "method", "status", "request_id", "handle", "fingerprint"}

// TestSafeAttrsRedactsCompositeValues covers the shapes a scalar check misses.
// A []string under an allowlisted key is a way to smuggle a token past any
// check that only inspects strings.
func TestSafeAttrsRedactsCompositeValues(t *testing.T) {
	policy := logging.NewPolicy()
	got := SafeAttrs(policy, attribute.StringSlice("route", []string{"secret-one", "secret-two"}))
	if v := got[0].Value.AsString(); strings.Contains(v, "secret") {
		t.Errorf("string slice under an allowlisted key rendered %q; composite values must not be expanded", v)
	}
}

// TestSafeAttrsWithNilPolicyRedactsEverything checks the misconstruction path
// fails closed rather than emitting raw values.
func TestSafeAttrsWithNilPolicyRedactsEverything(t *testing.T) {
	got := SafeAttrs(nil, attribute.String("route", "GET /{handle}"))
	if v := got[0].Value.AsString(); v != logging.RedactedMarker {
		t.Errorf("nil policy rendered %q, want %q", v, logging.RedactedMarker)
	}
}

// TestSafeAttrsScrubsURLCredentials proves the content-based half of the policy
// reaches spans too: a DSN under an allowlisted key loses its userinfo.
func TestSafeAttrsScrubsURLCredentials(t *testing.T) {
	got := SafeAttrs(logging.NewPolicy(),
		attribute.String("error", `dial postgres://admin:hunter2@db.internal/vallet: refused`))
	v := got[0].Value.AsString()
	if strings.Contains(v, "hunter2") {
		t.Fatalf("span attribute kept URL credentials: %q", v)
	}
	if !strings.Contains(v, logging.RedactedMarker) {
		t.Fatalf("expected the redaction marker in %q", v)
	}
}

// TestNormalizeMethodBoundsCardinality is the anti-DoS assertion for the method
// label. net/http hands the handler any RFC 9110 token, so a client can send
// unlimited distinct methods to ONE url; without normalization each is a
// permanent time series in every scraper.
func TestNormalizeMethodBoundsCardinality(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		if got := NormalizeMethod(m); got != m {
			t.Errorf("NormalizeMethod(%q) = %q, want it preserved", m, got)
		}
	}

	seen := map[string]bool{}
	for i := range 5000 {
		seen[NormalizeMethod("XMETHOD"+itoa(i))] = true
	}
	if len(seen) != 1 || !seen[MethodOther] {
		t.Fatalf("5000 distinct client-chosen methods produced %d label values (%v); "+
			"the method dimension must not be drivable by a request", len(seen), keys(seen))
	}
}

// TestRouteLabelNeverEchoesAClientPath is the anti-DoS and anti-disclosure
// assertion for the route label: an unmatched request must collapse to one
// constant, no matter what path it carried.
func TestRouteLabelNeverEchoesAClientPath(t *testing.T) {
	seen := map[string]bool{}
	for i := range 5000 {
		// RouteLabel receives the MATCHED PATTERN. An unmatched request has an
		// empty one, which is the case a raw-path fallback would fill in.
		seen[RouteLabel("")] = true
		_ = i
	}
	if len(seen) != 1 || !seen[RouteUnmatched] {
		t.Fatalf("unmatched requests produced %d label values (%v), want exactly [%s]",
			len(seen), keys(seen), RouteUnmatched)
	}

	if got := RouteLabel("GET /{handle}"); got != "GET /{handle}" {
		t.Errorf("RouteLabel dropped a real pattern: got %q", got)
	}
}
