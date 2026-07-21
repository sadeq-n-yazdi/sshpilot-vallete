package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// secretShapedValues are values a caller might plausibly pass that carry, or
// look like, a credential or key material. Every one must be refused.
var secretShapedValues = map[string]string{
	"pem private key":      "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n",
	"pem rsa private key":  "-----BEGIN RSA PRIVATE KEY-----",
	"pem certificate":      "-----BEGIN CERTIFICATE-----",
	"private key phrase":   "the user's private key was rotated",
	"bearer token":         "Bearer eyJhbGciOiJIUzI1NiJ9abcdef",
	"authorization header": "Authorization: Basic dXNlcjpwYXNz",
	"proxy authorization":  "Proxy-Authorization: Basic dXNlcjpwYXNz",
	"basic credentials":    "Basic dXNlcjpwYXNzd29yZA==",
	"aws secret key":       "aws_secret_access_key=wJalrXUtnFEMI",
	"openssh container":    "begin openssh private key",
	"putty key":            "PuTTY-User-Key-File-3: ssh-ed25519",
	"api key header":       "x-api-key: 8f14e45fceea167a",
	"set-cookie header":    "Set-Cookie: session=abc123",
	"jwt":                  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27u",
}

// TestDetailsRejectsSecretShapedValues is the primary "never store a secret"
// test: a credential placed in a legitimately-named field must be refused.
func TestDetailsRejectsSecretShapedValues(t *testing.T) {
	t.Parallel()

	for name, value := range secretShapedValues {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := Details{}.Set(DetailReason, value)
			if !errors.Is(d.Err(), domain.ErrInvalidInput) {
				t.Fatalf("Set(reason, %s) err = %v, want ErrInvalidInput", name, d.Err())
			}
			// Rejected, not merely flagged: the value must not be retained.
			if len(d.pairs) != 0 {
				t.Errorf("a rejected secret-shaped value was still stored: %v", d.pairs)
			}
		})
	}
}

// TestEmitRejectsSecretShapedValues drives the same values all the way through
// Emit, confirming nothing reaches the sink.
func TestEmitRejectsSecretShapedValues(t *testing.T) {
	t.Parallel()

	for name, value := range secretShapedValues {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e, sink := newTestEmitter(t)
			ev := validEvent()
			ev.Details = Details{}.Set(DetailReason, value)
			if err := e.Emit(context.Background(), ev); !errors.Is(err, domain.ErrInvalidInput) {
				t.Fatalf("Emit = %v, want ErrInvalidInput", err)
			}
			if len(sink.records) != 0 {
				t.Errorf("a record carrying a secret-shaped value reached the sink: %+v", sink.records)
			}
		})
	}
}

// TestEmitRejectsSecretShapedIdentifiers screens the actor and target ID fields
// too: an ID field is a plausible place to pass "whatever identified the
// caller", which may be a token.
func TestEmitRejectsSecretShapedIdentifiers(t *testing.T) {
	t.Parallel()

	token := "Bearer eyJhbGciOiJIUzI1NiJ9abcdef"
	for _, tc := range []struct {
		name string
		set  func(*Event)
	}{
		{"actor id", func(e *Event) { e.ActorID = token }},
		{"target id", func(e *Event) { e.TargetID = token }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e, sink := newTestEmitter(t)
			ev := validEvent()
			tc.set(&ev)
			if err := e.Emit(context.Background(), ev); !errors.Is(err, domain.ErrInvalidInput) {
				t.Errorf("Emit = %v, want ErrInvalidInput", err)
			}
			if len(sink.records) != 0 {
				t.Errorf("a record with a token in %s reached the sink", tc.name)
			}
		})
	}
}

// TestDetailsRejectsRedactedSecret covers the realistic accidental path: a
// caller formats a value that turns out to be a resolved secret. The secrets
// package renders it as its marker rather than the secret, and this package
// refuses to record the near miss.
func TestDetailsRejectsRedactedSecret(t *testing.T) {
	t.Parallel()

	r := secrets.NewRedacted("hunter2")
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"formatted with %v", fmt.Sprintf("%v", r)},
		{"formatted with %s", fmt.Sprintf("%s", r)},
		{"stringer", r.String()},
		{"embedded in a sentence", "rotated because " + r.String() + " expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := Details{}.Set(DetailReason, tc.value)
			if !errors.Is(d.Err(), domain.ErrInvalidInput) {
				t.Errorf("Set(reason, %q) err = %v, want ErrInvalidInput", tc.value, d.Err())
			}
		})
	}
}

// TestRedactionMarkerMatchesSecretsPackage pins this package's copy of the
// marker to what the secrets package actually renders. The marker is duplicated
// because it is unexported there; if it ever changes, this fails rather than the
// check silently going dead.
func TestRedactionMarkerMatchesSecretsPackage(t *testing.T) {
	t.Parallel()
	if got := secrets.NewRedacted("anything").String(); got != redactionMarker {
		t.Errorf("secrets renders %q, but this package screens for %q", got, redactionMarker)
	}
}

// TestDetailsRejectsNonAllowlistedKeys is the allowlist test: the keys a secret
// would naturally be filed under simply do not exist.
func TestDetailsRejectsNonAllowlistedKeys(t *testing.T) {
	t.Parallel()

	for _, key := range []string{
		"token", "password", "passwd", "secret", "credential", "private_key",
		"passphrase", "api_key", "session", "cookie", "authorization", "salt",
		"", "Fingerprint", "fingerprint ",
	} {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			d := Details{}.Set(DetailKey(key), "whatever")
			if !errors.Is(d.Err(), domain.ErrInvalidInput) {
				t.Errorf("Set(%q) err = %v, want ErrInvalidInput", key, d.Err())
			}
			if len(d.pairs) != 0 {
				t.Errorf("a value under a non-allowlisted key was stored: %v", d.pairs)
			}
		})
	}
}

// TestAllowlistedKeysAreNotSecretNamed guards the allowlist itself: if someone
// adds a key whose name suggests it carries a credential, this fails.
func TestAllowlistedKeysAreNotSecretNamed(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		"token", "password", "passwd", "secret", "credential", "private",
		"passphrase", "apikey", "api_key", "session", "cookie", "auth",
		"salt", "nonce", "seed", "signature", "cert", "blob", "material",
	}
	for key := range allowedDetailKeys {
		lower := strings.ToLower(string(key))
		for _, bad := range forbidden {
			if strings.Contains(lower, bad) {
				t.Errorf("allowlisted detail key %q contains %q: a key by that name "+
					"is liable to carry a secret and must not be allowlisted", key, bad)
			}
		}
	}
}

func TestDetailsAcceptsEveryAllowlistedKey(t *testing.T) {
	t.Parallel()

	values := map[DetailKey]string{
		DetailFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	for key := range allowedDetailKeys {
		value, ok := values[key]
		if !ok {
			value = "value"
		}
		d := Details{}.Set(key, value)
		if d.Err() != nil {
			t.Errorf("Set(%q) err = %v, want nil", key, d.Err())
		}
	}
}

// TestDetailErasureClassification pins the ADR-0024 per-key erasure policy: each
// of the fourteen allowlisted keys is either identifying (rewritten to a
// tombstone during owner erasure) or structural (kept byte-for-byte). The
// expectation is spelled out key by key rather than derived from the same map
// the implementation uses, so a future edit that moves a key across the line —
// the exact silent drift ADR-0024 warns about — fails here.
func TestDetailErasureClassification(t *testing.T) {
	t.Parallel()

	// true = identifying/erasable, false = structural/kept.
	want := map[DetailKey]bool{
		DetailFingerprint: true,
		DetailHandle:      true,
		DetailDeviceName:  true,
		DetailKeySetName:  true,
		DetailClientLabel: true,
		DetailFrom:        true,
		DetailTo:          true,

		DetailAlgorithm:  false,
		DetailVisibility: false,
		DetailScope:      false,
		DetailReason:     false,
		DetailResult:     false,
		DetailRequestID:  false,
		DetailCount:      false,
	}

	// Every allowlisted key must appear in the expectation: a new key added to
	// the allowlist without a deliberate classification decision fails here
	// rather than defaulting silently.
	for key := range allowedDetailKeys {
		if _, ok := want[key]; !ok {
			t.Errorf("allowlisted key %q has no erasure classification", key)
		}
	}
	for key, erasable := range want {
		if !allowedDetailKeys[key] {
			t.Errorf("classified key %q is not on the allowlist", key)
		}
		if got := IsErasableDetail(key); got != erasable {
			t.Errorf("IsErasableDetail(%q) = %v, want %v", key, got, erasable)
		}
	}

	// Fail-closed default: an unrecognized key is treated as identifying, so a
	// value under an unclassified name is erased rather than left in the clear.
	if !IsErasableDetail(DetailKey("unrecognized")) {
		t.Error("an unrecognized detail key must default to erasable (fail closed)")
	}
}

// TestFingerprintDetailMustBeAFingerprint stops the field that names a key from
// becoming a field that carries one.
func TestFingerprintDetailMustBeAFingerprint(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		value string
		ok    bool
	}{
		{"valid", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", true},
		{"missing prefix", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", false},
		{"truncated", "SHA256:AAAA", false},
		{"a public key blob", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB", false},
		{"arbitrary text", "the key with the red sticker", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := Details{}.Set(DetailFingerprint, tc.value)
			if tc.ok && d.Err() != nil {
				t.Errorf("Set(fingerprint, %q) err = %v, want nil", tc.value, d.Err())
			}
			if !tc.ok && !errors.Is(d.Err(), domain.ErrInvalidInput) {
				t.Errorf("Set(fingerprint, %q) err = %v, want ErrInvalidInput", tc.value, d.Err())
			}
		})
	}
}

func TestDetailsRejectsUnboundedValues(t *testing.T) {
	t.Parallel()

	d := Details{}.Set(DetailReason, strings.Repeat("a", maxDetailValueLen+1))
	if !errors.Is(d.Err(), domain.ErrInvalidInput) {
		t.Errorf("overlong value err = %v, want ErrInvalidInput", d.Err())
	}

	ok := Details{}.Set(DetailReason, strings.Repeat("a", maxDetailValueLen))
	if ok.Err() != nil {
		t.Errorf("value at the exact bound err = %v, want nil", ok.Err())
	}
}

func TestDetailsRejectsEmptyValue(t *testing.T) {
	t.Parallel()
	if d := (Details{}).Set(DetailReason, ""); !errors.Is(d.Err(), domain.ErrInvalidInput) {
		t.Errorf("empty value err = %v, want ErrInvalidInput", d.Err())
	}
}

// TestDetailsRejectsNonPrintableValues covers the log-injection path: a newline
// or an escape sequence in an audit value lets a writer forge extra lines in any
// text rendering of the log.
func TestDetailsRejectsNonPrintableValues(t *testing.T) {
	t.Parallel()

	for name, value := range map[string]string{
		"newline":       "revoked\nowner-b key.added key-9",
		"carriage ret":  "revoked\rowner-b",
		"tab":           "a\tb",
		"nul":           "abc\x00def",
		"ansi escape":   "\x1b[31mdanger\x1b[0m",
		"invalid utf8":  string([]byte{0xff, 0xfe}),
		"bidi override": "revoked\u202eowner-b",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := Details{}.Set(DetailReason, value)
			if !errors.Is(d.Err(), domain.ErrInvalidInput) {
				t.Errorf("Set(reason, %s) err = %v, want ErrInvalidInput", name, d.Err())
			}
		})
	}
}

// TestAllowlistBoundsRecordSize confirms the allowlist is what bounds how much
// context a record can carry: keys are unique, so setting every allowlisted key
// and then re-setting one cannot grow the record beyond the allowlist size.
func TestAllowlistBoundsRecordSize(t *testing.T) {
	t.Parallel()

	d := Details{}
	for key := range allowedDetailKeys {
		value := "value"
		if key == DetailFingerprint {
			value = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		}
		d = d.Set(key, value)
	}
	if d.Err() != nil {
		t.Fatalf("setting every allowlisted key err = %v, want nil", d.Err())
	}
	if len(d.pairs) != len(allowedDetailKeys) {
		t.Fatalf("details hold %d pairs, want %d", len(d.pairs), len(allowedDetailKeys))
	}

	again := d.Set(DetailReason, "another")
	if again.Err() != nil {
		t.Fatalf("overwriting an existing key err = %v, want nil", again.Err())
	}
	if len(again.pairs) != len(allowedDetailKeys) {
		t.Errorf("re-setting a key grew the record to %d pairs, want %d",
			len(again.pairs), len(allowedDetailKeys))
	}
}

// TestAllowlistStaysSmall keeps the allowlist from quietly growing into a
// general-purpose metadata bag, which is how a secret would eventually find a
// home in it.
func TestAllowlistStaysSmall(t *testing.T) {
	t.Parallel()
	if n := len(allowedDetailKeys); n > maxAllowedDetailKeys {
		t.Errorf("the detail allowlist has %d keys, above the ceiling of %d: "+
			"an unbounded allowlist defeats the point of having one", n, maxAllowedDetailKeys)
	}
}

// TestDetailsSetIsCopyOnWrite confirms branching one base Details into two
// events does not merge their context. An audit record that gains context from
// an unrelated event is a false record.
func TestDetailsSetIsCopyOnWrite(t *testing.T) {
	t.Parallel()

	base := Details{}.Set(DetailReason, "shared")
	left := base.Set(DetailHandle, "alice")
	right := base.Set(DetailHandle, "bob")

	if _, ok := base.pairs["handle"]; ok {
		t.Error("Set mutated the base Details in place")
	}
	if left.pairs["handle"] != "alice" || right.pairs["handle"] != "bob" {
		t.Errorf("branches interfered: left=%v right=%v", left.pairs, right.pairs)
	}
	if len(left.pairs) != 2 || len(right.pairs) != 2 {
		t.Errorf("branch sizes = %d/%d, want 2/2", len(left.pairs), len(right.pairs))
	}
}

// TestDetailsRetainsFirstError confirms a chained build surfaces the first
// failure and stops recording, so a later valid Set cannot mask an earlier
// rejection.
func TestDetailsRetainsFirstError(t *testing.T) {
	t.Parallel()

	d := Details{}.
		Set(DetailReason, "fine").
		Set(DetailKey("token"), "s3cret").
		Set(DetailHandle, "alice")

	if !errors.Is(d.Err(), domain.ErrInvalidInput) {
		t.Fatalf("err = %v, want the retained ErrInvalidInput", d.Err())
	}
	if len(d.pairs) != 0 {
		t.Errorf("details retained after a rejection: %v", d.pairs)
	}
}

func TestEmptyDetailsYieldNilMetadata(t *testing.T) {
	t.Parallel()

	e, sink := newTestEmitter(t)
	if err := e.Emit(context.Background(), validEvent()); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if sink.records[0].Metadata != nil {
		t.Errorf("Metadata = %#v, want nil for an event with no details", sink.records[0].Metadata)
	}
}

// TestErrorsDoNotEchoRejectedValues is a leak check on the error path itself:
// an error string is very likely to be logged, so a rejected secret must not
// travel into it.
func TestErrorsDoNotEchoRejectedValues(t *testing.T) {
	t.Parallel()

	secret := "Bearer eyJhbGciOiJIUzI1NiJ9SUPERSECRETVALUE"
	d := Details{}.Set(DetailReason, secret)
	if d.Err() == nil {
		t.Fatal("expected a rejection")
	}
	if strings.Contains(d.Err().Error(), "SUPERSECRETVALUE") {
		t.Errorf("the rejection error echoes the rejected value: %v", d.Err())
	}

	keyErr := Details{}.Set(DetailKey("my_password_field"), "x").Err()
	if keyErr == nil {
		t.Fatal("expected a rejection")
	}
	if strings.Contains(keyErr.Error(), "my_password_field") {
		t.Errorf("the rejection error echoes the rejected key: %v", keyErr)
	}
}

// TestScreenValueAllowsOrdinaryText guards against the screens being so eager
// that legitimate audit context is refused, which would push callers to stop
// recording context at all.
func TestScreenValueAllowsOrdinaryText(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"laptop", "alice", "work-keys", "public", "protected", "allowed", "denied",
		"ssh-ed25519", "revoked by owner request", "café ☕", "v1.2.3",
		"host.example.com", "keys:read", "2026-07-19",
		"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	} {
		if err := screenValue("detail value", value); err != nil {
			t.Errorf("screenValue(%q) = %v, want nil", value, err)
		}
	}
}

func TestLooksLikeJWT(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", true},
		{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0", false}, // only two parts
		{"v1.2.3", false},                                // ordinary dotted value
		{"host.example.com", false},                      // hostname
		{"eyJhbGciOiJIUzI1NiJ9..sig", false},             // empty middle segment
		{"notbase64.eyJzdWIiOiIxIn0.sig", false},         // no JSON header prefix
		{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.", false}, // empty signature
	} {
		if got := looksLikeJWT(tc.value); got != tc.want {
			t.Errorf("looksLikeJWT(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestScreenValueAllowsEmpty(t *testing.T) {
	t.Parallel()
	// A system actor's empty ActorID reaches screenValue; it must pass.
	if err := screenValue("actor id", ""); err != nil {
		t.Errorf("screenValue(\"\") = %v, want nil", err)
	}
}
