package logging

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// render logs one record through the redaction handler into a real JSON
// encoder and returns the bytes that would hit the log stream.
//
// Every assertion in this file is made against those bytes rather than against
// the slog.Attr the handler produced. That is the whole point: an attribute
// that looks redacted in a struct comparison but whose value is re-expanded by
// the encoder (a MarshalJSON that ignores String, a struct field walked field
// by field) is still a leak, and only the rendered output proves it is not.
func render(t *testing.T, emit func(l *slog.Logger), extraAllowed ...string) string {
	t.Helper()
	var buf bytes.Buffer
	enc := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	emit(slog.New(NewRedactHandler(enc, extraAllowed...)))
	return buf.String()
}

// mustNotContain fails when the secret survived into the rendered line.
func mustNotContain(t *testing.T, out, secret, what string) {
	t.Helper()
	if strings.Contains(out, secret) {
		t.Errorf("%s leaked into the log line\n  secret: %q\n  output: %s", what, secret, out)
	}
	if !strings.Contains(out, RedactedMarker) {
		t.Errorf("%s: no redaction marker in output, so nothing was filtered\n  output: %s", what, out)
	}
}

// --- The catalog of things that must never reach a log ------------------

// TestSecretBearingShapesNeverRender walks every secret-carrying shape the
// service handles and asserts the value is absent from the rendered bytes.
//
// Each case uses the key name the value would realistically be logged under by
// a caller who did not think of it as a secret -- which is the only case that
// matters, since a caller who knew would have used secrets.Redacted.
func TestSecretBearingShapesNeverRender(t *testing.T) {
	t.Parallel()

	const (
		privateKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----"
		bearer     = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.s3cr3t-signature"
		dsn        = "postgres://vallet:hunter2@db.internal:5432/vallet?sslmode=require"
	)

	cases := []struct {
		name   string
		key    string
		secret string
	}{
		{"private key", "private_key", privateKey},
		{"csr key material", "csr_key", privateKey},
		{"bearer token", "bearer_token", bearer},
		{"authorization header value", "authorization", "Bearer " + bearer},
		{"access token", "access_token", bearer},
		{"refresh token", "refresh_token", "rt_9f3c1d2b4a5e6f70"},
		{"refresh token hash", "refresh_token_hash", "sha256:9f3c1d2b4a5e6f70"},
		{"api token", "api_token", "vlt_live_8fa93bd0c1e24567"},
		{"pairing code", "pairing_code", "PAIR-7Q4M-2X9K"},
		{"access key value", "access_key", "ak_7c1e4b90d2f8a316"},
		{"session cookie", "cookie", "session=abc123def456; Path=/; HttpOnly"},
		{"set-cookie header", "set_cookie", "session=abc123def456"},
		{"database dsn", "dsn", dsn},
		{"connection string", "connection_string", dsn},
		{"password", "password", "hunter2"},
		{"tls private key", "key_file_contents", privateKey},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out := render(t, func(l *slog.Logger) {
				l.Info("op", slog.String(tc.key, tc.secret))
			})
			mustNotContain(t, out, tc.secret, tc.name)
		})
	}
}

// TestResolvedSecretRefAndRedactedNeverRender covers the two types
// internal/secrets already makes safe. The handler must not undo that, and the
// assertion is on rendered bytes so it also pins that slog resolves LogValue
// rather than marshaling the underlying string.
func TestResolvedSecretRefAndRedactedNeverRender(t *testing.T) {
	t.Parallel()

	const dsn = "postgres://vallet:hunter2@db.internal:5432/vallet"

	t.Run("resolved Redacted under an allowlisted key", func(t *testing.T) {
		t.Parallel()
		out := render(t, func(l *slog.Logger) {
			l.Info("resolved", slog.Any("public_key", secrets.NewRedacted(dsn)))
		})
		mustNotContain(t, out, "hunter2", "resolved secret")
	})

	t.Run("Ref holding a pasted DSN", func(t *testing.T) {
		t.Parallel()
		out := render(t, func(l *slog.Logger) {
			l.Info("ref", slog.Any("handle", secrets.Ref(dsn)))
		})
		mustNotContain(t, out, "hunter2", "pasted DSN in a Ref")
	})
}

// --- Nesting: one slog.Group must not defeat the filter -------------------

func TestRedactionSurvivesNesting(t *testing.T) {
	t.Parallel()

	const secret = "ak_7c1e4b90d2f8a316"

	t.Run("inside slog.Group", func(t *testing.T) {
		t.Parallel()
		out := render(t, func(l *slog.Logger) {
			l.Info("op", slog.Group("auth", slog.String("access_key", secret)))
		})
		mustNotContain(t, out, secret, "secret inside a group")
	})

	t.Run("inside nested slog.Group", func(t *testing.T) {
		t.Parallel()
		out := render(t, func(l *slog.Logger) {
			l.Info("op", slog.Group("outer",
				slog.Group("inner", slog.String("access_key", secret))))
		})
		mustNotContain(t, out, secret, "secret inside a nested group")
	})

	t.Run("inside a LogValuer that expands to a group", func(t *testing.T) {
		t.Parallel()
		out := render(t, func(l *slog.Logger) {
			l.Info("op", slog.Any("handle", credentialValuer{secret: secret}))
		})
		mustNotContain(t, out, secret, "secret returned by a LogValuer")
	})

	t.Run("inside a struct via slog.Any", func(t *testing.T) {
		t.Parallel()
		out := render(t, func(l *slog.Logger) {
			l.Info("op", slog.Any("handle", credentials{Name: "alice", AccessKey: secret}))
		})
		mustNotContain(t, out, secret, "secret in a struct passed to slog.Any")
	})

	t.Run("inside a map via slog.Any", func(t *testing.T) {
		t.Parallel()
		out := render(t, func(l *slog.Logger) {
			l.Info("op", slog.Any("handle", map[string]string{"access_key": secret}))
		})
		mustNotContain(t, out, secret, "secret in a map passed to slog.Any")
	})

	t.Run("inside a WithGroup namespace", func(t *testing.T) {
		t.Parallel()
		out := render(t, func(l *slog.Logger) {
			l.WithGroup("auth").Info("op", slog.String("access_key", secret))
		})
		mustNotContain(t, out, secret, "secret under WithGroup")
	})

	t.Run("attached once via WithAttrs and replayed", func(t *testing.T) {
		t.Parallel()
		out := render(t, func(l *slog.Logger) {
			l.With(slog.String("access_key", secret)).Info("op")
		})
		mustNotContain(t, out, secret, "secret preformatted via With")
	})

	t.Run("in a group nested past the depth bound", func(t *testing.T) {
		t.Parallel()
		attr := slog.String("access_key", secret)
		for i := 0; i < maxDepth+3; i++ {
			attr = slog.Group("g", attr)
		}
		out := render(t, func(l *slog.Logger) { l.Info("op", attr) })
		mustNotContain(t, out, secret, "secret past the depth bound")
	})
}

// TestDepthBoundRedactsEvenAllowlistedKeys pins that the bound is a real limit
// and not decoration.
//
// It has to assert on an ALLOWLISTED key. A secret under an unknown key is
// already redacted at every depth by the key policy, so nesting one proves
// nothing about the bound -- the test would pass with the bound removed. Only a
// value that the key policy would otherwise let through shows that the depth
// check fires, and firing means redacting: the bound stops the walk, and a
// value the filter has stopped inspecting must not be printed.
func TestDepthBoundRedactsEvenAllowlistedKeys(t *testing.T) {
	t.Parallel()

	attr := slog.String("handle", "alice")
	for i := 0; i < maxDepth+3; i++ {
		attr = slog.Group("g", attr)
	}

	out := render(t, func(l *slog.Logger) { l.Info("op", attr) })
	if strings.Contains(out, "alice") {
		t.Errorf("depth bound did not fire; the walk continued past maxDepth: %s", out)
	}
	if !strings.Contains(out, RedactedMarker) {
		t.Errorf("depth bound must redact what it stops inspecting: %s", out)
	}
}

// TestLogValuerIsResolvedNotRedactedWholesale pins that the handler resolves
// LogValuer rather than treating it as an opaque structured value.
//
// Both halves matter. Resolution is what lets a group returned by a LogValuer
// be filtered leaf by leaf -- keeping the safe fields -- instead of being
// redacted whole. It is worth stating that the failure mode if Resolve were
// dropped is a loss of usefulness rather than a leak: an unresolved
// KindLogValuer matches none of leafValue's safe kinds and would be redacted.
// The design is fail-closed even against its own omission, and this test exists
// so that the usefulness half is pinned too.
func TestLogValuerIsResolvedNotRedactedWholesale(t *testing.T) {
	t.Parallel()

	t.Run("scalar LogValuer under an allowed key renders", func(t *testing.T) {
		t.Parallel()
		out := render(t, func(l *slog.Logger) {
			l.Info("op", slog.Any("handle", handleValuer{name: "alice"}))
		})
		if !strings.Contains(out, "alice") {
			t.Errorf("LogValuer was not resolved; its value was redacted wholesale: %s", out)
		}
	})

	t.Run("group LogValuer keeps its safe leaves", func(t *testing.T) {
		t.Parallel()
		out := render(t, func(l *slog.Logger) {
			l.Info("op", slog.Any("auth", mixedValuer{handle: "alice", secret: "ak_secret"}))
		})
		if !strings.Contains(out, "alice") {
			t.Errorf("safe leaf of a resolved group was lost: %s", out)
		}
		if strings.Contains(out, "ak_secret") {
			t.Errorf("unsafe leaf of a resolved group leaked: %s", out)
		}
	})
}

// TestFormattedStructContainingSecretDoesNotLeak pins that %v/%s of a struct
// whose field is a secrets.Redacted renders the marker, so the pre-formatting
// path is closed at the type rather than only at the handler.
func TestFormattedStructContainingSecretDoesNotLeak(t *testing.T) {
	t.Parallel()

	cfg := struct {
		Name  string
		Token secrets.Redacted
	}{Name: "alice", Token: secrets.NewRedacted("hunter2")}

	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		out := render(t, func(l *slog.Logger) {
			l.Info("cfg", slog.String("handle", sprintf(verb, cfg)))
		})
		if strings.Contains(out, "hunter2") {
			t.Errorf("verb %s leaked the secret: %s", verb, out)
		}
	}
}

// --- The unknown-key policy, and the argument for it ----------------------

// TestUnknownKeyIsRedacted is the test that makes the allowlist case.
//
// "device_enrollment_nonce" is a key no denylist would have contained: it does
// not include the words password, token, secret, key or credential, yet the
// value under it is a credential. A denylist ships this to the log stream. The
// allowlist redacts it, because it was never declared loggable -- the failure
// falls on the side of an operator missing a diagnostic rather than on the side
// of disclosure, and the fix is a reviewed one-line addition to the allowlist.
func TestUnknownKeyIsRedacted(t *testing.T) {
	t.Parallel()

	const secret = "nonce_4f8a1c93e7b2d605"
	out := render(t, func(l *slog.Logger) {
		l.Info("enrolled", slog.String("device_enrollment_nonce", secret))
	})
	mustNotContain(t, out, secret, "unclassified key")

	if !strings.Contains(out, `"device_enrollment_nonce":"`+RedactedMarker+`"`) {
		t.Errorf("unknown key should render as the marker, got: %s", out)
	}
}

// TestExtraAllowedKeyRenders pins the declared-widening path: a key becomes
// loggable only by being named at construction.
func TestExtraAllowedKeyRenders(t *testing.T) {
	t.Parallel()

	out := render(t, func(l *slog.Logger) {
		l.Info("op", slog.String("migration_step", "0007_add_key_sets"))
	}, "migration_step")

	if !strings.Contains(out, "0007_add_key_sets") {
		t.Errorf("explicitly allowed key was redacted: %s", out)
	}
}

// TestAllowlistIsCaseInsensitive pins that "Authorization" and "authorization"
// cannot be different keys as far as the policy is concerned.
func TestAllowlistIsCaseInsensitive(t *testing.T) {
	t.Parallel()

	out := render(t, func(l *slog.Logger) {
		l.Info("op", slog.String("HANDLE", "alice"), slog.String("Migration_Step", "x"))
	}, "MIGRATION_step")

	if !strings.Contains(out, "alice") {
		t.Errorf("allowlisted key rejected because of case: %s", out)
	}
	if !strings.Contains(out, `"Migration_Step":"x"`) {
		t.Errorf("extra allowed key rejected because of case: %s", out)
	}
}

// --- The other side: the logs must stay useful ----------------------------

// TestPublicValuesAreNotRedacted pins that the filter does not destroy the
// values this service exists to serve. Redacting a public key (ADR-0002) or a
// handle (ADR-0010, public by default) would protect nothing and leave
// operators unable to diagnose anything.
func TestPublicValuesAreNotRedacted(t *testing.T) {
	t.Parallel()

	const (
		pubKey      = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH0kR2mVQ1XyZ alice@laptop"
		fingerprint = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
	)

	cases := []struct {
		key, value string
	}{
		{"public_key", pubKey},
		{"fingerprint", fingerprint},
		{"handle", "alice"},
		{"key_set", "prod-servers"},
		{"key_type", "ssh-ed25519"},
		{"route", "GET /{handle}/{keyset}"},
		{"method", "GET"},
		{"request_id", "01HQ3M8Z5N7P2K"},
	}

	out := render(t, func(l *slog.Logger) {
		attrs := make([]any, 0, len(cases))
		for _, c := range cases {
			attrs = append(attrs, slog.String(c.key, c.value))
		}
		l.Info("published", attrs...)
	})

	for _, c := range cases {
		if !strings.Contains(out, c.value) {
			t.Errorf("public value %q under key %q was redacted; logs would be useless\n  output: %s",
				c.value, c.key, out)
		}
	}
	if strings.Contains(out, RedactedMarker) {
		t.Errorf("nothing here is secret, yet something was redacted: %s", out)
	}
}

// TestSecretsFilePermissionWarningStaysUseful pins a real production log site
// against the allowlist.
//
// internal/secrets warns when a secret file is group/other-readable, using the
// keys "reference" and "perm". Both were missing from the first draft of the
// allowlist, which would have reduced that warning to "some file somewhere has
// bad permissions" -- a security warning an operator cannot act on, which is
// worse than none. This is the failure mode an allowlist has to be tested
// against, and it is invisible from the secrets package's own tests because
// those use their own handler rather than the one production runs.
func TestSecretsFilePermissionWarningStaysUseful(t *testing.T) {
	t.Parallel()

	out := render(t, func(l *slog.Logger) {
		l.Warn("secret file has group/other-readable permissions",
			slog.String("reference", "/run/secrets/pg-dsn"),
			slog.String("perm", "0644"),
		)
	})

	for _, want := range []string{"/run/secrets/pg-dsn", "0644"} {
		if !strings.Contains(out, want) {
			t.Errorf("permission warning lost %q, leaving it unactionable: %s", want, out)
		}
	}
}

// TestRefUnderAllowlistedKeyStillRedacts pins the backstop that makes
// allowlisting "reference" safe: a secrets.Ref redacts itself through LogValue
// regardless of what the key policy says, so an operator who pastes a DSN into
// a *_ref field cannot have it printed by this key.
func TestRefUnderAllowlistedKeyStillRedacts(t *testing.T) {
	t.Parallel()

	out := render(t, func(l *slog.Logger) {
		l.Warn("perm", slog.Any("reference", secrets.Ref("postgres://vallet:hunter2@db/x")))
	})
	mustNotContain(t, out, "hunter2", "Ref under an allowlisted key")
}

// --- Value-kind policy ----------------------------------------------------

func TestScalarKindsPassThroughUnderAllowedKey(t *testing.T) {
	t.Parallel()

	out := render(t, func(l *slog.Logger) {
		l.Info("op",
			slog.Bool("v_bool", true),
			slog.Int64("v_int", -7),
			slog.Uint64("v_uint", 42),
			slog.Float64("v_float", 1.5),
			slog.Duration("v_dur", 250*time.Millisecond),
			slog.Time("v_time", time.Unix(1700000000, 0).UTC()),
		)
	}, "v_bool", "v_int", "v_uint", "v_float", "v_dur", "v_time")

	for _, want := range []string{"true", "-7", "42", "1.5", "250000000", "2023-11-14"} {
		if !strings.Contains(out, want) {
			t.Errorf("scalar %q was not rendered: %s", want, out)
		}
	}
	if strings.Contains(out, RedactedMarker) {
		t.Errorf("scalars must not be redacted: %s", out)
	}
}

// TestErrorRendersButStructuredValueDoesNot pins the one deliberate exception
// in leafValue and its boundary: an error under an allowlisted key renders its
// cause, while any other structured value under the same key does not.
func TestErrorRendersButStructuredValueDoesNot(t *testing.T) {
	t.Parallel()

	t.Run("error renders its cause", func(t *testing.T) {
		t.Parallel()
		out := render(t, func(l *slog.Logger) {
			l.Error("failed", slog.Any("error", errors.New("ping database: connection refused")))
		})
		if !strings.Contains(out, "connection refused") {
			t.Errorf("error cause must be logged: %s", out)
		}
	})

	t.Run("struct under an allowlisted key is redacted", func(t *testing.T) {
		t.Parallel()
		out := render(t, func(l *slog.Logger) {
			l.Error("failed", slog.Any("error", credentials{Name: "alice", AccessKey: "ak_secret"}))
		})
		mustNotContain(t, out, "ak_secret", "struct under an allowlisted key")
	})
}

// TestErrorTextCarryingDSNIsScrubbed covers the leak no key-based policy can
// see: a driver error whose text embeds the connection string it was built
// from, arriving under the legitimately allowlisted key "error".
func TestErrorTextCarryingDSNIsScrubbed(t *testing.T) {
	t.Parallel()

	out := render(t, func(l *slog.Logger) {
		l.Error("db", slog.Any("error",
			errors.New(`dial postgres://vallet:hunter2@db.internal:5432/vallet: refused`)))
	})

	if strings.Contains(out, "hunter2") {
		t.Errorf("password embedded in an error string leaked: %s", out)
	}
	if !strings.Contains(out, "db.internal") {
		t.Errorf("scrubbing removed the diagnostic half of the error: %s", out)
	}
}

// TestMessageIsScrubbed pins that a credential folded into the message -- past
// the attribute filter entirely -- is still caught.
func TestMessageIsScrubbed(t *testing.T) {
	t.Parallel()

	out := render(t, func(l *slog.Logger) {
		l.Error("cannot reach postgres://vallet:hunter2@db.internal/vallet")
	})
	if strings.Contains(out, "hunter2") {
		t.Errorf("credential in the message leaked: %s", out)
	}
}

func TestScrubURLCredentials(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, in, want string
	}{
		{"no scheme separator", "plain text", "plain text"},
		{"scheme with no userinfo", "https://db.internal/x", "https://db.internal/x"},
		{"userinfo without password", "ssh://alice@host/x", "ssh://alice@host/x"},
		{"userinfo with password", "postgres://u:p@h/d", "postgres://" + RedactedMarker + "@h/d"},
		{"at sign after path", "https://h/a@b", "https://h/a@b"},
		{"trailing scheme only", "see https://", "see https://"},
		{"two dsns", "a postgres://u:p@h1 b mysql://u2:p2@h2",
			"a postgres://" + RedactedMarker + "@h1 b mysql://" + RedactedMarker + "@h2"},
		{"public key is untouched", "ssh-ed25519 AAAAC3Nza alice@laptop", "ssh-ed25519 AAAAC3Nza alice@laptop"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := scrubURLCredentials(tc.in); got != tc.want {
				t.Errorf("scrubURLCredentials(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// --- Handler plumbing -----------------------------------------------------

func TestEnabledDelegatesToNext(t *testing.T) {
	t.Parallel()

	h := NewRedactHandler(slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("info must be disabled when the wrapped handler is at warn")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("error must be enabled when the wrapped handler is at warn")
	}
}

// TestWithAttrsAndWithGroupNoOpOnEmpty pins that the identity cases return the
// receiver rather than allocating a new handler around the same next.
func TestWithAttrsAndWithGroupNoOpOnEmpty(t *testing.T) {
	t.Parallel()

	h := NewRedactHandler(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	if got := h.WithAttrs(nil); got != slog.Handler(h) {
		t.Error("WithAttrs(nil) must return the receiver")
	}
	if got := h.WithGroup(""); got != slog.Handler(h) {
		t.Error("WithGroup(\"\") must return the receiver")
	}
}

// TestWithAttrsPreservesAllowedValues pins that preformatting does not redact
// legitimate values -- the filter must be lossless for allowlisted keys.
func TestWithAttrsPreservesAllowedValues(t *testing.T) {
	t.Parallel()

	out := render(t, func(l *slog.Logger) {
		l.With(slog.String("component", "publish")).Info("op", slog.String("handle", "alice"))
	})
	if !strings.Contains(out, "publish") || !strings.Contains(out, "alice") {
		t.Errorf("allowed values lost through With: %s", out)
	}
}

// --- helpers --------------------------------------------------------------

type credentials struct {
	Name      string
	AccessKey string
}

// credentialValuer expands into a group, which is the case that defeats a
// filter that only inspects top-level attributes.
type credentialValuer struct{ secret string }

func (c credentialValuer) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("name", "alice"),
		slog.String("access_key", c.secret),
	)
}

// handleValuer resolves to a plain, non-secret value.
type handleValuer struct{ name string }

func (h handleValuer) LogValue() slog.Value { return slog.StringValue(h.name) }

// mixedValuer resolves to a group holding one loggable and one secret leaf, so
// that resolution and per-leaf filtering are exercised together.
type mixedValuer struct{ handle, secret string }

func (m mixedValuer) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("handle", m.handle),
		slog.String("access_key", m.secret),
	)
}

func sprintf(verb string, v any) string { return fmt.Sprintf(verb, v) }
