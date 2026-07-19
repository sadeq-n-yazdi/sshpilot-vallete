package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// pastedDSN is the realistic operator error this fix exists for: a Postgres DSN
// pasted into a *_ref config field instead of a reference to one. It parses as a
// valid scheme:opaque reference, so config validation accepts it and it reaches
// the resolver, which historically printed it in full at startup.
const pastedDSN = Ref("postgres://user:hunter2@db.internal:5432/vallet")

// dsnSecrets are the substrings of pastedDSN that must never reach a log or an
// error: the password, the username, and the host.
var dsnSecrets = []string{"hunter2", "user", "db.internal", "5432", "vallet"}

// assertNoDSNLeak fails if out contains any part of the pasted DSN beyond its
// scheme. It is deliberately strict: the whole opaque half is sensitive.
func assertNoDSNLeak(t *testing.T, what, out string) {
	t.Helper()
	for _, s := range dsnSecrets {
		if strings.Contains(out, s) {
			t.Errorf("%s leaked %q from the pasted DSN: %s", what, s, out)
		}
	}
	if strings.Contains(out, "://") {
		t.Errorf("%s leaked the DSN body: %s", what, out)
	}
}

func TestRefRedactsAllFormatVerbs(t *testing.T) {
	for _, verb := range []string{"%v", "%s", "%q", "%+v", "%#v", "%d"} {
		out := fmt.Sprintf(verb, pastedDSN)
		assertNoDSNLeak(t, "fmt.Sprintf("+verb+")", out)
		if !strings.Contains(out, redactedMarker) {
			t.Errorf("fmt.Sprintf(%s) = %q, want the redaction marker", verb, out)
		}
		// The scheme survives: it is the diagnostic that tells an operator they
		// pasted a DSN rather than a reference, and it is not secret.
		if !strings.Contains(out, "postgres") {
			t.Errorf("fmt.Sprintf(%s) = %q, want the scheme preserved", verb, out)
		}
	}
}

// TestRefRedactsInsideStruct covers the realistic path: a Ref is not printed on
// its own, it is a field of a config struct someone dumps with %+v.
func TestRefRedactsInsideStruct(t *testing.T) {
	cfg := struct {
		DSNRef Ref
		Port   int
	}{DSNRef: pastedDSN, Port: 8080}

	for _, verb := range []string{"%v", "%+v", "%#v"} {
		assertNoDSNLeak(t, "struct "+verb, fmt.Sprintf(verb, cfg))
	}
}

func TestRefStringAndGoString(t *testing.T) {
	if got := pastedDSN.String(); got != "postgres:"+redactedMarker {
		t.Errorf("String() = %q", got)
	}
	if got := pastedDSN.GoString(); got != "postgres:"+redactedMarker {
		t.Errorf("GoString() = %q", got)
	}
}

func TestRefRedactsThroughSlogHandlers(t *testing.T) {
	// A Ref passed directly as an attribute is covered by LogValue; a Ref inside
	// a struct passed to slog.Any is covered by MarshalJSON, which the JSON
	// handler reaches instead of LogValue.
	cfg := struct {
		DSNRef Ref `json:"dsn_ref"`
	}{DSNRef: pastedDSN}

	for _, tc := range []struct {
		name    string
		handler func(*bytes.Buffer) slog.Handler
	}{
		{"text", func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) }},
		{"json", func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(tc.handler(&buf))
			logger.Info("startup", slog.Any("ref", pastedDSN), slog.Any("config", cfg))

			out := buf.String()
			assertNoDSNLeak(t, "slog "+tc.name+" handler", out)
			if !strings.Contains(out, redactedMarker) {
				t.Errorf("slog %s output %q lacks the redaction marker", tc.name, out)
			}
		})
	}
}

func TestRefRedactsThroughMarshalers(t *testing.T) {
	jsonOut, err := json.Marshal(struct {
		DSNRef Ref `json:"dsn_ref"`
	}{DSNRef: pastedDSN})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	assertNoDSNLeak(t, "json.Marshal", string(jsonOut))

	// The output must remain valid JSON, not just redacted.
	var back map[string]string
	if err := json.Unmarshal(jsonOut, &back); err != nil {
		t.Fatalf("redacted JSON is not valid JSON: %v", err)
	}

	yamlOut, err := yaml.Marshal(struct {
		DSNRef Ref `yaml:"dsn_ref"`
	}{DSNRef: pastedDSN})
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	assertNoDSNLeak(t, "yaml.Marshal", string(yamlOut))

	text, err := pastedDSN.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	assertNoDSNLeak(t, "MarshalText", string(text))
}

// TestRefUnmarshalStillYieldsRealReference guards the other half of the
// contract: redaction is a rendering concern only. A Ref read from YAML must
// still hold the real reference, or providers could not resolve anything.
func TestRefUnmarshalStillYieldsRealReference(t *testing.T) {
	var cfg struct {
		DSNRef Ref `yaml:"dsn_ref"`
	}
	if err := yaml.Unmarshal([]byte("dsn_ref: env:VALLET_PG_DSN\n"), &cfg); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	if string(cfg.DSNRef) != "env:VALLET_PG_DSN" {
		t.Errorf("unmarshalled ref = %q, want the real reference", string(cfg.DSNRef))
	}
	if cfg.DSNRef.Opaque() != "VALLET_PG_DSN" {
		t.Errorf("Opaque() = %q, want the real opaque part", cfg.DSNRef.Opaque())
	}
}

func TestRefRedactedForms(t *testing.T) {
	tests := []struct {
		name string
		ref  Ref
		want string
	}{
		{"env reference keeps scheme", "env:VALLET_PG_DSN", "env:" + redactedMarker},
		{"file reference keeps scheme", "file:/run/secrets/pg-dsn", "file:" + redactedMarker},
		{"pasted dsn keeps scheme", pastedDSN, "postgres:" + redactedMarker},
		{"empty ref", "", redactedMarker},
		// No colon: a bare pasted password. Nothing is echoed at all.
		{"bare pasted password", "hunter2", redactedMarker},
		// Not scheme-shaped: pasted key material must not have its first
		// colon-delimited chunk echoed.
		{"pem block", "-----BEGIN PRIVATE KEY-----:MIIE", redactedMarker},
		{"scheme with space", "not a scheme:x", redactedMarker},
		{"leading digit", "1postgres:x", redactedMarker},
		{"empty scheme", ":opaque", redactedMarker},
		{"overlong scheme", Ref(strings.Repeat("a", maxSchemeLen+1) + ":x"), redactedMarker},
		{"max length scheme", Ref(strings.Repeat("a", maxSchemeLen) + ":x"), strings.Repeat("a", maxSchemeLen) + ":" + redactedMarker},
		{"scheme punctuation", "s3+https:bucket", "s3+https:" + redactedMarker},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.ref.redacted(); got != tc.want {
				t.Errorf("redacted() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRedactedRefIsRejectedOnReload pins the fail-closed half of one-way
// redaction. Serializing a config and reading it back must not yield something
// that looks usable: the marshalers replace every reference with the marker, so
// the resulting document describes no secret at all.
//
// The requirement is that this is caught at LOAD, by Validate, with a message
// naming the real cause. Without the check the round-tripped reference parses
// cleanly -- "env" is a real scheme and "[REDACTED]" a non-empty opaque part --
// and only fails much later at Resolve as "env var [REDACTED] not set", which
// reads like a missing deployment variable and sends the operator looking in
// entirely the wrong place.
func TestRedactedRefIsRejectedOnReload(t *testing.T) {
	original := Ref("env:VALLET_PG_DSN")
	if err := original.Validate(); err != nil {
		t.Fatalf("the original reference must be valid: %v", err)
	}

	// Round-trip it exactly as a config export would: marshal, then read back.
	encoded, err := yaml.Marshal(struct {
		DSNRef Ref `yaml:"dsn_ref"`
	}{DSNRef: original})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded struct {
		DSNRef Ref `yaml:"dsn_ref"`
	}
	if err := yaml.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.DSNRef == original {
		t.Fatal("redaction is one-way: a marshaled reference must not survive the round trip intact")
	}
	err = decoded.DSNRef.Validate()
	if err == nil {
		t.Fatalf("Validate accepted the round-tripped reference %q; a redacted reference is not usable and must be refused at load", decoded.DSNRef)
	}
	if !strings.Contains(err.Error(), "redacted") {
		t.Errorf("error must name the real cause, got: %v", err)
	}
	// The diagnostic itself must stay redacted, like every other Ref rendering.
	if strings.Contains(err.Error(), "VALLET_PG_DSN") {
		t.Errorf("error echoed the original reference: %v", err)
	}
}
