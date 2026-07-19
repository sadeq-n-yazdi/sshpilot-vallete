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

const secretValue = "super-secret-password-1234"

// holder embeds a Redacted the way real config/log structs do, so we exercise
// the realistic leak path: printing the surrounding struct.
type holder struct {
	Name  string
	Token Redacted
}

func assertNoLeak(t *testing.T, where, out string) {
	t.Helper()
	if strings.Contains(out, secretValue) {
		t.Fatalf("%s leaked secret value: %q", where, out)
	}
	if !strings.Contains(out, redactedMarker) {
		t.Fatalf("%s did not contain %q: %q", where, redactedMarker, out)
	}
}

func TestRedactedDirectFormatting(t *testing.T) {
	r := NewRedacted(secretValue)
	cases := map[string]string{
		"%v":  fmt.Sprintf("%v", r),
		"%s":  fmt.Sprintf("%s", r),
		"%q":  fmt.Sprintf("%q", r),
		"%#v": fmt.Sprintf("%#v", r),
		"%d":  fmt.Sprintf("%d", r),
		"%x":  fmt.Sprintf("%x", r),
		"str": r.String(),
		"go":  r.GoString(),
	}
	for verb, out := range cases {
		assertNoLeak(t, "direct "+verb, out)
	}
}

func TestRedactedInStructFormatting(t *testing.T) {
	h := holder{Name: "db", Token: NewRedacted(secretValue)}
	cases := map[string]string{
		"%v":  fmt.Sprintf("%v", h),
		"%+v": fmt.Sprintf("%+v", h),
		"%#v": fmt.Sprintf("%#v", h),
		"%s":  fmt.Sprintf("%s", h),
	}
	for verb, out := range cases {
		assertNoLeak(t, "struct "+verb, out)
	}
	// Pointer to struct too.
	assertNoLeak(t, "ptr %v", fmt.Sprintf("%v", &h))
}

func TestRedactedJSON(t *testing.T) {
	h := holder{Name: "db", Token: NewRedacted(secretValue)}
	out, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	assertNoLeak(t, "json", string(out))
	// Output must remain valid JSON with a quoted marker.
	var back map[string]any
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("json not valid: %v (%s)", err, out)
	}
	if back["Token"] != redactedMarker {
		t.Fatalf("json token = %v, want %q", back["Token"], redactedMarker)
	}
}

func TestRedactedYAML(t *testing.T) {
	h := holder{Name: "db", Token: NewRedacted(secretValue)}
	out, err := yaml.Marshal(h)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	assertNoLeak(t, "yaml", string(out))
}

func TestRedactedText(t *testing.T) {
	out, err := NewRedacted(secretValue).MarshalText()
	if err != nil {
		t.Fatalf("marshal text: %v", err)
	}
	assertNoLeak(t, "text", string(out))
}

func TestRedactedSlog(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	r := NewRedacted(secretValue)
	// Direct attribute value (LogValuer path).
	logger.Info("msg", slog.Any("token", r))
	// Inside a struct attribute (fmt/Format path via %v resolution).
	logger.Info("msg2", slog.Any("holder", holder{Token: r}))
	assertNoLeak(t, "slog", buf.String())
}

func TestRedactedReveal(t *testing.T) {
	r := NewRedacted(secretValue)
	if got := r.Reveal(); got != secretValue {
		t.Fatalf("Reveal() = %q, want %q", got, secretValue)
	}
}
