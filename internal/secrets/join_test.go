package secrets

import (
	"fmt"
	"strings"
	"testing"
)

// TestJoinComposesAndRedacts proves Join builds the separated value (reachable
// only through Reveal) while the result still redacts through every formatting
// path — it is a Redacted like any other.
func TestJoinComposesAndRedacts(t *testing.T) {
	t.Parallel()

	joined := Join(":", NewRedacted("AKID"), NewRedacted("secretkey"))

	if got := joined.Reveal(); got != "AKID:secretkey" {
		t.Fatalf("Reveal() = %q, want AKID:secretkey", got)
	}

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		out := fmt.Sprintf(verb, joined)
		if strings.Contains(out, "AKID") || strings.Contains(out, "secretkey") {
			t.Errorf("verb %s leaked a part: %s", verb, out)
		}
		if !strings.Contains(out, redactedMarker) {
			t.Errorf("verb %s did not redact: %s", verb, out)
		}
	}
}
