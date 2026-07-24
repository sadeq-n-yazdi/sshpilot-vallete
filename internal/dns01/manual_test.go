package dns01

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// TestManualProviderPublishesNothingItself is the security property of manual
// mode: it emits instructions and creates no record.
//
// Nothing here can make issuance succeed. The record exists only if the
// operator creates it, and the solver's propagation gate is what decides
// whether they did — so a manual deployment nobody is watching fails closed
// instead of drifting into "issuance appeared to succeed".
func TestManualProviderPublishesNothingItself(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	provider := NewManualProvider(logger)

	rec := Record{Name: "_acme-challenge.vallet.example.com", Value: "digest-value"}
	cleanup, err := provider.Present(t.Context(), rec)
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if cleanup == nil {
		t.Fatal("Present returned no cleanup; the solver's unconditional release " +
			"path must be uniform across providers")
	}

	out := buf.String()
	for _, want := range []string{rec.Name, rec.Value, "TXT"} {
		if !strings.Contains(out, want) {
			t.Errorf("operator instructions omit %q; an operator cannot publish a "+
				"record they were never shown: %s", want, out)
		}
	}

	// Emitted at WARN. At INFO the default production level would filter it out
	// and the operator would watch handshakes be refused with no indication of
	// what the server was waiting for.
	if !strings.Contains(out, "level=WARN") {
		t.Errorf("instructions were not logged at WARN: %s", out)
	}

	if err := cleanup(t.Context()); err != nil {
		t.Errorf("cleanup: %v, want nil: manual mode has nothing to delete", err)
	}
}

// TestManualProviderToleratesNoLogger proves a nil logger does not panic. The
// provider is constructed from config on the startup path, and a panic there
// would be an outage rather than a diagnostic.
func TestManualProviderToleratesNoLogger(t *testing.T) {
	t.Parallel()

	if _, err := NewManualProvider(nil).Present(t.Context(), Record{Name: "x", Value: "y"}); err != nil {
		t.Errorf("Present with a nil logger: %v", err)
	}
}
