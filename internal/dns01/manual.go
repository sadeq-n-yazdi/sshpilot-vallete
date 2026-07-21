package dns01

import (
	"context"
	"log/slog"
)

// manualProvider is ADR-0015's "manual" DNS-01 mode: it emits the record the
// operator must publish and creates nothing itself.
//
// # Why this is the reference implementation of the interface
//
// It implements [Provider] without any vendor API, which is the proof that the
// interface does not smuggle in assumptions about one. It also works for the
// deployments the API providers cannot serve at all — a DNS host with no API,
// or an air-gapped zone edited by hand.
//
// # It cannot make issuance succeed on its own
//
// Present publishes NOTHING. The record exists only if the operator creates it,
// and the solver's propagation gate is what decides whether it did: the gate
// polls the authoritative nameservers for the exact value and, on timeout,
// fails the order. So an unattended manual deployment cannot drift into
// "issuance appeared to succeed" — with no record published there is no
// validation, no certificate, and every handshake keeps being refused.
//
// This is why Present does not block waiting for a keypress or sleep for a
// grace period. Either would be a second, weaker gate that could be satisfied
// by the passage of time rather than by the record existing.
type manualProvider struct {
	logger *slog.Logger
}

var _ Provider = (*manualProvider)(nil)

func newManual(logger *slog.Logger) *manualProvider {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &manualProvider{logger: logger}
}

// Name identifies the mode. It is a constant.
func (m *manualProvider) Name() string { return "manual" }

// Present prints the record the operator must publish.
//
// Logged at Warn because it is a request for human action that blocks issuance:
// at Info it would be filtered out by the default production level and an
// operator would watch the server refuse handshakes with no indication of what
// it was waiting for.
//
// Both fields are safe to log — see [Record]. The TXT value is a digest whose
// entire purpose is to be published in public DNS; the key authorization it
// derives from is never in this process's log path.
func (m *manualProvider) Present(_ context.Context, rec Record) (CleanupFunc, error) {
	m.logger.Warn(
		"dns-01 manual mode: publish this TXT record, issuance is blocked until it resolves",
		slog.String("record_type", "TXT"),
		slog.String("record_name", rec.Name),
		slog.String("record_value", rec.Value),
	)

	// A cleanup is returned even though nothing was created, so the solver's
	// unconditional cleanup path is uniform across providers and the operator
	// is told when the record has served its purpose. It cannot delete
	// anything: this provider has no write access to the zone by definition.
	return func(context.Context) error {
		m.logger.Warn(
			"dns-01 manual mode: this TXT record is no longer needed and should be removed",
			slog.String("record_type", "TXT"),
			slog.String("record_name", rec.Name),
		)
		return nil
	}, nil
}
