// Package dns01 provides the pluggable DNS-provider seam ADR-0015 §2 requires
// for the ACME DNS-01 solver.
//
// DNS-01 proves control of a name by publishing a TXT record at
// "_acme-challenge.<name>" whose value the CA can compute from the challenge
// token and the account key. Every provider in ADR-0015's phase-1 list —
// Cloudflare, Route 53, Google Cloud DNS, Azure DNS, DigitalOcean, DNSimple,
// GoDaddy, Namecheap, Gandi, OVH, ArvanCloud and RFC 2136 — differs only in HOW
// that one record is created and removed. This package isolates that difference
// so each new provider is a self-contained file plus one registry case.
//
// # Why the credential never appears in this package's exported surface
//
// A DNS-01 credential can rewrite the zone: it is the highest-privilege secret
// this process holds. It therefore enters a provider as a [secrets.Redacted],
// which renders as the redaction marker through every fmt, log, JSON and YAML
// path, and is unwrapped only at the moment it is written into an outbound
// request header. No exported type in this package carries the plaintext, so a
// caller cannot accidentally place it in a log field, a span attribute or an
// error.
package dns01

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// ErrUnsupportedProvider is returned by [NewAPIProvider] for a provider name
// this build does not implement.
//
// It is a refusal, never a fallback. A configuration naming a provider that is
// not compiled in must fail startup: the alternatives are solving the challenge
// through some other provider's credentials, or silently downgrading to a
// different challenge type, and both are security decisions taken by an error
// path rather than by the operator.
var ErrUnsupportedProvider = errors.New("dns01: unsupported dns provider")

// challengePrefix is the label ACME DNS-01 prescribes (RFC 8555 §8.4).
const challengePrefix = "_acme-challenge"

// maxAPIMessageBytes bounds how much of a DNS provider's own error message is
// carried into an error this package returns.
//
// It is shared by every provider so the limit is one decision rather than a
// number each new provider picks again. The message is remote input and is a
// bounded diagnostic, not trusted text. Apply it with [safetext.Bound], never
// with a slice expression: a fixed byte cut can split a multi-byte rune and
// leave invalid UTF-8 for the log encoder downstream to mangle.
const maxAPIMessageBytes = 200

// Record is the single TXT record a DNS-01 challenge needs published.
//
// Neither field is a secret. Name is a public hostname, and Value is the
// base64url SHA-256 digest of the key authorization — a one-way function of a
// token the CA already knows and of the account key's PUBLIC part. The digest
// is designed to be published in DNS for the whole world to read, so a provider
// may log it. The key authorization itself is never carried here.
type Record struct {
	// Name is the fully qualified record name, without a trailing dot, e.g.
	// "_acme-challenge.vallet.example.com".
	Name string
	// Value is the TXT record's content, unquoted.
	Value string
}

// ChallengeRecordName returns the TXT record name for an ACME identifier.
//
// A wildcard identifier's "*." prefix is stripped: RFC 8555 §8.4 puts the
// challenge for "*.example.com" at "_acme-challenge.example.com", the same
// place as the challenge for the bare name. Leaving the asterisk in would
// publish a record at a name no CA ever queries, so issuance would time out
// waiting for propagation of a record nothing was looking for.
func ChallengeRecordName(identifier string) string {
	return challengePrefix + "." + strings.TrimPrefix(identifier, "*.")
}

// CleanupFunc removes the exact record a [Provider.Present] call created.
//
// # Why cleanup is a closure and not a Remove(Record) method
//
// This is the structural answer to "the provider must not be able to modify or
// delete unrelated records". A closure captures the provider-assigned IDENTITY
// of the record that was just created — for Cloudflare, the record ID the API
// returned. Removal is then a delete of that one ID, and there is no code path
// that turns a NAME into a set of records to delete. A Remove(Record) method
// would have to search the zone by name and delete what it found, which is a
// primitive that can delete a record this process never created — including an
// operator's own TXT record at the same name.
//
// A CleanupFunc must be safe to call more than once and must not fail because
// the record is already gone: a challenge record removed by the operator, or by
// a previous attempt, leaves nothing to do and is a success.
//
// It takes its own context because it runs on paths where the caller's context
// is already canceled — see the solver's detached-context cleanup.
type CleanupFunc func(context.Context) error

// Provider creates and removes the challenge TXT record for one DNS host.
//
// # The contract E6–E16 implement
//
//   - Present publishes rec and returns the cleanup for exactly that record.
//   - A non-nil CleanupFunc MUST be returned whenever anything was created,
//     INCLUDING when Present goes on to fail. A provider that creates a record
//     and then errors without handing back its cleanup has leaked a standing
//     authorization that nothing in this process can withdraw.
//   - Present must not wait for DNS propagation. That check is common to every
//     provider and is performed once, by the solver, against the authoritative
//     nameservers — so a provider cannot accidentally omit it, and no provider
//     has to reimplement it.
//   - Errors must name the record and the API fault, never the credential.
//
// The interface is deliberately this small. Everything a DNS-01 solver needs
// beyond it — the record name, the TXT value, propagation, retry, the ordering
// of cleanup against failure paths — is solved once above this line, so a new
// provider is only the vendor's create and delete calls.
type Provider interface {
	// Name identifies the provider for diagnostics. It is a constant like
	// "cloudflare", never derived from the credential.
	Name() string

	// Present publishes rec and returns the cleanup that removes it.
	Present(ctx context.Context, rec Record) (CleanupFunc, error)
}

// NewAPIProvider builds the provider selected by tls.acme.dns.provider.
//
// The switch is exhaustive and its default REFUSES. Adding a provider from
// ADR-0015's phase-1 list is one file plus one case here; nothing else in the
// solver, the ACME flow or the config schema changes. That is the property the
// per-provider tasks depend on.
//
// The credential arrives already resolved through the secret provider and
// already wrapped, so no caller of this package ever holds it in plain form.
func NewAPIProvider(name string, credential secrets.Redacted, client *http.Client) (Provider, error) {
	switch name {
	case "cloudflare":
		return NewCloudflare(credential, client)
	case "route53":
		return NewRoute53(credential, client)
	case "digitalocean":
		return NewDigitalOcean(credential, client)
	case "dnsimple":
		return NewDNSimple(credential, client)
	case "gandi":
		return NewGandi(credential, client)
	case "arvancloud":
		return NewArvanCloud(credential, client)
	default:
		// The provider NAME is echoed because it came from the operator's own
		// config file and is the diagnostic. The credential is not touched.
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedProvider, name)
	}
}

// NewManualProvider builds the operator-driven provider. It is separate from
// NewAPIProvider because manual mode is selected by tls.acme.dns.mode rather
// than by a provider name, and because it takes no credential at all.
func NewManualProvider(logger *slog.Logger) Provider { return newManual(logger) }
