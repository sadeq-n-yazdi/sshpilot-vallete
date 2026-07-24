package dns01

import (
	"fmt"
	"io"
	"maps"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// Credentials is the immutable set of resolved credentials handed to a DNS
// provider constructor.
//
// # Why a set rather than one value
//
// The DNS-01 seam originally passed exactly one [secrets.Redacted]. That fits
// the single-token providers (Cloudflare, DigitalOcean, DNSimple, Gandi,
// ArvanCloud) but not the ones that authenticate with several distinct values —
// Route 53 (an access-key id and a secret), and the GoDaddy/Azure/OVH/Namecheap/
// GCP/RFC2136 providers still to come. Credentials generalizes the seam to carry
// SEVERAL NAMED values without changing how a single-token provider is written:
// it reads its one value through [Credentials.Single].
//
// # Custody
//
// Every value is a [secrets.Redacted], and the plaintext map is never exposed:
// there is no accessor that returns the map, only [Credentials.Get] for one
// named value and [Credentials.Single] for a lone value. The type implements
// [fmt.Formatter] so that formatting a Credentials — or a struct that embeds one
// in an unexported field — renders a constant and never a value. That method is
// required, not decorative: fmt walks a struct's unexported fields by raw
// reflection and does not call the String/Format/GoString methods of the values
// it finds, so without a Formatter on the containing type a "%+v" of a struct
// holding this one would print the underlying secrets in full.
//
// # Immutability
//
// The value is constructed once, at startup, and never mutated. The named map
// is cloned on construction so the caller cannot alias and later mutate the
// stored set, and it is never handed back out.
type Credentials struct {
	single    secrets.Redacted
	hasSingle bool
	named     map[string]secrets.Redacted
}

// NewSingleCredential wraps one resolved value as a credential set. It is what
// the single-token providers, and Route 53's colon-packed back-compat form,
// are built from.
func NewSingleCredential(value secrets.Redacted) Credentials {
	return Credentials{single: value, hasSingle: true}
}

// NewNamedCredentials wraps a map of named resolved values. The map is cloned so
// the returned set does not alias the caller's map. A nil or empty map yields a
// set from which nothing can be read — Get and Single both report absence — so
// an empty set fails closed at the provider constructor.
func NewNamedCredentials(values map[string]secrets.Redacted) Credentials {
	return Credentials{named: maps.Clone(values)}
}

// Get returns the named credential and whether it was present. A provider that
// needs a specific value (Route 53's access_key_id) reads it by name.
func (c Credentials) Get(name string) (secrets.Redacted, bool) {
	v, ok := c.named[name]
	return v, ok
}

// Single returns the sole credential in the set, for a provider that
// authenticates with one value.
//
// It succeeds only when the set holds EXACTLY one value: the single-value form,
// or a named map with a single entry (so an operator may use credentials_refs
// with one key for a single-token provider). A set with several named values,
// or the mixed and empty forms, yields (_, false) — the provider then refuses
// rather than guessing which value to send. Fail closed.
func (c Credentials) Single() (secrets.Redacted, bool) {
	switch {
	case c.hasSingle && len(c.named) == 0:
		return c.single, true
	case !c.hasSingle && len(c.named) == 1:
		for _, v := range c.named {
			return v, true
		}
	}
	return "", false
}

// Format implements [fmt.Formatter] so no formatting of a Credentials, under
// any verb, can reveal a value. See the type comment for why this is required
// rather than relying on secrets.Redacted's own redaction.
func (Credentials) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "dns01.Credentials{[REDACTED]}")
}
