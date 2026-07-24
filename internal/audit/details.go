package audit

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// DetailKey names a piece of non-secret context attached to an audit record.
//
// Only the keys declared below may be used. The allowlist, not a denylist of
// forbidden words, is what keeps secrets out: a denylist has to anticipate every
// name a secret might be given, whereas an allowlist means an unanticipated name
// simply does not work. There is no "token", "password", or "credential" key, so
// a secret has no natural home in a record, and giving it one is a visible edit
// to this list rather than an incidental string literal at a call site.
//
// Adding a key here is a deliberate act: the reviewer's question is "can this
// field ever carry a secret, key material, or a credential?" — and if the answer
// is anything but a confident no, the key does not belong.
type DetailKey string

// Allowlisted detail keys. Each records a non-secret fact needed to reconstruct
// an access-affecting change.
const (
	// DetailFingerprint is a public key's SHA256 fingerprint — the way a key is
	// named in the audit log. The key's bytes are never recorded; the
	// fingerprint identifies which key was involved without copying it.
	DetailFingerprint DetailKey = "fingerprint"
	// DetailAlgorithm is a public key algorithm, e.g. "ssh-ed25519".
	DetailAlgorithm DetailKey = "algorithm"

	// DetailDeviceName, DetailHandle, and DetailKeySetName are display names of
	// the entity involved, recorded because an ID alone is unreadable in an
	// incident review.
	DetailDeviceName DetailKey = "device_name"
	DetailHandle     DetailKey = "handle"
	DetailKeySetName DetailKey = "key_set_name"

	// DetailFrom and DetailTo capture a before/after pair for a change that
	// replaces one non-secret value with another, such as a rename or a
	// visibility change.
	DetailFrom DetailKey = "from"
	DetailTo   DetailKey = "to"

	// DetailVisibility is a key set's visibility, e.g. "public" or "protected".
	DetailVisibility DetailKey = "visibility"
	// DetailScope is the authorization scope an action was performed under.
	DetailScope DetailKey = "scope"
	// DetailReason is a short, operator-supplied explanation for the action.
	DetailReason DetailKey = "reason"
	// DetailResult is the outcome of the action, e.g. "allowed" or "denied".
	DetailResult DetailKey = "result"
	// DetailRequestID correlates the record with the request that caused it,
	// linking the audit log to the request log without duplicating either.
	DetailRequestID DetailKey = "request_id"
	// DetailClientLabel is the caller-supplied label of the client involved.
	DetailClientLabel DetailKey = "client_label"
	// DetailCount is a whole number of items an action affected, for actions
	// that operate on a set rather than one entity -- for example how many
	// records a retention purge removed. It carries a count, never any part of
	// what was counted.
	DetailCount DetailKey = "count"
)

// allowedDetailKeys is the authoritative allowlist. DetailKey is a defined
// string type, so a caller can conjure DetailKey("token") by conversion; this
// map is what actually refuses it.
var allowedDetailKeys = map[DetailKey]bool{
	DetailFingerprint: true,
	DetailAlgorithm:   true,
	DetailDeviceName:  true,
	DetailHandle:      true,
	DetailKeySetName:  true,
	DetailFrom:        true,
	DetailTo:          true,
	DetailVisibility:  true,
	DetailScope:       true,
	DetailReason:      true,
	DetailResult:      true,
	DetailRequestID:   true,
	DetailClientLabel: true,
	DetailCount:       true,
}

// keptDetailKeys are the detail keys whose VALUE is structural and carries no
// identity: the kind of a thing that happened, never who it happened to. They
// are preserved byte-for-byte through owner crypto-erasure (ADR-0024), because
// erasing them would destroy the forensic substance of a record while erasing
// nothing personal — an algorithm name or a request correlator names no owner.
//
// Every other allowlisted key can carry an owner's identity in its value and is
// therefore erasable:
//
//   - fingerprint names a specific key and so its owner;
//   - handle, device_name, key_set_name and client_label are display names of
//     the owner's own entities;
//   - from and to carry the old/new names in a rename, which are those same
//     display names.
//
// The classification is expressed as the KEEP set rather than the erasable set
// on purpose, and IsErasableDetail below inverts it: an unrecognized or
// newly-added key defaults to erasable, so the failure mode of forgetting to
// classify a new key is a value needlessly tombstoned, never an identity
// silently left in the clear. This is the fail-closed direction for privacy.
//
// The split is authoritative: ADR-0024's "Open items" records exactly this
// field list. TestDetailErasureClassification pins each of the fourteen keys so
// a future edit that moves one across the line fails loudly.
var keptDetailKeys = map[DetailKey]bool{
	DetailAlgorithm:  true,
	DetailVisibility: true,
	DetailScope:      true,
	DetailReason:     true,
	DetailResult:     true,
	DetailRequestID:  true,
	DetailCount:      true,
}

// IsErasableDetail reports whether the value stored under key can identify an
// owner and must be rewritten to a tombstone during owner crypto-erasure
// (ADR-0024). It is the inverse of the structural KEEP set: any key not
// explicitly classified as structural — including an unrecognized one — is
// treated as identifying, so the fail-closed default is to erase.
func IsErasableDetail(key DetailKey) bool {
	return !keptDetailKeys[key]
}

// maxDetailValueLen bounds a detail value. Audit context is short, factual
// text; the bound both keeps records small and means a large blob — a key file,
// a certificate, a dump — cannot be parked in the log through a detail field.
const maxDetailValueLen = 256

// maxAllowedDetailKeys bounds the allowlist itself, and with it the number of
// details a record can carry: keys are unique in the map, so a record can hold
// at most one value per allowlisted key. The allowlist is therefore the bound
// on record size, and no separate count limit is needed — a separate limit set
// above the allowlist size would be unreachable code pretending to be a control.
// TestAllowlistStaysSmall enforces this ceiling so the list cannot quietly grow
// into a general-purpose metadata bag.
const maxAllowedDetailKeys = 32

// Details is the bounded, allowlisted, non-secret context attached to an event.
// The zero value is empty and ready to use.
//
// Set is chainable and records the first error it encounters, so a caller can
// build a Details in one expression and let Emit surface any problem, rather
// than checking an error after every field and being tempted to skip the check.
type Details struct {
	pairs map[string]string
	err   error
}

// Set returns a copy of d with the detail added. Both the key and the value are
// validated; the first failure is retained and returned by Emit. Set never
// records a value it has rejected, so a rejected secret is not merely flagged,
// it is not stored.
//
// Set copies the underlying map rather than mutating it in place. Details is a
// value type, so an in-place mutation would be visible through every copy a
// caller had already taken — branching one base Details into two events would
// silently merge their context, and an audit record that gains context from an
// unrelated event is a false record.
func (d Details) Set(key DetailKey, value string) Details {
	if d.err != nil {
		return d
	}
	if !allowedDetailKeys[key] {
		// The rejected key is not echoed: a caller who passed a key named after
		// a secret should not have that name copied into an error that is itself
		// likely to be logged.
		return Details{err: fmt.Errorf("audit: detail key is not on the allowlist: %w", domain.ErrInvalidInput)}
	}
	if err := screenDetailValue(key, value); err != nil {
		return Details{err: err}
	}
	pairs := make(map[string]string, len(d.pairs)+1)
	for k, v := range d.pairs {
		pairs[k] = v
	}
	pairs[string(key)] = value
	return Details{pairs: pairs}
}

// Err returns the first error recorded while building the details, if any.
func (d Details) Err() error { return d.err }

// metadata returns the map to store on the record, or the retained build error.
// An empty Details yields a nil map, matching the nil-collection convention.
func (d Details) metadata() (map[string]string, error) {
	if d.err != nil {
		return nil, d.err
	}
	if len(d.pairs) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(d.pairs))
	for k, v := range d.pairs {
		out[k] = v
	}
	return out, nil
}

// screenDetailValue validates one detail value: length, character content, and
// credential shape, plus any per-key format rule.
func screenDetailValue(key DetailKey, value string) error {
	if value == "" {
		return fmt.Errorf("audit: empty detail value: %w", domain.ErrInvalidInput)
	}
	if len(value) > maxDetailValueLen {
		return fmt.Errorf("audit: detail value too long: %w", domain.ErrInvalidInput)
	}
	if err := screenValue("detail value", value); err != nil {
		return err
	}
	// A fingerprint is the one detail with an exact required shape. Enforcing it
	// means the field that names a key cannot quietly become a field that
	// carries one.
	if key == DetailFingerprint {
		if err := domain.ValidateFingerprint(value); err != nil {
			return fmt.Errorf("audit: malformed fingerprint detail: %w", domain.ErrInvalidInput)
		}
	}
	return nil
}

// redactionMarker is what the secrets package renders in place of a secret
// through every formatting path. Its presence in an audit value means a caller
// formatted a live secret into an audit call and was saved by the redaction; the
// value is not a fact worth recording and the call site is a bug, so it is
// rejected rather than stored.
const redactionMarker = "[REDACTED]"

// credentialMarkers are substrings that betray key material or a credential.
// This is a backstop behind the key allowlist, not the primary defense: it
// catches a secret placed in a legitimately-named field (a token pasted into
// "reason"), which the allowlist alone cannot see.
var credentialMarkers = []string{
	"-----begin",     // any PEM block, including PRIVATE KEY and CERTIFICATE
	"private key",    // OpenSSH and PEM private key headers
	"bearer ",        // Authorization: Bearer <token>
	"authorization:", // a copied request header
	"proxy-authorization:",
	"basic ",         // Authorization: Basic <base64>
	"aws_secret",     // credential file keys
	"begin openssh",  // OpenSSH key container
	"putty-user-key", // PuTTY private key container
	"x-api-key",      // a copied API key header
	"set-cookie:",    // a copied cookie header
}

// screenValue rejects a value that looks like a credential or is otherwise
// unfit for a durable, widely-copied record. Nothing about the offending value
// is echoed into the error.
func screenValue(field, value string) error {
	if value == "" {
		return nil
	}
	if strings.Contains(value, redactionMarker) {
		return fmt.Errorf("audit: %s carries a redacted secret; "+
			"audit records must never be given secret values: %w", field, domain.ErrInvalidInput)
	}

	lower := strings.ToLower(value)
	for _, marker := range credentialMarkers {
		if strings.Contains(lower, marker) {
			return fmt.Errorf("audit: %s looks like key material or a credential: %w",
				field, domain.ErrInvalidInput)
		}
	}
	if looksLikeJWT(value) {
		return fmt.Errorf("audit: %s looks like a token: %w", field, domain.ErrInvalidInput)
	}
	if err := screenPrintable(field, value); err != nil {
		return err
	}
	return nil
}

// screenPrintable rejects control characters and other non-printable runes. A
// newline or an ANSI escape in an audit value lets a writer forge extra lines in
// any text rendering of the log — the log-injection variant of the problem this
// package exists to prevent — and a NUL can truncate the value in a downstream
// consumer.
func screenPrintable(field, value string) error {
	for _, r := range value {
		if r == unicode.ReplacementChar {
			return fmt.Errorf("audit: %s is not valid UTF-8: %w", field, domain.ErrInvalidInput)
		}
		if !unicode.IsPrint(r) {
			return fmt.Errorf("audit: %s contains a non-printable character: %w",
				field, domain.ErrInvalidInput)
		}
	}
	return nil
}

// looksLikeJWT reports whether value has the three-part dotted shape of a JSON
// Web Token with a plausible header segment. The check is deliberately narrow —
// it requires the "eyJ" prefix a base64url-encoded JSON header always produces —
// so ordinary dotted values such as version strings and hostnames are unaffected.
func looksLikeJWT(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	if !strings.HasPrefix(parts[0], "eyJ") {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	return true
}
