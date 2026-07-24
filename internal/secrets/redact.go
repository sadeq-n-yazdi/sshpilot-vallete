package secrets

import (
	"fmt"
	"log/slog"
	"strings"
)

// redactedMarker is the single string every redaction path emits. A secret
// value is never rendered by any of the standard formatting, logging, or
// marshaling interfaces below; the only way to obtain the underlying value is
// the explicit Reveal method.
const redactedMarker = "[REDACTED]"

// Redacted wraps a resolved secret value so that dumping it via fmt, log/slog,
// encoding/json, or gopkg.in/yaml.v3 is safe by construction. Every rendering
// path returns "[REDACTED]"; only Reveal returns the underlying value.
//
// Redacted implements fmt.Stringer, fmt.GoStringer, fmt.Formatter,
// json.Marshaler, encoding.TextMarshaler, slog.LogValuer, and yaml.Marshaler.
type Redacted string

// NewRedacted wraps a raw secret value.
func NewRedacted(value string) Redacted { return Redacted(value) }

// Reveal returns the underlying secret value. This is the ONLY exit from a
// Redacted; callers must treat the result as sensitive and never log it.
func (r Redacted) Reveal() string { return string(r) }

// Join composes several resolved secrets into one Redacted, separated by sep.
//
// It exists so a provider whose credential is assembled from several separately
// resolved parts — Route 53's access-key id and secret — can build its stored
// form WITHOUT a Reveal in the provider package. The plaintext exists only
// transiently inside this function and the result is a Redacted like any other,
// redacted through every fmt/log/json/yaml path. Keeping this reveal here, in
// the package that owns redaction, is what lets each provider file keep its
// single documented unwrap site.
func Join(sep string, parts ...Redacted) Redacted {
	raw := make([]string, len(parts))
	for i, p := range parts {
		raw[i] = p.Reveal()
	}
	return Redacted(strings.Join(raw, sep))
}

// IsBlank reports whether the secret is empty or consists only of whitespace.
//
// A blank value is not a credential. It carries no authentication material, so
// accepting one can only produce an unauthenticated request that the remote
// side rejects — at first use, which for a certificate credential is the first
// issuance or renewal, weeks after the deploy that introduced it. Every gate in
// this project that used to compare against "" alone let "   " and "\n" through
// and failed exactly that late; this predicate is what those gates check now.
//
// It tests the value AFTER trimming but deliberately does NOT trim the stored
// secret. Rejecting a blank value cannot destroy anything an operator meant to
// supply, because a blank value holds no information. Trimming a value like
// " abc " is a different act: it silently rewrites a secret the operator
// supplied, on a guess about which bytes were intended, and this project does
// not mutate secrets it was given. Such a value is accepted here unchanged and
// fails, if it is wrong, at the remote API — visibly, and with the operator's
// own bytes intact.
//
// Whitespace is Unicode whitespace as [unicode.IsSpace] defines it, which
// covers ASCII space and tab, NEL (U+0085), NBSP (U+00A0) and the Unicode Zs
// spaces including U+3000. It does NOT cover the zero-width space (U+200B),
// which Unicode classes as a format character rather than whitespace; a
// credential of only zero-width characters is not blank by this definition.
//
// Reveal is called on the value but nothing is returned from it: the result is
// a bool, so no caller can obtain plaintext through this method.
func (r Redacted) IsBlank() bool { return strings.TrimSpace(string(r)) == "" }

// String implements fmt.Stringer.
func (r Redacted) String() string { return redactedMarker }

// GoString implements fmt.GoStringer so that the %#v verb also redacts.
func (r Redacted) GoString() string { return redactedMarker }

// Format implements fmt.Formatter. It takes precedence over String and
// GoString for every verb (%v, %s, %q, %#v, %d, ...), which is what catches the
// realistic leak path: a Redacted field printed as part of a surrounding struct
// with %v/%+v/%#v.
func (r Redacted) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(redactedMarker))
}

// MarshalJSON implements json.Marshaler. It returns the quoted JSON string
// "[REDACTED]" (with quotes) so the output remains valid JSON.
func (r Redacted) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redactedMarker + `"`), nil
}

// MarshalText implements encoding.TextMarshaler.
func (r Redacted) MarshalText() ([]byte, error) {
	return []byte(redactedMarker), nil
}

// MarshalYAML implements yaml.Marshaler for gopkg.in/yaml.v3.
func (r Redacted) MarshalYAML() (any, error) {
	return redactedMarker, nil
}

// LogValue implements slog.LogValuer so structured logging redacts the value
// when a Redacted is passed directly as an attribute value.
func (r Redacted) LogValue() slog.Value {
	return slog.StringValue(redactedMarker)
}

// --- Ref redaction ------------------------------------------------------
//
// A Ref is not itself a secret: it is supposed to name one ("env:VALLET_PG_DSN").
// But the realistic operator error is pasting the secret *into* a *_ref field --
// a Postgres DSN like "postgres://user:pass@host/db" is syntactically a valid
// scheme:opaque reference, so it survives config validation and then reaches
// exactly the code paths that format a reference into an error or a log line.
// Rendering a Ref therefore redacts the opaque half unconditionally, so that a
// future %v/%q/slog use of a Ref is safe by construction rather than by every
// caller remembering.
//
// Scheme-echo policy: the scheme is preserved in the rendered form. It is the
// key diagnostic -- seeing "postgres:[REDACTED]" tells an operator immediately
// that they pasted a DSN rather than a reference to one -- and for every
// supported scheme ("env", "file") it is a fixed, public constant. schemeShaped
// additionally filters out text that is not identifier-shaped, so a pasted PEM
// block or prose does not have its first colon-delimited chunk echoed.
//
// Accepted residual risk: schemeShaped does NOT make the echo provably safe.
// A pasted "user:pass" credential pair is identifier-shaped and would surface
// the *username*. That is accepted deliberately: the credential half stays
// redacted, so the leaked fragment is not usable on its own, a username alone is
// low severity, and losing the scheme would leave the operator with an error
// they cannot act on. The sensitive half is never echoed under any input.
//
// Note that these methods only govern *rendering*. An explicit string(ref)
// conversion bypasses them by design, because some callers legitimately need
// the real reference (a provider must receive the opaque part to resolve it).
// Such conversions must never be handed to a formatter or logger.

// maxSchemeLen bounds an echoed scheme. Real schemes are short; anything longer
// is pasted content rather than a scheme, and is redacted whole.
const maxSchemeLen = 32

// schemeShaped reports whether s looks like a URI scheme (RFC 3986: an ASCII
// letter followed by letters, digits, '+', '-' or '.') and is short enough to
// be a scheme rather than pasted payload.
func schemeShaped(s string) bool {
	if s == "" || len(s) > maxSchemeLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

// redacted returns the display form of a reference: the scheme preserved and
// the opaque part replaced by the redaction marker ("env:[REDACTED]"). A
// reference with no parseable, identifier-shaped scheme renders as the bare
// marker. This is the single place the render policy lives; every Ref rendering
// method and every error message in this package goes through it.
func (r Ref) redacted() string {
	scheme, _, ok := r.split()
	if !ok || !schemeShaped(scheme) {
		return redactedMarker
	}
	return scheme + ":" + redactedMarker
}

// String implements fmt.Stringer.
func (r Ref) String() string { return r.redacted() }

// GoString implements fmt.GoStringer so that the %#v verb also redacts.
func (r Ref) GoString() string { return r.redacted() }

// Format implements fmt.Formatter. It takes precedence over String and GoString
// for every verb, which is what catches the realistic leak path: a Ref printed
// as part of a surrounding config struct with %v/%+v/%#v.
func (r Ref) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(r.redacted()))
}

// MarshalJSON implements json.Marshaler. Besides json.Marshal itself this
// covers slog's JSONHandler, which marshals a struct field rather than
// consulting LogValue: without it, a Ref inside a struct logged via
// slog.Any("config", cfg) would still render in full.
func (r Ref) MarshalJSON() ([]byte, error) {
	return []byte(`"` + r.redacted() + `"`), nil
}

// MarshalText implements encoding.TextMarshaler.
func (r Ref) MarshalText() ([]byte, error) {
	return []byte(r.redacted()), nil
}

// MarshalYAML implements yaml.Marshaler for gopkg.in/yaml.v3.
//
// Redacting on marshal is safe here because nothing in this project serializes
// a Config back out; there is no config-dump path whose fidelity this could
// break. Code that ever needs to write a real reference back to disk must use
// string(ref) explicitly rather than relying on marshaling.
func (r Ref) MarshalYAML() (any, error) {
	return r.redacted(), nil
}

// LogValue implements slog.LogValuer so structured logging redacts a Ref passed
// directly as an attribute value.
func (r Ref) LogValue() slog.Value {
	return slog.StringValue(r.redacted())
}
