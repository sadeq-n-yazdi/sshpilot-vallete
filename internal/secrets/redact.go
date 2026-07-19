package secrets

import (
	"fmt"
	"log/slog"
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
