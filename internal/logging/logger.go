package logging

import (
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
)

// levels is the canonical name->level table. It lives here, not in
// internal/config, so that validation and construction can never disagree:
// config imports this package to validate the configured name, and this package
// uses the same map to parse it. Two switch statements in two packages would
// drift, and the direction they drift in is "validation passes, parsing falls
// back", which is the silent-default failure this package must not have.
var levels = map[string]slog.Level{
	"debug": slog.LevelDebug,
	"info":  slog.LevelInfo,
	"warn":  slog.LevelWarn,
	"error": slog.LevelError,
}

// formats is the canonical set of output encodings. JSON is the ADR-0025
// default; text exists for local development, where a human reads the stream
// directly. Redaction is applied identically to both -- it runs before the
// encoder, so the choice of encoder cannot weaken it.
var formats = map[string]struct{}{
	"json": {},
	"text": {},
}

// Levels returns the accepted level names in a stable order, for error messages
// and documentation.
func Levels() []string { return sortedKeysOf(levels) }

// Formats returns the accepted format names in a stable order.
func Formats() []string { return sortedKeysOf(formats) }

func sortedKeysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ParseLevel maps a configured level name onto slog.
//
// It FAILS CLOSED: an unrecognized name is an error, never a default. The
// tempting alternative -- fall back to info so that "losing logs is not a
// reason to refuse to start" -- is wrong in both directions. Falling back
// quietly to a more verbose level than intended turns a typo into a disclosure:
// an operator who wrote "warning" instead of "warn" asked for less logging and
// would silently get debug-or-info volume, shipped to wherever logs go. Falling
// back to a quieter level loses the record of an incident. Either way the
// operator believes a level is in force that is not, and finds out only from
// the consequences. Refusing to start is the one outcome that cannot be
// misread.
func ParseLevel(name string) (slog.Level, error) {
	level, ok := levels[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return 0, fmt.Errorf("unknown log level %q (want one of: %s)", name, strings.Join(Levels(), ", "))
	}
	return level, nil
}

// ValidateFormat reports whether the configured output format is supported,
// failing closed for the same reason as ParseLevel.
func ValidateFormat(name string) error {
	if _, ok := formats[strings.ToLower(strings.TrimSpace(name))]; !ok {
		return fmt.Errorf("unknown log format %q (want one of: %s)", name, strings.Join(Formats(), ", "))
	}
	return nil
}

// New builds the application logger: the configured encoder, wrapped in the
// redaction filter.
//
// The wrapping order is the point. RedactHandler is the OUTER handler, so every
// attribute is filtered before the encoder ever sees it; there is no path that
// reaches the JSON writer unfiltered. Returning the encoder directly on any
// error path would be an unfiltered logger, so New returns an error instead and
// leaves the caller nothing to accidentally use.
func New(w io.Writer, level, format string, extraAllowed ...string) (*slog.Logger, error) {
	lvl, err := ParseLevel(level)
	if err != nil {
		return nil, err
	}
	if err := ValidateFormat(format); err != nil {
		return nil, err
	}

	opts := &slog.HandlerOptions{Level: lvl}
	var enc slog.Handler
	if strings.EqualFold(strings.TrimSpace(format), "text") {
		enc = slog.NewTextHandler(w, opts)
	} else {
		enc = slog.NewJSONHandler(w, opts)
	}
	return slog.New(NewRedactHandler(enc, extraAllowed...)), nil
}
