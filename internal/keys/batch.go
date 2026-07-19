package keys

import (
	"bytes"
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// LineError reports a per-line failure from ParseAuthorizedKeys. Line is the
// 1-based line number, or 0 when the error applies to the whole submission
// (size limit or private-key material). Err is a package sentinel and never
// contains bytes from the input.
type LineError struct {
	Line int
	Err  error
}

// Error implements the error interface. It reports only the line number and the
// wrapped sentinel; it never reflects input bytes.
func (e LineError) Error() string {
	return "keys: line error: " + e.Err.Error()
}

// Unwrap exposes the wrapped sentinel for errors.Is / errors.As.
func (e LineError) Unwrap() error { return e.Err }

// ParseAuthorizedKeys validates a batch of SSH public keys, one per line. Blank
// lines and lines whose first non-space rune is '#' are skipped. Each remaining
// line is validated exactly as Parse validates a single key; failures are
// collected as LineError values with 1-based line numbers rather than aborting
// the batch.
//
// Two conditions reject the whole submission and return a single LineError with
// Line 0 and no parsed keys: the input exceeding MaxFileBytes, and any
// private-key material anywhere in the input. A key whose fingerprint duplicates
// an earlier accepted key in the same batch is surfaced (not silently deduped)
// as a LineError wrapping domain.ErrConflict on the later line.
func ParseAuthorizedKeys(raw []byte) ([]ParsedKey, []LineError) {
	if len(raw) > MaxFileBytes {
		return nil, []LineError{{Line: 0, Err: ErrTooLarge}}
	}
	if containsPrivateKeyMaterial(raw) {
		return nil, []LineError{{Line: 0, Err: ErrPrivateKey}}
	}

	var (
		keys []ParsedKey
		errs []LineError
		seen = make(map[string]struct{})
	)
	// Iterate line by line with IndexByte rather than bytes.Split: a 1MB input
	// of mostly newlines would otherwise allocate up to ~1M sub-slices at once.
	lineNo := 0
	for rest := raw; len(rest) > 0; {
		lineNo++
		var line []byte
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			line, rest = rest[:i], rest[i+1:]
		} else {
			line, rest = rest, nil
		}
		line = bytes.TrimRight(line, "\r")
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if t := bytes.TrimLeft(line, " \t"); t[0] == '#' {
			continue
		}
		// Enforce the per-line size cap here too: MaxFileBytes bounds the whole
		// submission, but without this a single line could still reach that
		// size and bypass the MaxLineBytes limit that Parse applies.
		if len(line) > MaxLineBytes {
			errs = append(errs, LineError{Line: lineNo, Err: ErrTooLarge})
			continue
		}

		k, err := parseKeyLine(line)
		if err != nil {
			errs = append(errs, LineError{Line: lineNo, Err: err})
			continue
		}
		if _, dup := seen[k.Fingerprint]; dup {
			errs = append(errs, LineError{Line: lineNo, Err: errDuplicate})
			continue
		}
		seen[k.Fingerprint] = struct{}{}
		keys = append(keys, k)
	}
	return keys, errs
}

// errDuplicate wraps domain.ErrConflict for a repeated fingerprint within a
// single batch. It is only ever surfaced inside a LineError.
var errDuplicate = fmt.Errorf("keys: duplicate key fingerprint in batch: %w", domain.ErrConflict)
