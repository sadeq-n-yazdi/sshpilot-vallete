// Package managedblock maintains a delimited, service-owned region inside an
// existing authorized_keys file.
//
// # Marker format
//
// The managed region is delimited by two fixed comment lines:
//
//	# >>> sshpilot-vallet managed keys BEGIN >>>
//	<one canonical authorized_keys line per published key>
//	# <<< sshpilot-vallet managed keys END <<<
//
// A line counts as a marker only when the whole line, after its terminator and
// any surrounding spaces or tabs are stripped, equals the marker exactly. A
// marker string appearing inside a key comment is therefore a suffix of a key
// line, not a whole line, and never matches.
//
// # Ownership and preservation
//
// Everything outside the two marker lines is copied byte for byte: line
// terminators (including CRLF), blank lines, comments, the user's own keys, and
// the presence or absence of a trailing newline all survive unchanged. The
// replacement is a byte-offset splice, never a split-and-rejoin.
//
// There is exactly one deliberate exception. When no block is present and the
// file does not end with a newline, appending the block requires writing a
// single "\n" separator first; without it the block's BEGIN marker would be
// glued onto the user's last key line. That one added byte is the only
// modification this package ever makes outside the markers.
//
// Content the user places *inside* the markers is not preserved: the region is
// owned by this package and is regenerated on every apply.
//
// # Fail-closed marker states
//
// The marker state reduces to counting whole-line matches:
//
//   - zero BEGIN and zero END: no block yet, append one.
//   - exactly one BEGIN and exactly one END, END after BEGIN: splice in place,
//     keeping the block's position and all surrounding bytes.
//   - anything else: refuse with ErrMalformedBlock and write nothing.
//
// That last rule covers duplicate blocks, END before BEGIN, BEGIN with no END,
// and END with no BEGIN. Losing a user's own key locks them out of their
// server, so an ambiguous file is never "recovered" by rewriting it; the
// operator is told to fix the markers by hand.
//
// # Trust model
//
// The published key set is untrusted input. Every line is re-parsed by
// internal/keys and re-emitted from the parsed algorithm, wire blob, and
// validated comment, so authorized_keys options, embedded line breaks, NUL
// bytes, weak or non-allowlisted algorithms, and forged marker lines are all
// structurally unrepresentable in the rendered block.
package managedblock

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/keys"
)

// Marker lines delimiting the managed region. They are fixed strings, not
// configuration: a mismatch between the writer and a previously written file
// would orphan a block and duplicate keys.
const (
	// BeginMarker opens the managed region.
	BeginMarker = "# >>> sshpilot-vallet managed keys BEGIN >>>"
	// EndMarker closes the managed region.
	EndMarker = "# <<< sshpilot-vallet managed keys END <<<"
)

// MaxFileBytes bounds the authorized_keys file this package will read. It
// matches the batch ceiling in internal/keys.
const MaxFileBytes = keys.MaxFileBytes

// ErrMalformedBlock indicates the target file's marker state is ambiguous.
// The file is left untouched; the operator must repair the markers by hand.
var ErrMalformedBlock = fmt.Errorf("managedblock: ambiguous BEGIN/END markers; refusing to modify the file")

// emitLine is the canonicalizer that turns a parsed key back into an
// authorized_keys line. It is indirect so the gate below it (checkEmitted) can
// be exercised against a canonicalizer that misbehaves: that gate is the last
// thing standing between a regression in reconstruction and a forged marker or
// smuggled option reaching the file. Production code never reassigns it.
var emitLine = keys.AuthorizedKeyLine

// Render builds the managed block from a published key set.
//
// Each entry is validated and canonicalized through internal/keys, so the
// emitted lines carry no options, no line breaks, and no attacker-chosen
// prefix. An empty key set yields an empty block (BEGIN immediately followed
// by END) rather than no block at all, which keeps the result idempotent and
// leaves the region visible in the file.
//
// Errors identify the offending entry by position only; input bytes are never
// echoed.
func Render(pubkeys []string) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(BeginMarker)
	buf.WriteByte('\n')
	for i, raw := range pubkeys {
		k, err := keys.Parse([]byte(raw))
		if err != nil {
			return nil, fmt.Errorf("managedblock: key %d: %w", i+1, err)
		}
		line, err := emitLine(k)
		if err != nil {
			return nil, fmt.Errorf("managedblock: key %d: %w", i+1, err)
		}
		if err := checkEmitted(line); err != nil {
			return nil, fmt.Errorf("managedblock: key %d: %w", i+1, err)
		}
		buf.WriteString(line)
	}
	buf.WriteString(EndMarker)
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

// checkEmitted is the last gate before a line enters the block: it must be a
// single terminated line and must not itself be a marker. Canonical
// reconstruction already makes both impossible, so this is defense in depth
// against a future change to the reconstruction path.
func checkEmitted(line string) error {
	if !strings.HasSuffix(line, "\n") || strings.ContainsAny(line[:len(line)-1], "\n\r\x00") {
		return ErrMalformedBlock
	}
	if isMarker(line, BeginMarker) || isMarker(line, EndMarker) {
		return ErrMalformedBlock
	}
	return nil
}

// isMarker reports whether one physical line, terminator and surrounding
// horizontal whitespace stripped, is exactly the given marker.
func isMarker(line, marker string) bool {
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return strings.Trim(line, " \t") == marker
}

// span is the half-open byte range of one physical line, terminator included.
type span struct{ start, end int }

// lineSpans returns the byte span of every physical line in b. Spans tile b
// exactly, so any subrange can be spliced without reconstructing the rest.
func lineSpans(b []byte) []span {
	var spans []span
	for off := 0; off < len(b); {
		i := bytes.IndexByte(b[off:], '\n')
		if i < 0 {
			spans = append(spans, span{off, len(b)})
			break
		}
		spans = append(spans, span{off, off + i + 1})
		off += i + 1
	}
	return spans
}

// locate finds the managed block in existing. It returns the byte offsets of
// the start of the BEGIN line and of the first byte after the END line, or
// found=false when no block is present. Any ambiguous marker state is an
// error.
func locate(existing []byte) (start, stop int, found bool, err error) {
	var begins, ends []span
	for _, s := range lineSpans(existing) {
		line := string(existing[s.start:s.end])
		switch {
		case isMarker(line, BeginMarker):
			begins = append(begins, s)
		case isMarker(line, EndMarker):
			ends = append(ends, s)
		}
	}
	switch {
	case len(begins) == 0 && len(ends) == 0:
		return 0, 0, false, nil
	case len(begins) == 1 && len(ends) == 1 && ends[0].start > begins[0].start:
		return begins[0].start, ends[0].end, true, nil
	default:
		return 0, 0, false, ErrMalformedBlock
	}
}

// blockKeyCount returns the number of key lines inside the managed block of b,
// or 0 when b has no well-formed block. It counts only the lines between the
// BEGIN and END markers, skipping the markers themselves and any blank line, so
// keys elsewhere in the file are never counted. A malformed marker state counts
// as 0 here; Merge is the choke point that rejects such a file, so this is only
// ever consulted for a file whose markers Merge accepts.
func blockKeyCount(b []byte) int {
	start, stop, found, err := locate(b)
	if err != nil || !found {
		return 0
	}
	inner := b[start:stop]
	n := 0
	for _, s := range lineSpans(inner) {
		line := string(inner[s.start:s.end])
		if isMarker(line, BeginMarker) || isMarker(line, EndMarker) {
			continue
		}
		if strings.Trim(strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), " \t") == "" {
			continue
		}
		n++
	}
	return n
}

// Merge splices block into existing and returns the new file contents.
//
// When a well-formed block is present it is replaced where it stands. When no
// block is present the block is appended, preceded by a single "\n" only if
// existing does not already end with one. Every byte outside the block is
// carried over untouched.
func Merge(existing, block []byte) ([]byte, error) {
	start, stop, found, err := locate(existing)
	if err != nil {
		return nil, err
	}
	var out []byte
	if found {
		out = make([]byte, 0, start+len(block)+len(existing)-stop)
		out = append(out, existing[:start]...)
		out = append(out, block...)
		out = append(out, existing[stop:]...)
		return out, nil
	}
	out = make([]byte, 0, len(existing)+len(block)+1)
	out = append(out, existing...)
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		out = append(out, '\n')
	}
	out = append(out, block...)
	return out, nil
}
