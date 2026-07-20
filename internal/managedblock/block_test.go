package managedblock

import (
	"errors"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/keys"
)

const (
	begin = BeginMarker + "\n"
	end   = EndMarker + "\n"
)

// testBlock is a stand-in managed block: using a fixed synthetic body keeps the
// merge assertions about byte placement rather than key serialization.
const testBlock = begin + "NEWKEY\n" + end

func TestMergeMarkerStates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		existing string
		want     string
		wantErr  error
	}{
		{
			name:     "empty file appends the block",
			existing: "",
			want:     testBlock,
		},
		{
			name:     "file without trailing newline gains one separator byte",
			existing: "ssh-ed25519 AAAA user@host",
			want:     "ssh-ed25519 AAAA user@host\n" + testBlock,
		},
		{
			name:     "file with trailing newline is appended to verbatim",
			existing: "# mine\nssh-ed25519 AAAA user@host\n",
			want:     "# mine\nssh-ed25519 AAAA user@host\n" + testBlock,
		},
		{
			name:     "block in the middle is replaced in place",
			existing: "before\n" + begin + "OLD1\nOLD2\n" + end + "after\n",
			want:     "before\n" + testBlock + "after\n",
		},
		{
			name:     "surrounding CRLF and blank lines survive",
			existing: "a\r\n\r\n" + begin + "OLD\n" + end + "\r\nb\r\n",
			want:     "a\r\n\r\n" + testBlock + "\r\nb\r\n",
		},
		{
			name:     "markers with CRLF terminators match",
			existing: "x\n" + BeginMarker + "\r\nOLD\n" + EndMarker + "\r\ny\n",
			want:     "x\n" + testBlock + "y\n",
		},
		{
			name:     "markers with surrounding horizontal whitespace match",
			existing: "  " + BeginMarker + " \t\nOLD\n\t" + EndMarker + "  \n",
			want:     testBlock,
		},
		{
			name:     "unterminated END marker on the last line still matches",
			existing: begin + "OLD\n" + EndMarker,
			want:     testBlock,
		},
		{
			name:     "empty block is replaced like any other",
			existing: "keep\n" + begin + end,
			want:     "keep\n" + testBlock,
		},
		{
			name:     "marker text inside a key comment is not a marker",
			existing: "ssh-ed25519 AAAA " + BeginMarker + "\n",
			want:     "ssh-ed25519 AAAA " + BeginMarker + "\n" + testBlock,
		},
		{
			name:     "END before BEGIN fails closed",
			existing: end + "x\n" + begin,
			wantErr:  ErrMalformedBlock,
		},
		{
			name:     "BEGIN with no END fails closed",
			existing: "x\n" + begin + "orphan\n",
			wantErr:  ErrMalformedBlock,
		},
		{
			name:     "END with no BEGIN fails closed",
			existing: "x\n" + end,
			wantErr:  ErrMalformedBlock,
		},
		{
			name:     "duplicate blocks fail closed",
			existing: begin + "a\n" + end + begin + "b\n" + end,
			wantErr:  ErrMalformedBlock,
		},
		{
			name:     "duplicate BEGIN with one END fails closed",
			existing: begin + begin + "a\n" + end,
			wantErr:  ErrMalformedBlock,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Merge([]byte(tc.existing), []byte(testBlock))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Merge error = %v, want %v", err, tc.wantErr)
				}
				if got != nil {
					t.Fatalf("Merge returned %q alongside an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Merge: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("Merge =\n%q\nwant\n%q", got, tc.want)
			}
		})
	}
}

// TestMergePreservesForeignContentByteForByte is the central safety property:
// a user's own keys must survive a replacement unchanged, since losing one
// locks them out of the server.
func TestMergePreservesForeignContentByteForByte(t *testing.T) {
	t.Parallel()

	foreignHead := "#\tuser's own keys\r\n\n" + keyLine(t, 1, "laptop") + "\n\n"
	foreignTail := "\n# tail comment\n" + keyLine(t, 2, "phone") + " \t\n\n"
	existing := foreignHead + begin + "STALE\n" + end + foreignTail

	got, err := Merge([]byte(existing), []byte(testBlock))
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if !strings.HasPrefix(string(got), foreignHead) {
		t.Fatalf("content before the block was modified: %q", got)
	}
	if !strings.HasSuffix(string(got), foreignTail) {
		t.Fatalf("content after the block was modified: %q", got)
	}
	if want := foreignHead + testBlock + foreignTail; string(got) != want {
		t.Fatalf("Merge =\n%q\nwant\n%q", got, want)
	}
}

func TestMergeIsIdempotent(t *testing.T) {
	t.Parallel()

	for _, existing := range []string{"", "no newline", "own\n", "a\r\n" + begin + "x\n" + end + "b\n"} {
		once, err := Merge([]byte(existing), []byte(testBlock))
		if err != nil {
			t.Fatalf("Merge(%q): %v", existing, err)
		}
		twice, err := Merge(once, []byte(testBlock))
		if err != nil {
			t.Fatalf("second Merge(%q): %v", existing, err)
		}
		if string(twice) != string(once) {
			t.Fatalf("Merge is not idempotent for %q:\n%q\n%q", existing, once, twice)
		}
	}
}

func TestRenderCanonicalizes(t *testing.T) {
	t.Parallel()

	// Extra internal whitespace and a trailing newline in the input must not
	// reach the file: the line is rebuilt from the parsed key.
	raw := keyLine(t, 7, "laptop") + "\n"
	got, err := Render([]string{raw})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	want := begin + keyLine(t, 7, "laptop") + "\n" + end
	if string(got) != want {
		t.Fatalf("Render =\n%q\nwant\n%q", got, want)
	}
}

func TestRenderEmptyKeySetYieldsEmptyBlock(t *testing.T) {
	t.Parallel()

	got, err := Render(nil)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if string(got) != begin+end {
		t.Fatalf("Render = %q, want %q", got, begin+end)
	}
}

// TestRenderRejectsHostileInput covers the injection attempts a compromised or
// spoofed server could attempt. Each must fail closed with nothing rendered.
func TestRenderRejectsHostileInput(t *testing.T) {
	t.Parallel()

	valid := keyLine(t, 3, "ok")
	tests := []struct {
		name  string
		input string
		want  error
	}{
		{"command option is remote code execution", `command="rm -rf /" ` + valid, keys.ErrOptionsPresent},
		{"permitopen option", "permitopen=\"localhost:25\" " + valid, keys.ErrOptionsPresent},
		{"embedded newline smuggles a second key", valid + "\n" + valid, keys.ErrMultipleKeys},
		{"embedded carriage return", valid + "\r" + valid, keys.ErrMultipleKeys},
		{"forged BEGIN marker", BeginMarker, keys.ErrMalformed},
		{"forged END marker", EndMarker, keys.ErrMalformed},
		{"NUL byte", valid + "\x00", keys.ErrBadComment},
		{"blank line", "   ", keys.ErrMalformed},
		{"private key material", "-----BEGIN OPENSSH PRIVATE KEY-----", keys.ErrPrivateKey},
		{"unparseable key body", "ssh-dss AAAAB3NzaC1kc3M= user", keys.ErrMalformed},
		{"oversized line", strings.Repeat("A", keys.MaxLineBytes+1), keys.ErrTooLarge},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := Render([]string{valid, tc.input})
			if !errors.Is(err, tc.want) {
				t.Fatalf("Render error = %v, want %v", err, tc.want)
			}
			if got != nil {
				t.Fatalf("Render returned %q alongside an error", got)
			}
			if !strings.Contains(err.Error(), "key 2") {
				t.Fatalf("error does not identify the offending entry: %v", err)
			}
			if strings.Contains(err.Error(), tc.input) && tc.input != "" {
				t.Fatalf("error echoed the input: %v", err)
			}
		})
	}
}

// TestRenderRejectsCommentThatWouldForgeAMarker guards the one place attacker
// text is carried through: the key comment. It can never make the line a
// marker, because a marker must start the line.
func TestRenderRejectsCommentThatWouldForgeAMarker(t *testing.T) {
	t.Parallel()

	got, err := Render([]string{keyLine(t, 4, EndMarker)})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if _, _, _, err := locate(got); err != nil {
		t.Fatalf("a marker-shaped comment made the block ambiguous: %v", err)
	}
	start, stop, found, err := locate(got)
	if err != nil || !found || start != 0 || stop != len(got) {
		t.Fatalf("locate(%q) = %d,%d,%v,%v", got, start, stop, found, err)
	}
}

// TestCheckEmitted exercises the last-gate assertion directly. Canonical
// reconstruction already makes these states unreachable through Render, so the
// only way to prove the gate works is to call it.
func TestCheckEmitted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		line string
		ok   bool
	}{
		{"canonical line", keyLine(t, 5, "ok") + "\n", true},
		{"missing terminator", keyLine(t, 5, "ok"), false},
		{"embedded newline", "ssh-ed25519 AAAA\nssh-ed25519 BBBB\n", false},
		{"embedded carriage return", "ssh-ed25519 AAAA\rx\n", false},
		{"embedded NUL", "ssh-ed25519 AAAA\x00\n", false},
		{"forged BEGIN marker", BeginMarker + "\n", false},
		{"forged END marker", "  " + EndMarker + "\t\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkEmitted(tc.line)
			if tc.ok && err != nil {
				t.Fatalf("checkEmitted(%q) = %v, want nil", tc.line, err)
			}
			if !tc.ok && !errors.Is(err, ErrMalformedBlock) {
				t.Fatalf("checkEmitted(%q) = %v, want ErrMalformedBlock", tc.line, err)
			}
		})
	}
}

func TestLineSpansTileTheInput(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"", "a", "a\n", "a\nb", "\n\n", "a\r\nb\r\n"} {
		spans := lineSpans([]byte(in))
		off := 0
		for _, s := range spans {
			if s.start != off {
				t.Fatalf("lineSpans(%q) has a gap at %d", in, s.start)
			}
			off = s.end
		}
		if off != len(in) {
			t.Fatalf("lineSpans(%q) covers %d of %d bytes", in, off, len(in))
		}
	}
}

// FuzzMerge asserts the two properties that matter under adversarial file
// contents: Merge never panics, and a successful merge is a fixed point.
func FuzzMerge(f *testing.F) {
	for _, s := range []string{"", "a", "a\n", begin + end, end + begin, begin, end,
		"x\r\n" + begin + "y\n" + end, "ssh-ed25519 AAAA " + BeginMarker} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, existing []byte) {
		once, err := Merge(existing, []byte(testBlock))
		if err != nil {
			if !errors.Is(err, ErrMalformedBlock) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		twice, err := Merge(once, []byte(testBlock))
		if err != nil {
			t.Fatalf("merge of a merged file failed: %v", err)
		}
		if string(twice) != string(once) {
			t.Fatalf("merge is not a fixed point:\n%q\n%q", once, twice)
		}
	})
}
