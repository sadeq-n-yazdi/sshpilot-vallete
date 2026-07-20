package publish

import (
	"context"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// forgedKeyLine is a complete, valid authorized_keys entry with a permissive
// option prefix. If a comment could smuggle a newline into the output, this is
// what an attacker would append: a second entry granting a key they control,
// with command restrictions disabled.
const forgedKeyLine = `no-pty,command="/bin/sh" ssh-ed25519 ` +
	`AAAAC3NzaC1lZDI1NTE5AAAAIJm7t7g6Uu1PL7lxQvfLh7dGxzZBLcYqLxYUlD8HpXTd attacker@evil`

// TestCommentCannotInjectAnAuthorizedKeysLine is the single most important test
// in this slice.
//
// A key comment is attacker-influenced text: it comes from whatever the user
// put after their key. authorized_keys is a newline-delimited format with no
// escaping, so a comment that survived into output carrying a line break would
// not merely look odd — it would BE an additional authorized entry, and the
// attacker would choose its contents. That is remote code execution on every
// host consuming the file.
//
// F8a rejects such comments at ingest, so these rows cannot be created through
// the write path. They are forged directly into storage here precisely because
// the question under test is what the PUBLISH path does when its input
// assumptions have already been violated — a defense that is only ever
// exercised by the layer above it is not a defense.
func TestCommentCannotInjectAnAuthorizedKeysLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		comment string
	}{
		{name: "line feed", comment: "ok\n" + forgedKeyLine},
		{name: "carriage return", comment: "ok\r" + forgedKeyLine},
		{name: "crlf", comment: "ok\r\n" + forgedKeyLine},
		{name: "bare line feed", comment: "first\nsecond"},
		{name: "leading newline", comment: "\n" + forgedKeyLine},
		{name: "trailing newline", comment: forgedKeyLine + "\n"},
		{name: "embedded null", comment: "ok\x00" + forgedKeyLine},
		{name: "options prefix only", comment: `no-pty,command="/bin/sh"`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			alice := f.seedOwner("alice")
			keyID := f.addKey(alice.OwnerID, alice.KeySetID, "harmless")

			// Overwrite the stored comment with the poisoned value, bypassing
			// every validator that would normally stand in the way.
			f.exec(`UPDATE public_keys SET comment = ? WHERE id = ?`, tc.comment, string(keyID))

			body, err := f.svc.Resolve(context.Background(), "alice", "")

			// Whatever happens, the forged entry must not be published. That is
			// the invariant; the error is merely how this implementation
			// upholds it.
			if strings.Contains(string(body), "attacker@evil") {
				t.Fatalf("FORGED ENTRY PUBLISHED: %q", body)
			}

			// No published body may ever contain more entries than the set has
			// members, whatever a comment contains.
			if got := lines(string(body)); len(got) > 1 {
				t.Fatalf("body has %d lines from a single-key set: %q", len(got), body)
			}

			// Whatever survived must still parse as exactly one option-free
			// entry. This is the assertion that actually matters for a comment
			// with no line break: text sitting in the comment position cannot
			// become an option, because options only precede the key type, and
			// this proves sshd would read it that way rather than trusting the
			// absence of a substring.
			for _, line := range lines(string(body)) {
				_, _, options, rest, parseErr := ssh.ParseAuthorizedKey([]byte(line))
				if parseErr != nil {
					t.Fatalf("published line does not parse: %v", parseErr)
				}
				if len(options) != 0 {
					t.Fatalf("published line carries options %v: %q", options, line)
				}
				if len(rest) != 0 {
					t.Fatalf("published line holds a second entry: %q", rest)
				}
			}

			if !strings.ContainsAny(tc.comment, "\n\r") {
				// No line break, so no entry can be forged: the poisoned text
				// is confined to the comment field, which the parse check above
				// has just confirmed. Nothing further to assert.
				return
			}

			// A line-break-bearing comment must fail the whole request. It must
			// NOT be reported as ErrNotFound: that would map to a 404 and make
			// a corrupted row look to an operator like an empty account, hiding
			// the corruption instead of surfacing it.
			if err == nil {
				t.Fatalf("Resolve succeeded with a line-break comment; body = %q", body)
			}
			if errors.Is(err, ErrNotFound) {
				t.Errorf("corrupted row reported as ErrNotFound; it must surface as an internal fault")
			}
			if body != nil {
				t.Errorf("body = %q, want nil on failure", body)
			}
		})
	}
}

// TestPoisonedCommentDoesNotYieldAPartialBody guards the choice to fail the
// whole response rather than skip the offending key.
//
// Silently dropping a key would emit a shorter authorized_keys file that
// nothing downstream could distinguish from a legitimately shorter one — a
// lockout, or a stale key list, presented as a success.
func TestPoisonedCommentDoesNotYieldAPartialBody(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	alice := f.seedOwner("alice")
	good := f.addKey(alice.OwnerID, alice.KeySetID, "good-one")
	poisoned := f.addKey(alice.OwnerID, alice.KeySetID, "poison-me")
	f.addKey(alice.OwnerID, alice.KeySetID, "good-two")

	f.exec(`UPDATE public_keys SET comment = ? WHERE id = ?`, "x\n"+forgedKeyLine, string(poisoned))

	body, err := f.svc.Resolve(context.Background(), "alice", "")
	if err == nil {
		t.Fatalf("Resolve succeeded despite a poisoned key; body = %q", body)
	}
	if body != nil {
		t.Fatalf("a partial body was returned: %q", body)
	}

	// Sanity: the untouched keys are fine on their own, so the failure is
	// attributable to the poisoned row and not to the fixture.
	f.exec(`UPDATE public_keys SET comment = 'clean' WHERE id = ?`, string(poisoned))
	fixed := f.resolve("alice", "")
	if got := lines(fixed); len(got) != 3 {
		t.Errorf("after cleaning, got %d lines, want 3", len(got))
	}
	_ = good
}

// TestForgedKeyLineIsGenuinelyDangerous asserts the fixture's premise: the
// string the tests search for really does parse as a working authorized_keys
// entry with options. Without this, a typo could turn every assertion above
// into a test that searches for something harmless and always passes.
func TestForgedKeyLineIsGenuinelyDangerous(t *testing.T) {
	t.Parallel()

	_, comment, options, _, err := ssh.ParseAuthorizedKey([]byte(forgedKeyLine))
	if err != nil {
		t.Fatalf("the forged line does not parse, so the injection tests prove nothing: %v", err)
	}
	if len(options) == 0 {
		t.Error("the forged line carries no options")
	}
	if comment != "attacker@evil" {
		t.Errorf("comment = %q, want attacker@evil", comment)
	}
}
