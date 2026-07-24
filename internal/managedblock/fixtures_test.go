package managedblock

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// keyLine builds a deterministic ed25519 authorized_keys line (no trailing
// newline) from a one-byte seed, optionally with a comment. Deterministic keys
// keep the exact-bytes assertions readable and the tests fast.
func keyLine(t testing.TB, seed byte, comment string) string {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("new public key: %v", err)
	}
	line := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pub)), "\n")
	if comment != "" {
		line += " " + comment
	}
	return line
}
