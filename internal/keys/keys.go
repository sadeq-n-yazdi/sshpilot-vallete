package keys

import (
	"bytes"
	"crypto/rsa"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// ParsedKey is a validated SSH public key. It maps one-to-one onto the
// public-key fields of domain.PublicKey. Blob is always the re-serialized wire
// form (ssh.PublicKey.Marshal), never the caller's decoded bytes.
type ParsedKey struct {
	Algorithm   domain.Algorithm
	Blob        []byte
	Comment     string
	Fingerprint string
	BitLen      int
}

// privateKeyMarkers are case-insensitive substrings whose presence indicates
// private key material. They are matched before any parsing so private keys are
// rejected without being processed, echoed, or stored (ADR-0002).
var privateKeyMarkers = []string{
	"private key",         // BEGIN {OPENSSH,RSA,EC,DSA,ENCRYPTED} PRIVATE KEY
	"putty-user-key-file", // PuTTY .ppk private key
}

// containsPrivateKeyMaterial reports whether raw carries any private-key
// marker. The scan is case-insensitive and never retains or returns input.
func containsPrivateKeyMaterial(raw []byte) bool {
	lower := bytes.ToLower(raw)
	for _, m := range privateKeyMarkers {
		if bytes.Contains(lower, []byte(m)) {
			return true
		}
	}
	return false
}

// Parse validates a single SSH public key line and returns its canonical form.
// It is strict: exactly one key, no authorized_keys options, no trailing
// content, an allowlisted algorithm, and sufficient strength. Every error is a
// package sentinel; none reflects the input bytes.
func Parse(raw []byte) (ParsedKey, error) {
	if len(raw) > MaxLineBytes {
		return ParsedKey{}, ErrTooLarge
	}
	if containsPrivateKeyMaterial(raw) {
		return ParsedKey{}, ErrPrivateKey
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return ParsedKey{}, ErrMalformed
	}

	// Enforce a single line: strip exactly one trailing newline, then reject
	// any remaining line break. This defeats ssh.ParseAuthorizedKey's habit of
	// skipping leading unparseable lines to find a later valid one.
	line := raw
	if n := len(line); n > 0 && line[n-1] == '\n' {
		line = line[:n-1]
		if n2 := len(line); n2 > 0 && line[n2-1] == '\r' {
			line = line[:n2-1]
		}
	}
	if bytes.ContainsAny(line, "\n\r") {
		return ParsedKey{}, ErrMultipleKeys
	}
	if t := bytes.TrimLeft(line, " \t"); len(t) > 0 && t[0] == '#' {
		return ParsedKey{}, ErrMalformed
	}

	k, err := parseKeyLine(line)
	if err != nil {
		return ParsedKey{}, err
	}
	return k, nil
}

// parseKeyLine parses one authorized_keys entry: it rejects options and any
// trailing content, then normalizes via finalize. It is shared by Parse and the
// batch path, which each guarantee a single physical line before calling it.
// The trailing-content (rest) rejection is defense in depth: those callers strip
// line breaks first, but the check ensures a multi-line argument can never yield
// a silently-accepted second key.
func parseKeyLine(line []byte) (ParsedKey, error) {
	pub, comment, options, rest, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		return ParsedKey{}, ErrMalformed
	}
	if len(options) > 0 {
		return ParsedKey{}, ErrOptionsPresent
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return ParsedKey{}, ErrMultipleKeys
	}
	return finalize(pub, comment)
}

// finalize applies the algorithm allowlist, strength check, and normalization
// shared by Parse and the batch path, then enforces the output invariant.
func finalize(pub ssh.PublicKey, comment string) (ParsedKey, error) {
	alg := domain.Algorithm(pub.Type())
	if !alg.IsValid() {
		return ParsedKey{}, ErrUnsupportedAlgorithm
	}

	bitLen, err := strength(alg, pub)
	if err != nil {
		return ParsedKey{}, err
	}

	k := ParsedKey{
		Algorithm:   alg,
		Blob:        pub.Marshal(),
		Comment:     strings.TrimSpace(comment),
		Fingerprint: ssh.FingerprintSHA256(pub),
		BitLen:      bitLen,
	}
	// Defense in depth: every returned ParsedKey must satisfy domain
	// validation. checkInvariants both validates the comment and guarantees
	// this for callers.
	return k, checkInvariants(k)
}

// checkInvariants verifies that a ParsedKey satisfies the domain validators.
// It is the single source of truth for the guarantee that Parse and
// ParseAuthorizedKeys never emit a key that domain validation would reject.
func checkInvariants(k ParsedKey) error {
	if !k.Algorithm.IsValid() {
		return ErrUnsupportedAlgorithm
	}
	if domain.ValidateFingerprint(k.Fingerprint) != nil {
		return ErrMalformed
	}
	if domain.ValidateKeyComment(k.Comment) != nil {
		return ErrBadComment
	}
	return nil
}

// strength returns the key's bit length and rejects RSA keys below the minimum
// modulus size. Only RSA touches CryptoPublicKey; the assertion is checked so a
// surprising key type yields ErrMalformed rather than a panic.
func strength(alg domain.Algorithm, pub ssh.PublicKey) (int, error) {
	switch alg {
	case domain.AlgRSA:
		cpk, ok := pub.(ssh.CryptoPublicKey)
		if !ok {
			return 0, ErrMalformed
		}
		// A typed-nil *rsa.PublicKey wrapped in the interface would pass the
		// assertion with ok == true; guard against it so rpk.N below can never
		// nil-panic on a malformed key.
		rpk, ok := cpk.CryptoPublicKey().(*rsa.PublicKey)
		if !ok || rpk == nil {
			return 0, ErrMalformed
		}
		n := rpk.N.BitLen()
		if n < domain.MinRSABits {
			return 0, ErrWeakKey
		}
		return n, nil
	case domain.AlgECDSA384:
		return 384, nil
	case domain.AlgECDSA521:
		return 521, nil
	case domain.AlgEd25519, domain.AlgECDSA256, domain.AlgSKEd25519, domain.AlgSKECDSA256:
		return 256, nil
	default:
		return 0, ErrUnsupportedAlgorithm
	}
}
