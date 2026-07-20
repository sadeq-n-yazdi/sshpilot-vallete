package auth

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// TestUserCodeAlphabetIsConfusableFree is the readable statement of the rule
// the alphabet exists to satisfy. It checks the property rather than the
// literal, so a future edit that adds a symbol is judged by the rule and not by
// whether someone remembered to update a constant.
func TestUserCodeAlphabetIsConfusableFree(t *testing.T) {
	if len(userCodeAlphabet) != 32 {
		t.Fatalf("alphabet has %d symbols, want 32: a non-power-of-two alphabet cannot be "+
			"indexed by masking without modulo bias", len(userCodeAlphabet))
	}
	seen := map[rune]bool{}
	for _, r := range userCodeAlphabet {
		if seen[r] {
			t.Fatalf("alphabet repeats %q, which shrinks the real symbol count below 32", r)
		}
		seen[r] = true
	}
	// A pair is a defect only when both members are present; a glyph with one
	// possible reading is not ambiguous. These are the pairs the brief names.
	for _, pair := range []struct{ a, b rune }{{'0', 'O'}, {'1', 'L'}, {'1', 'I'}, {'I', 'L'}} {
		if seen[pair.a] && seen[pair.b] {
			t.Fatalf("alphabet contains both %q and %q, which a person transcribing a code "+
				"cannot reliably tell apart", pair.a, pair.b)
		}
	}
	// Masking five bits indexes exactly the alphabet, so every byte value maps
	// to a symbol and none is favored.
	if userCodeMask != len(userCodeAlphabet)-1 {
		t.Fatalf("mask %#x does not index a %d-symbol alphabet uniformly", userCodeMask, len(userCodeAlphabet))
	}
}

// TestNewUserCodeShape checks that a generated code is drawn only from the
// alphabet, is the advertised length, and is not repeated across calls.
func TestNewUserCodeShape(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		raw := newUserCode().Reveal()
		if strings.Count(raw, "-") != userCodeLen/userCodeGroup-1 {
			t.Fatalf("code %q is not grouped for transcription", raw)
		}
		norm, err := normalizeUserCode(raw)
		if err != nil {
			t.Fatalf("a freshly generated code %q failed to normalize: %v", raw, err)
		}
		if len(norm) != userCodeLen {
			t.Fatalf("normalized code %q has length %d, want %d", norm, len(norm), userCodeLen)
		}
		for _, r := range norm {
			if !strings.ContainsRune(userCodeAlphabet, r) {
				t.Fatalf("code %q contains %q, which is outside the alphabet", norm, r)
			}
		}
		if seen[norm] {
			t.Fatalf("code %q was generated twice in 200 draws, which no correct "+
				"40-bit generator does; the source is not random", norm)
		}
		seen[norm] = true
	}
}

// TestNewUserCodeUsesEveryAlphabetSymbol catches a generator that silently
// covers only part of the alphabet -- the visible symptom of a mask, an index,
// or a modulo that is wrong -- and therefore has less entropy than claimed.
func TestNewUserCodeUsesEveryAlphabetSymbol(t *testing.T) {
	seen := map[rune]bool{}
	for range 2000 {
		norm, err := normalizeUserCode(newUserCode().Reveal())
		if err != nil {
			t.Fatalf("normalizing a generated code: %v", err)
		}
		for _, r := range norm {
			seen[r] = true
		}
	}
	for _, r := range userCodeAlphabet {
		if !seen[r] {
			t.Fatalf("symbol %q never appeared in 16000 draws; the generator does not "+
				"cover the whole alphabet, so a code has less entropy than %d bits", r, userCodeLen*5)
		}
	}
}

func TestNormalizeUserCode(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{name: "canonical", in: "ABCDEFGH", want: "ABCDEFGH", ok: true},
		{name: "grouped", in: "ABCD-EFGH", want: "ABCDEFGH", ok: true},
		{name: "lowercase", in: "abcd-efgh", want: "ABCDEFGH", ok: true},
		{name: "spaced", in: "ABCD EFGH", want: "ABCDEFGH", ok: true},
		// The bar class folds onto its one surviving member. Neither '1' nor
		// 'I' is ever generated, so the fold cannot collide two real codes.
		{name: "one folds to L", in: "1BCDEFGH", want: "LBCDEFGH", ok: true},
		{name: "I folds to L", in: "IBCDEFGH", want: "LBCDEFGH", ok: true},
		{name: "lowercase i folds to L", in: "ibcdefgh", want: "LBCDEFGH", ok: true},
		// The round class kept no member, so there is nothing to fold onto and
		// a guess would map one typed code onto a different real one.
		{name: "zero is rejected", in: "0BCDEFGH", ok: false},
		{name: "O is rejected", in: "OBCDEFGH", ok: false},
		{name: "too short", in: "ABCDEFG", ok: false},
		{name: "too long", in: "ABCDEFGHJ", ok: false},
		{name: "empty", in: "", ok: false},
		{name: "punctuation", in: "ABCD!FGH", ok: false},
		{name: "non-ascii", in: "ABCDEFGÉ", ok: false},
		{name: "separators only", in: "--------", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeUserCode(tt.in)
			if !tt.ok {
				// Every rejection is the bare sentinel: a caller must not learn
				// which of the several ways to be wrong it was.
				if !errors.Is(err, ErrAuthFailed) {
					t.Fatalf("normalizeUserCode(%q) error = %v, want ErrAuthFailed", tt.in, err)
				}
				if err.Error() != ErrAuthFailed.Error() {
					t.Fatalf("normalizeUserCode(%q) wrapped a cause: %v", tt.in, err)
				}
				if got != "" {
					t.Fatalf("normalizeUserCode(%q) returned %q alongside an error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeUserCode(%q) = %v, want %q", tt.in, err, tt.want)
			}
			if got != tt.want {
				t.Fatalf("normalizeUserCode(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestHashesAreNotPlaintext is the storage invariant: nothing that is written
// to a row may contain the code it was derived from.
func TestHashesAreNotPlaintext(t *testing.T) {
	secret := newDeviceSecret()
	dh := hashDeviceSecret(secret)
	if bytes.Contains(dh, secret) {
		t.Fatal("the stored device code digest contains the secret itself")
	}
	if len(dh) != sha256.Size {
		t.Fatalf("device digest is %d bytes, want %d", len(dh), sha256.Size)
	}

	const code = "ABCDEFGH"
	uh := hashUserCode(code)
	if strings.Contains(string(uh), code) {
		t.Fatal("the stored user code digest contains the code itself")
	}
	if len(uh) != sha256.Size {
		t.Fatalf("user digest is %d bytes, want %d", len(uh), sha256.Size)
	}
}

// TestDigestsAreDomainSeparated proves the two digests cannot collide. Without
// the tags, a value accepted on the rate-limited user code path would also be
// accepted on the unlimited device code path.
func TestDigestsAreDomainSeparated(t *testing.T) {
	const shared = "ABCDEFGH"
	if bytes.Equal(hashDeviceSecret([]byte(shared)), hashUserCode(shared)) {
		t.Fatal("the device and user digests of one value are equal; the domain " +
			"separation tags are missing, so one code type can be presented as the other")
	}
	// Both must still be deterministic, or a stored digest could never be
	// matched again.
	if !bytes.Equal(hashUserCode(shared), hashUserCode(shared)) {
		t.Fatal("hashUserCode is not deterministic")
	}
	if !bytes.Equal(hashDeviceSecret([]byte(shared)), hashDeviceSecret([]byte(shared))) {
		t.Fatal("hashDeviceSecret is not deterministic")
	}
}

func TestDeviceSecretMatches(t *testing.T) {
	secret := newDeviceSecret()
	stored := hashDeviceSecret(secret)

	if !deviceSecretMatches(stored, secret) {
		t.Fatal("the correct secret did not match its own digest")
	}

	wrong := append([]byte(nil), secret...)
	wrong[0] ^= 0xff
	if deviceSecretMatches(stored, wrong) {
		t.Fatal("a secret differing in one bit matched")
	}
	if deviceSecretMatches(stored, secret[:len(secret)-1]) {
		t.Fatal("a truncated secret matched")
	}
	if deviceSecretMatches(stored, nil) {
		t.Fatal("a nil secret matched")
	}
	// A corrupt or truncated stored digest must fail closed rather than match
	// anything, which is what ConstantTimeCompare's length check gives.
	if deviceSecretMatches(stored[:16], secret) {
		t.Fatal("a truncated stored digest matched")
	}
	if deviceSecretMatches(nil, secret) {
		t.Fatal("an absent stored digest matched")
	}
	// The digest, not the raw secret, is what a caller could ever have to
	// present: passing the stored digest back in must not authenticate.
	if deviceSecretMatches(stored, stored) {
		t.Fatal("presenting the stored digest as the secret authenticated")
	}
}

func TestDeviceCodeRoundTrip(t *testing.T) {
	id := newPairingID()
	secret := newDeviceSecret()
	code := formatDeviceCode(id, secret)

	if !strings.HasPrefix(code.Reveal(), "svd_") {
		t.Fatalf("device code %q lacks the svd_ prefix a secret scanner keys on", code.Reveal())
	}
	// The redaction guarantee: the value prints as [REDACTED] however it is
	// formatted, and the raw form leaves only through Reveal.
	if strings.Contains(code.String(), secret2str(secret)) {
		t.Fatal("a device code rendered its secret when printed")
	}

	gotID, gotSecret, err := parseDeviceCode(code)
	if err != nil {
		t.Fatalf("parsing a freshly formatted device code: %v", err)
	}
	if gotID != id {
		t.Fatalf("round-tripped id = %q, want %q", gotID, id)
	}
	if !bytes.Equal(gotSecret, secret) {
		t.Fatal("round-tripped secret differs from the one formatted")
	}
}

func TestParseDeviceCodeRejects(t *testing.T) {
	id := newPairingID()
	secret := newDeviceSecret()
	good := formatDeviceCode(id, secret).Reveal()
	encSecret := tokenEncoding.EncodeToString(secret)

	tests := []struct {
		name string
		in   string
	}{
		{name: "empty", in: ""},
		{name: "no prefix", in: strings.TrimPrefix(good, "svd_")},
		// A refresh token is the same shape under a different prefix. It must
		// be refused on shape here rather than reaching a lookup.
		{name: "refresh token prefix", in: "svr_" + string(id) + "." + encSecret},
		{name: "access token prefix", in: "sva_" + string(id) + "." + encSecret},
		{name: "no separator", in: "svd_" + string(id) + encSecret},
		{name: "two separators", in: "svd_" + string(id) + "." + encSecret + "." + encSecret},
		{name: "short id", in: "svd_" + string(id)[:10] + "." + encSecret},
		{name: "long id", in: "svd_" + string(id) + "AA." + encSecret},
		{name: "id not base64url", in: "svd_" + strings.Repeat("*", credentialIDChars) + "." + encSecret},
		{name: "secret not base64url", in: "svd_" + string(id) + "." + strings.Repeat("*", 43)},
		{name: "short secret", in: "svd_" + string(id) + "." + encSecret[:20]},
		{name: "long secret", in: "svd_" + string(id) + "." + encSecret + "AA"},
		{name: "empty secret", in: "svd_" + string(id) + "."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotID, gotSecret, err := parseDeviceCode(secrets.NewRedacted(tt.in))
			if !errors.Is(err, ErrAuthFailed) {
				t.Fatalf("parseDeviceCode(%q) error = %v, want ErrAuthFailed", tt.in, err)
			}
			if err.Error() != ErrAuthFailed.Error() {
				t.Fatalf("parseDeviceCode(%q) wrapped a cause, which reinstates the "+
					"distinction the sentinel erases: %v", tt.in, err)
			}
			if gotID != "" || gotSecret != nil {
				t.Fatalf("parseDeviceCode(%q) returned material alongside an error", tt.in)
			}
		})
	}
}

// TestNewPairingIDIsRandom checks the identifier is drawn fresh each time and
// has the encoded width the parser requires.
func TestNewPairingIDIsRandom(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		id := string(newPairingID())
		if len(id) != credentialIDChars {
			t.Fatalf("pairing id %q has length %d, want %d", id, len(id), credentialIDChars)
		}
		if seen[id] {
			t.Fatalf("pairing id %q repeated, so identifiers are not random", id)
		}
		seen[id] = true
	}
}

// secret2str renders a secret the way a leak would, for the redaction check.
func secret2str(secret []byte) string { return tokenEncoding.EncodeToString(secret) }
