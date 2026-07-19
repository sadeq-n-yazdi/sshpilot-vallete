package keys

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

func joinLines(lines ...[]byte) []byte {
	return bytes.Join(lines, []byte("\n"))
}

func TestParseAuthorizedKeysAccepts(t *testing.T) {
	a := ed25519Fixture(t)
	b := ecdsaFixtureP256(t)
	raw := joinLines(
		[]byte("# a header comment"),
		[]byte(""),
		a.line("first"),
		[]byte("   "),
		b.line(""),
		[]byte("\t# indented comment"),
	)
	keys, errs := ParseAuthorizedKeys(raw)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	if keys[0].Algorithm != a.alg || keys[0].Comment != "first" {
		t.Errorf("key0 = %+v", keys[0])
	}
	if keys[1].Algorithm != b.alg {
		t.Errorf("key1 = %+v", keys[1])
	}
}

func TestParseAuthorizedKeysCRLF(t *testing.T) {
	a := ed25519Fixture(t)
	b := ecdsaFixtureP256(t)
	raw := bytes.Join([][]byte{a.line(""), b.line(""), {}}, []byte("\r\n"))
	keys, errs := ParseAuthorizedKeys(raw)
	if len(errs) != 0 || len(keys) != 2 {
		t.Fatalf("keys=%d errs=%v", len(keys), errs)
	}
}

func TestParseAuthorizedKeysLineNumbers(t *testing.T) {
	a := ed25519Fixture(t)
	b := ecdsaFixtureP256(t)
	raw := joinLines(
		a.line(""),                               // 1 ok
		[]byte(""),                               // 2 blank
		[]byte("this is not a key"),              // 3 malformed
		append([]byte("no-pty "), b.line("")...), // 4 options
		b.line(""),                               // 5 ok
	)
	keys, errs := ParseAuthorizedKeys(raw)
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	if len(errs) != 2 {
		t.Fatalf("got %d errors, want 2: %v", len(errs), errs)
	}
	if errs[0].Line != 3 || !errors.Is(errs[0].Err, ErrMalformed) {
		t.Errorf("errs[0] = %+v, want line 3 malformed", errs[0])
	}
	if errs[1].Line != 4 || !errors.Is(errs[1].Err, ErrOptionsPresent) {
		t.Errorf("errs[1] = %+v, want line 4 options", errs[1])
	}
}

func TestParseAuthorizedKeysDuplicate(t *testing.T) {
	a := ed25519Fixture(t)
	raw := joinLines(a.line("original"), a.line("copy"))
	keys, errs := ParseAuthorizedKeys(raw)
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	if len(errs) != 1 {
		t.Fatalf("got %d errors, want 1", len(errs))
	}
	if errs[0].Line != 2 {
		t.Errorf("dup line = %d, want 2", errs[0].Line)
	}
	if !errors.Is(errs[0].Err, domain.ErrConflict) {
		t.Errorf("dup err = %v, want ErrConflict", errs[0].Err)
	}
	if errors.Is(errs[0].Err, domain.ErrInvalidInput) {
		t.Errorf("dup err must not wrap ErrInvalidInput")
	}
}

func TestParseAuthorizedKeysWholeSubmissionRejects(t *testing.T) {
	valid := ed25519Fixture(t).line("")
	t.Run("too-large", func(t *testing.T) {
		keys, errs := ParseAuthorizedKeys(bytes.Repeat([]byte("A"), MaxFileBytes+1))
		if keys != nil {
			t.Errorf("keys = %v, want nil", keys)
		}
		if len(errs) != 1 || errs[0].Line != 0 || !errors.Is(errs[0].Err, ErrTooLarge) {
			t.Fatalf("errs = %v, want single line-0 ErrTooLarge", errs)
		}
	})
	privateCases := map[string][]byte{
		"whole":     []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----"),
		"mid-batch": joinLines(valid, []byte("-----BEGIN RSA PRIVATE KEY-----"), valid),
		"putty":     []byte("PuTTY-User-Key-File-3: ssh-rsa\n"),
	}
	for name, raw := range privateCases {
		t.Run("private/"+name, func(t *testing.T) {
			keys, errs := ParseAuthorizedKeys(raw)
			if keys != nil {
				t.Errorf("keys = %v, want nil", keys)
			}
			if len(errs) != 1 || errs[0].Line != 0 || !errors.Is(errs[0].Err, ErrPrivateKey) {
				t.Fatalf("errs = %v, want single line-0 ErrPrivateKey", errs)
			}
			assertNoInput(t, errs[0].Err, string(raw))
		})
	}
}

func TestParseAuthorizedKeysEmpty(t *testing.T) {
	for name, raw := range map[string][]byte{
		"nil":       nil,
		"blank":     []byte("\n\n   \n"),
		"only-hash": []byte("# one\n# two\n"),
	} {
		t.Run(name, func(t *testing.T) {
			keys, errs := ParseAuthorizedKeys(raw)
			if len(keys) != 0 || len(errs) != 0 {
				t.Fatalf("keys=%v errs=%v, want both empty", keys, errs)
			}
		})
	}
}

func TestLineErrorMethods(t *testing.T) {
	le := LineError{Line: 7, Err: ErrMalformed}
	if !errors.Is(le, ErrMalformed) {
		t.Error("errors.Is(LineError, ErrMalformed) = false")
	}
	if !errors.Is(le, domain.ErrInvalidInput) {
		t.Error("LineError does not chain to domain.ErrInvalidInput")
	}
	if msg := le.Error(); !strings.Contains(msg, "keys:") {
		t.Errorf("unexpected message %q", msg)
	}
}
