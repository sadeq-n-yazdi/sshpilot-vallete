package keys

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

func TestParseRejectsWeakRSA(t *testing.T) {
	for _, bits := range []int{1024, 2048, 3071} {
		t.Run(itoa(bits), func(t *testing.T) {
			k := rsaKey(t, bits)
			pub := mustSSHPub(t, k.Public())
			line := ssh.MarshalAuthorizedKey(pub)
			_, err := Parse(line)
			if !errors.Is(err, ErrWeakKey) {
				t.Fatalf("bits=%d err = %v, want ErrWeakKey", bits, err)
			}
		})
	}
	// Boundary: exactly MinRSABits is accepted.
	k, err := Parse(rsaFixture(t, domain.MinRSABits).line(""))
	if err != nil {
		t.Fatalf("rsa-%d boundary: %v", domain.MinRSABits, err)
	}
	if k.BitLen != domain.MinRSABits {
		t.Errorf("BitLen = %d, want %d", k.BitLen, domain.MinRSABits)
	}
}

func TestParseRejectsUnsupportedAlgorithms(t *testing.T) {
	t.Run("ssh-dss", func(t *testing.T) {
		line := ssh.MarshalAuthorizedKey(dsaPublicKey(t))
		_, err := Parse(line)
		if !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
		}
	})
	t.Run("certificate", func(t *testing.T) {
		line := ssh.MarshalAuthorizedKey(certificate(t))
		_, err := Parse(line)
		if !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
		}
	})
}

func TestParseRejectsOptions(t *testing.T) {
	body := ed25519Fixture(t).line("")
	options := []string{
		`command="echo hi"`,
		`from="10.0.0.0/8"`,
		`environment="X=1"`,
		`permitopen="host:22"`,
		"no-pty",
		"restrict",
		`restrict,command="x",no-pty`,
		`command="a b c"`,
	}
	for _, opt := range options {
		t.Run(opt, func(t *testing.T) {
			line := append([]byte(opt+" "), body...)
			_, err := Parse(line)
			if !errors.Is(err, ErrOptionsPresent) {
				t.Fatalf("opt=%q err = %v, want ErrOptionsPresent", opt, err)
			}
			assertNoInput(t, err, opt)
		})
	}
}

func TestParseRejectsMultipleKeys(t *testing.T) {
	a := ed25519Fixture(t).line("")
	b := ecdsaFixtureP256(t).line("")
	cases := map[string][]byte{
		"two-lines":           append(append(append([]byte{}, a...), '\n'), b...),
		"trailing-second-key": append(append(append(append([]byte{}, a...), '\n'), b...), '\n'),
		"garbage-then-valid":  append([]byte("not-a-key\n"), a...),
		"crlf-separated":      append(append(append([]byte{}, a...), []byte("\r\n")...), b...),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(in)
			if !errors.Is(err, ErrMultipleKeys) {
				t.Fatalf("err = %v, want ErrMultipleKeys", err)
			}
		})
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	cases := map[string][]byte{
		"empty":            nil,
		"whitespace":       []byte("   \t  "),
		"hash-comment":     []byte("# just a comment"),
		"indented-hash":    []byte("   # spaced comment"),
		"bare-algo":        []byte("ssh-ed25519"),
		"truncated-base64": []byte("ssh-ed25519 AAAA"),
		"wrong-blob-type":  wrongBlobLine(t),
		"non-utf8":         []byte("ssh-ed25519 \xff\xfe garbage"),
		"null-bytes":       []byte("ssh-ed25519 \x00\x00\x00"),
		"random-garbage":   []byte("hello world this is not a key"),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(in)
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
			if err := errWrapsInvalidInput(err); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestParseRejectsTooLarge(t *testing.T) {
	_, err := Parse(bytes.Repeat([]byte("A"), MaxLineBytes+1))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	// Exactly MaxLineBytes is not rejected for size (it fails later as
	// malformed, not as too large).
	_, err = Parse(bytes.Repeat([]byte("A"), MaxLineBytes))
	if errors.Is(err, ErrTooLarge) {
		t.Fatalf("size-boundary should not be ErrTooLarge, got %v", err)
	}
}

func TestParseRejectsPrivateKey(t *testing.T) {
	valid := ed25519Fixture(t).line("")
	cases := map[string][]byte{
		"openssh":          []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"),
		"rsa-pem":          []byte("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"),
		"ec-pem":           []byte("-----BEGIN EC PRIVATE KEY-----\nabc\n"),
		"encrypted-pem":    []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nabc\n"),
		"putty":            []byte("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n"),
		"lowercase":        []byte("-----begin openssh private key-----"),
		"surrounded-ws":    []byte("\n\n   -----BEGIN OPENSSH PRIVATE KEY-----   \n\n"),
		"private-then-pub": append([]byte("-----BEGIN RSA PRIVATE KEY-----\n"), valid...),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(in)
			if !errors.Is(err, ErrPrivateKey) {
				t.Fatalf("err = %v, want ErrPrivateKey", err)
			}
			assertNoInput(t, err, string(in))
			if strings.Contains(err.Error(), "abc") {
				t.Error("error message leaked input")
			}
		})
	}
}
