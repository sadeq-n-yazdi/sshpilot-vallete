package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// fixture is a generated, accepted key together with its expected metadata and
// a ready-to-parse authorized_keys line (no trailing newline).
type fixture struct {
	name    string
	alg     domain.Algorithm
	bitLen  int
	pub     ssh.PublicKey
	lineNoC []byte // "<alg> <base64>" with no comment
}

// line returns the authorized_keys line for this fixture, optionally with a
// trailing comment. The base64 body is produced by x/crypto so tests compare
// against the canonical serialization.
func (f fixture) line(comment string) []byte {
	if comment == "" {
		return append([]byte{}, f.lineNoC...)
	}
	return append(append(append([]byte{}, f.lineNoC...), ' '), comment...)
}

// rsaCache memoizes slow RSA key generation across subtests, keyed by bit size.
var (
	rsaMu    sync.Mutex
	rsaCache = map[int]*rsa.PrivateKey{}
)

func rsaKey(t testing.TB, bits int) *rsa.PrivateKey {
	t.Helper()
	rsaMu.Lock()
	defer rsaMu.Unlock()
	if k, ok := rsaCache[bits]; ok {
		return k
	}
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate rsa %d: %v", bits, err)
	}
	rsaCache[bits] = k
	return k
}

func mustSSHPub(t testing.TB, key any) ssh.PublicKey {
	t.Helper()
	p, err := ssh.NewPublicKey(key)
	if err != nil {
		t.Fatalf("new ssh public key: %v", err)
	}
	return p
}

func mkFixture(t testing.TB, name string, alg domain.Algorithm, bitLen int, pub ssh.PublicKey) fixture {
	t.Helper()
	body := ssh.MarshalAuthorizedKey(pub) // "<alg> <base64>\n"
	if n := len(body); n > 0 && body[n-1] == '\n' {
		body = body[:n-1]
	}
	return fixture{name: name, alg: alg, bitLen: bitLen, pub: pub, lineNoC: body}
}

// ed25519Fixture returns a generated ed25519 fixture plus its raw public key.
func ed25519Fixture(t testing.TB) fixture {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	return mkFixture(t, "ed25519", domain.AlgEd25519, 256, mustSSHPub(t, pub))
}

func ecdsaFixture(t testing.TB, curve elliptic.Curve, alg domain.Algorithm, bitLen int) fixture {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa: %v", err)
	}
	return mkFixture(t, string(alg), alg, bitLen, mustSSHPub(t, k.Public()))
}

func rsaFixture(t testing.TB, bits int) fixture {
	t.Helper()
	k := rsaKey(t, bits)
	return mkFixture(t, "rsa", domain.AlgRSA, bits, mustSSHPub(t, k.Public()))
}

// skEd25519Fixture hand-marshals the sk-ssh-ed25519 wire format (x/crypto has
// no generator for security-key types) and re-parses it to a real PublicKey.
func skEd25519Fixture(t testing.TB) fixture {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	wire := ssh.Marshal(struct {
		Name        string
		KeyBytes    []byte
		Application string
	}{string(domain.AlgSKEd25519), []byte(pub), "ssh:"})
	sk, err := ssh.ParsePublicKey(wire)
	if err != nil {
		t.Fatalf("parse sk-ed25519: %v", err)
	}
	return mkFixture(t, "sk-ed25519", domain.AlgSKEd25519, 256, sk)
}

// skECDSAFixture hand-marshals the sk-ecdsa-sha2-nistp256 wire format. The point
// is taken via crypto/ecdh to avoid the deprecated elliptic.Marshal.
func skECDSAFixture(t testing.TB) fixture {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa: %v", err)
	}
	ek, err := k.PublicKey.ECDH()
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	wire := ssh.Marshal(struct {
		Name        string
		ID          string
		Key         []byte
		Application string
	}{string(domain.AlgSKECDSA256), "nistp256", ek.Bytes(), "ssh:"})
	sk, err := ssh.ParsePublicKey(wire)
	if err != nil {
		t.Fatalf("parse sk-ecdsa: %v", err)
	}
	return mkFixture(t, "sk-ecdsa", domain.AlgSKECDSA256, 256, sk)
}

// acceptFixtures returns one fixture per accepted algorithm.
func acceptFixtures(t testing.TB) []fixture {
	t.Helper()
	return []fixture{
		ed25519Fixture(t),
		ecdsaFixture(t, elliptic.P256(), domain.AlgECDSA256, 256),
		ecdsaFixture(t, elliptic.P384(), domain.AlgECDSA384, 384),
		ecdsaFixture(t, elliptic.P521(), domain.AlgECDSA521, 521),
		rsaFixture(t, 3072),
		rsaFixture(t, 4096),
		skEd25519Fixture(t),
		skECDSAFixture(t),
	}
}
