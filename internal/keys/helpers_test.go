package keys

import (
	"bytes"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

func ecdsaFixtureP256(t testing.TB) fixture {
	t.Helper()
	return ecdsaFixture(t, elliptic.P256(), domain.AlgECDSA256, 256)
}

// dsaPublicKey hand-marshals an ssh-dss key with parameters that satisfy
// x/crypto's structural checks (1024-bit P, 160-bit Q) without pulling in the
// deprecated crypto/dsa package. The key is not cryptographically meaningful;
// it exists only to be rejected by the algorithm allowlist.
func dsaPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	p := new(big.Int).Lsh(big.NewInt(1), 1023) // 1024-bit
	q := new(big.Int).Lsh(big.NewInt(1), 159)  // 160-bit
	wire := ssh.Marshal(struct {
		Name    string
		P, Q, G *big.Int
		Y       *big.Int
	}{"ssh-dss", p, q, big.NewInt(2), big.NewInt(3)})
	pub, err := ssh.ParsePublicKey(wire)
	if err != nil {
		t.Fatalf("parse ssh-dss: %v", err)
	}
	if pub.Type() != "ssh-dss" {
		t.Fatalf("type = %q, want ssh-dss", pub.Type())
	}
	return pub
}

// certificate builds a signed SSH user certificate whose Type is a
// *-cert-v01@openssh.com name that must be rejected as unsupported.
func certificate(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	sshPub := mustSSHPub(t, pub)
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ca: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	cert := &ssh.Certificate{
		Key:             sshPub,
		CertType:        ssh.UserCert,
		KeyId:           "id",
		ValidPrincipals: []string{"user"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	return cert
}

// wrongBlobLine emits a line whose declared algorithm disagrees with its blob
// (an ed25519 blob labeled ssh-rsa), which ssh.ParseAuthorizedKey rejects.
func wrongBlobLine(t *testing.T) []byte {
	t.Helper()
	f := ed25519Fixture(t)
	fields := bytes.SplitN(f.line(""), []byte(" "), 2)
	return append([]byte("ssh-rsa "), fields[1]...)
}

func errWrapsInvalidInput(err error) error {
	if !errors.Is(err, domain.ErrInvalidInput) {
		return errors.New("error does not wrap domain.ErrInvalidInput")
	}
	return nil
}

// assertNoInput fails if the error text contains the given input fragment.
func assertNoInput(t *testing.T, err error, input string) {
	t.Helper()
	if err == nil {
		return
	}
	if trimmed := strings.TrimSpace(input); trimmed != "" && strings.Contains(err.Error(), trimmed) {
		t.Errorf("error message reflected input %q: %q", trimmed, err.Error())
	}
	if err := errWrapsInvalidInput(err); err != nil {
		t.Error(err)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
