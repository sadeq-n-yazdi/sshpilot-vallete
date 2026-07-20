package httpserver

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

const (
	// keyFileMode is the only mode a private key file may have. ADR-0015 §3
	// requires 0600 for cert and key material.
	keyFileMode fs.FileMode = 0o600

	// csrFileMode is the mode of the emitted CSR. A CSR carries the public key
	// and the subject/SAN names and nothing else — both appear verbatim in the
	// certificate the CA hands back and publishes — so it is not secret, and
	// the operator has to be able to collect it and send it to a CA.
	csrFileMode fs.FileMode = 0o644

	// groupOtherReadWrite are the permission bits that must never be set on a
	// private key file. A key readable by another account on the host is
	// compromised regardless of what this process does with it.
	groupOtherReadWrite fs.FileMode = 0o077
)

// csrProvider implements ADR-0015 §2's "generate CSR for external signing" mode.
//
// The division of labor is deliberate and one-directional: this process owns the
// private key and NEVER emits it, while the operator owns the trip to a CA. On
// startup the provider ensures a key exists, writes a CSR for the operator to
// collect, and then either serves the signed chain they installed or refuses to
// start. Renewal is manual, as the ADR says — the operator repeats the round
// trip and restarts.
//
// The chain an operator installs gets NO trust for having come from an operator.
// It is handed to the same [certGuard] as every other provider, which re-derives
// the leaf from DER, checks it against this process's key, and enforces the
// validity window on every handshake. An operator who installs the wrong file,
// a chain for a different key, or an already-expired certificate finds out at
// startup rather than from their clients.
type csrProvider struct {
	cert tls.Certificate
}

// newCSRProvider prepares key material, emits the CSR, and loads the signed
// chain if the operator has installed one.
//
// The ordering matters. The key is created BEFORE the CSR (a CSR is a signed
// statement about a specific key) and the chain is loaded LAST, so that the
// no-certificate-yet case still leaves the operator with everything they need to
// obtain one. A first run therefore fails to start, but fails having produced
// the CSR that fixes it.
func newCSRProvider(cfg *config.Config) (*csrProvider, error) {
	paths := cfg.TLS.CSR

	key, err := loadOrCreateKey(paths.KeyFile)
	if err != nil {
		return nil, err
	}

	if err := writeCSR(paths.CSRFile, key, cfg); err != nil {
		return nil, err
	}

	chain, err := loadCertChain(paths.CertFile)
	if err != nil {
		return nil, err
	}

	// The key is paired with the chain in memory. Note what does NOT happen
	// here: the key is never re-serialized to PEM to feed tls.X509KeyPair. It
	// stays a crypto.Signer from the moment it is parsed, so no plaintext copy
	// of it exists to be logged, formatted, or written anywhere. The guard
	// still proves the pairing is real by comparing public keys.
	return &csrProvider{cert: tls.Certificate{Certificate: chain, PrivateKey: key}}, nil
}

// Name identifies the mode for diagnostics.
func (p *csrProvider) Name() string { return "csr" }

// GetCertificate returns the operator-installed chain. The material is fixed for
// the process lifetime — renewal in this mode is an operator restarting with a
// new file — but the guard re-checks its validity window every handshake, so an
// expired certificate stops the listener without waiting for a restart.
func (p *csrProvider) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return &p.cert, nil
}

// loadOrCreateKey returns the provider's private key, generating and persisting
// one on first run.
//
// An existing key is REUSED rather than regenerated. Regenerating would silently
// invalidate a certificate the operator already paid for and installed, and
// would do it at the least convenient moment — a restart.
//
// ECDSA P-256 is chosen over the ed25519 key the self-signed provider uses,
// because this key's signature has to be accepted by a third party. Ed25519 CSR
// support is still uneven across public CAs and enterprise PKI, and a key an
// operator cannot get signed is a key that fails at exactly the point of the
// mode. P-256 is universally supported and gives no ground on strength.
func loadOrCreateKey(path string) (crypto.Signer, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-configured key path.
	switch {
	case err == nil:
		return parseKey(path, raw)
	case errors.Is(err, fs.ErrNotExist):
		return createKey(path)
	default:
		// The path is named; nothing that was read is quoted.
		return nil, fmt.Errorf("%w: read key %s: %w", ErrTLSCertificateInvalid, path, err)
	}
}

// parseKey decodes an existing key file, refusing one other accounts can read.
//
// The permission check comes first and is fatal. A key at 0644 has potentially
// already been copied by any local user, so continuing to serve with it would be
// serving with material that must be considered compromised — and silently
// tightening the mode would hide that it ever happened.
func parseKey(path string, raw []byte) (crypto.Signer, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: stat key %s: %w", ErrTLSCertificateInvalid, path, err)
	}
	if mode := info.Mode().Perm(); mode&groupOtherReadWrite != 0 {
		return nil, fmt.Errorf("%w: key %s has mode %#o; it must not be accessible to group or other (want %#o)",
			ErrTLSKeyPermissions, path, mode, keyFileMode)
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%w: key %s contains no PEM block", ErrTLSCertificateInvalid, path)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// The crypto/x509 error describes the structure, never the bytes.
		return nil, fmt.Errorf("%w: parse key %s: %w", ErrTLSCertificateInvalid, path, err)
	}

	signer, ok := parsed.(crypto.Signer)
	if !ok {
		// %T names the type only, never the value.
		return nil, fmt.Errorf("%w: key %s is a %T, which cannot sign", ErrTLSCertificateInvalid, path, parsed)
	}
	return signer, nil
}

// createKey generates a new key and persists it with mode 0600.
//
// The generated key crosses exactly one boundary in serialized form — the write
// to disk — and it is wrapped in [secrets.Redacted] for that crossing, so that
// any code which later formats or logs the value it came from yields the
// redaction marker rather than the key. The plaintext is obtained only at the
// moment it is handed to the writer.
func createKey(path string) (crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		// Unlike a bare crypto/rand read, ecdsa.GenerateKey can fail on an
		// invalid curve, so this branch is real rather than decorative.
		return nil, fmt.Errorf("httpserver: generate csr key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("httpserver: marshal csr key: %w", err)
	}

	encoded := secrets.NewRedacted(string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})))

	if err := atomicWriteFile(path, []byte(encoded.Reveal()), keyFileMode); err != nil {
		return nil, fmt.Errorf("%w: write key %s: %w", ErrTLSCertificateInvalid, path, err)
	}
	return key, nil
}

// writeCSR emits the certificate signing request for the operator to collect.
//
// It is rewritten on every start rather than only when absent, so that a change
// to tls.domain or tls.sans is reflected without the operator having to know
// which file to delete. That is safe precisely because a CSR is derived data:
// it commits to nothing until a CA signs it, and it never contains the key.
func writeCSR(path string, key crypto.Signer, cfg *config.Config) error {
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cfg.TLS.Domain},
	}
	for _, h := range certHosts(cfg) {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return fmt.Errorf("httpserver: create csr: %w", err)
	}

	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if err := atomicWriteFile(path, encoded, csrFileMode); err != nil {
		return fmt.Errorf("httpserver: write csr %s: %w", path, err)
	}
	return nil
}

// loadCertChain reads the operator-installed chain as DER blocks.
//
// A missing file is its own error, not a generic read failure: on a first run it
// is the EXPECTED state, and the operator's next action is to get the CSR signed
// rather than to debug a path. The server still refuses to start, because
// ADR-0015 permits no fallback to plaintext or to a self-signed certificate
// while waiting.
//
// The chain is returned as raw DER rather than parsed certificates because that
// is what tls.Certificate carries and what the guard re-derives the leaf from.
func loadCertChain(path string) ([][]byte, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-configured cert path.
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: no signed certificate at %s yet", ErrTLSCSRPending, path)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read certificate %s: %w", ErrTLSCertificateInvalid, path, err)
	}

	var chain [][]byte
	for rest := raw; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, block.Bytes)
		}
	}

	if len(chain) == 0 {
		return nil, fmt.Errorf("%w: %s contains no CERTIFICATE block", ErrTLSCertificateInvalid, path)
	}
	return chain, nil
}

// atomicWriteFile writes data to path so that no reader ever observes a partial
// file and no key is ever briefly world-readable.
//
// Three properties, each of which fails a different attack or accident:
//
//   - Atomic. The write goes to a temporary file which is renamed into place.
//     rename(2) is atomic within a filesystem, so a concurrent reader sees
//     either the old file or the complete new one, never a truncated key. The
//     temporary is created in the SAME DIRECTORY as the target for this reason:
//     a rename across filesystems fails, and falling back to a copy would
//     reintroduce the torn-write window.
//   - Never world-readable, even transiently. os.CreateTemp creates at 0600 and
//     the mode is set explicitly before any content is written, so the bytes
//     never exist on disk under looser permissions. Creating at the final mode
//     and tightening afterwards would leave exactly the race this avoids.
//     (umask can only clear bits, never add them, so it cannot widen this.)
//   - Durable before it is visible. The file is synced before the rename, so a
//     crash cannot leave the target name pointing at a file whose contents were
//     never flushed.
func atomicWriteFile(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, ".vallet-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	// Any failure from here on must not leave the temporary behind; a stray
	// file containing a private key is the whole problem restated.
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return nil
}
