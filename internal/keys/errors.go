// Package keys ingests SSH public keys and reconstructs canonical,
// options-free authorized_keys lines.
//
// It handles public key material only (ADR-0002): it never accepts, stores, or
// echoes private key material, and no error it returns ever contains bytes from
// the caller's input. The package is pure — no I/O, logging, or global state —
// and imports only the standard library, internal/domain, and
// golang.org/x/crypto/ssh.
//
// Every sentinel error wraps domain.ErrInvalidInput (except the batch
// duplicate-fingerprint case, which wraps domain.ErrConflict) so callers test
// membership with errors.Is. Error messages are fixed strings; they never
// reflect input.
package keys

import (
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// Size limits. These are tighten-only ceilings, not tuning knobs.
const (
	// MaxLineBytes bounds a single key submission to Parse.
	MaxLineBytes = 16 * 1024
	// MaxFileBytes bounds a whole authorized_keys batch to ParseAuthorizedKeys.
	MaxFileBytes = 1 << 20
)

// Sentinel errors. Each wraps domain.ErrInvalidInput. None ever contains bytes
// from the caller's input; the messages are fixed text.
var (
	// ErrMalformed indicates the input is not a single, parseable public key.
	ErrMalformed = fmt.Errorf("keys: malformed public key: %w", domain.ErrInvalidInput)
	// ErrOptionsPresent indicates the line carried authorized_keys options,
	// which are never accepted.
	ErrOptionsPresent = fmt.Errorf("keys: authorized_keys options are not permitted: %w", domain.ErrInvalidInput)
	// ErrUnsupportedAlgorithm indicates the key algorithm is not on the
	// allowlist (for example ssh-dss or a certificate type).
	ErrUnsupportedAlgorithm = fmt.Errorf("keys: unsupported key algorithm: %w", domain.ErrInvalidInput)
	// ErrWeakKey indicates the key does not meet the minimum strength (RSA
	// below domain.MinRSABits).
	ErrWeakKey = fmt.Errorf("keys: key is too weak: %w", domain.ErrInvalidInput)
	// ErrMultipleKeys indicates more than one key was present where exactly one
	// was required.
	ErrMultipleKeys = fmt.Errorf("keys: exactly one key is required: %w", domain.ErrInvalidInput)
	// ErrBadComment indicates the trailing comment failed validation.
	ErrBadComment = fmt.Errorf("keys: invalid key comment: %w", domain.ErrInvalidInput)
	// ErrTooLarge indicates the input exceeded the applicable size limit.
	ErrTooLarge = fmt.Errorf("keys: input exceeds the maximum permitted size: %w", domain.ErrInvalidInput)
	// ErrPrivateKey indicates private key material was detected. Its message
	// guides the user and is deliberately fixed: the pasted content is never
	// echoed or stored.
	ErrPrivateKey = fmt.Errorf("keys: private key material detected; submit only the .pub file — the pasted content was not stored: %w", domain.ErrInvalidInput)
)
