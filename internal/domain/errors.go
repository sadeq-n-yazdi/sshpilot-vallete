// Package domain holds the pure data types, sentinel errors, and
// format-validation helpers for sshpilot-vallet.
//
// It contains no business logic, storage, normalization, blocklist, or crypto
// concerns; those live in other layers. It imports only the standard library.
//
// Error handling convention: callers wrap the sentinel errors declared here
// using fmt.Errorf("context: %w", ErrX) and test membership via errors.Is.
// Never compare errors with == or by matching their message text.
package domain

import "errors"

// Sentinel errors. All messages are prefixed with "domain: ".
var (
	// ErrNotFound indicates a requested entity does not exist.
	ErrNotFound = errors.New("domain: not found")
	// ErrConflict indicates a uniqueness or state conflict.
	ErrConflict = errors.New("domain: conflict")
	// ErrInvalidInput indicates malformed or out-of-range input.
	ErrInvalidInput = errors.New("domain: invalid input")
	// ErrUnauthorized indicates missing or invalid authentication.
	ErrUnauthorized = errors.New("domain: unauthorized")
	// ErrForbidden indicates the actor lacks permission for the action.
	ErrForbidden = errors.New("domain: forbidden")
	// ErrQuarantined indicates a name is currently quarantined.
	ErrQuarantined = errors.New("domain: quarantined")
	// ErrBlockedName indicates a name is disallowed by policy.
	ErrBlockedName = errors.New("domain: blocked name")
	// ErrRevoked indicates the target has been revoked.
	ErrRevoked = errors.New("domain: revoked")
	// ErrExpired indicates the target has expired.
	ErrExpired = errors.New("domain: expired")
	// ErrImmutable indicates an attempt to mutate an immutable field.
	ErrImmutable = errors.New("domain: immutable")
	// ErrLimitExceeded indicates a quota or rate limit was exceeded.
	ErrLimitExceeded = errors.New("domain: limit exceeded")
	// ErrDefaultKeySet indicates an invalid operation on the default key set.
	ErrDefaultKeySet = errors.New("domain: default key set")
)
