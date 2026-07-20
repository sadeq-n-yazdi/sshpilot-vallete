package auth

import "errors"

// ErrAuthFailed is the single error every authentication denial returns,
// whatever the cause: an unregistered provider, a provider that rejected the
// credential, a provider that misbehaved, a principal with no LinkedIdentity, or
// an owner that is not active.
//
// It is one sentinel on purpose. Distinguishable failures let an
// unauthenticated caller probe the system: "unknown principal" versus "known
// principal, no link" reveals which credentials exist, and "no such provider"
// reveals the deployment's configuration. The same reasoning is already applied
// one layer down, where domain.ErrNotFound deliberately covers both a missing
// row and another owner's row.
//
// Denials are returned bare, never wrapped with a cause, because a wrapped
// cause is still readable by the caller through errors.Is and errors.As and
// would reinstate exactly the distinction this sentinel exists to erase.
//
// This guarantee is about information content, not timing; see the package
// documentation.
var ErrAuthFailed = errors.New("auth: authentication failed")
