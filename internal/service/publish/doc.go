// Package publish resolves a public handle (and optional key set name) to the
// canonical authorized_keys body that the unauthenticated publish endpoint
// serves.
//
// It is transport-free: it knows nothing about HTTP status codes, headers, or
// caching. The transport maps its two error modes onto the wire.
//
// # Two error modes, deliberately
//
// Resolve returns exactly one of:
//
//   - [ErrNotFound] — the request does not name something this endpoint may
//     publish. EVERY negative verdict collapses into this single sentinel:
//     malformed handle or set name, unclaimed handle, non-active handle,
//     suspended or deleted owner, unknown set, a set belonging to another
//     owner, a quarantined set tombstone, and a set that is not public. The
//     caller cannot tell these apart, and that is the point: any distinguishable
//     outcome would be an existence oracle that lets an unauthenticated stranger
//     probe which handles exist and which sets another owner holds.
//   - any other error — an internal fault. The transport answers 500 and the
//     detail goes only to the log.
//
// Cross-owner isolation is structural rather than checked after the fact. The
// owner is derived from the handle, and every subsequent lookup is scoped to
// that owner ID, so another owner's set is never a candidate in the first
// place; there is no code path that looks a key set up globally.
//
// # Output
//
// The body is native authorized_keys: one canonical key line per active member
// of the set, each terminated by "\n", with no options and no comments-as-
// directives. Lines are rebuilt by [keys.AuthorizedKeyLineFrom] from the stored
// algorithm, wire blob, and comment — never by string-concatenating stored text
// — so a stored comment carrying a line break cannot forge an extra entry. An
// unrenderable key fails the WHOLE request rather than being skipped: a silently
// partial authorized_keys file is far more dangerous than a loud error, because
// nothing downstream can tell a truncated key list from a legitimately shorter
// one.
//
// A resolved, public set with no active members yields an empty body and a
// successful result, which is the correct representation of "this set publishes
// no keys" and is distinct from the 404 cases above only because the set itself
// is public by declaration.
package publish
