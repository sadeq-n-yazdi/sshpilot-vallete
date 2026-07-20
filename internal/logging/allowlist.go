package logging

// defaultAllowedKeys is the set of attribute keys whose values may be rendered.
// Everything else becomes "[REDACTED]".
//
// # Why an allowlist and not a denylist
//
// A denylist ("redact anything called password, token, secret, ...") is the
// common choice and it is default-allow: it protects exactly the key names
// somebody thought of in advance, and fails open on every one they did not.
// That failure mode is not hypothetical here. Between them, the shapes this
// service handles are named "pairing_code", "access_key", "dsn", "csr_key",
// "refresh_token_hash" and "authorization" -- six different words for the same
// category, and a seventh will be added by whoever implements the next feature.
// The denylist protects them only if that author remembers to extend it, which
// is the same "the caller has to remember" dependency the whole design is meant
// to remove. It is also the identical shape of default-allow bug this codebase
// just fixed in its TLS environment check.
//
// The allowlist inverts the failure. A key nobody has classified renders as
// "[REDACTED]", so a forgotten new field costs an operator one missing value in
// a log line -- visible, harmless, and fixed by a one-line diff that lands in
// front of a reviewer at exactly the moment the security question is being
// asked: "is it safe to print this?" The cost is paid in inconvenience by the
// author of a new log line; the denylist would instead pay it in disclosure, on
// a field nobody was looking at.
//
// # What is deliberately NOT redacted
//
// This service exists to publish SSH *public* keys (ADR-0002), so redacting
// them would leave the logs useless while protecting nothing. Public keys, key
// types, fingerprints, handles and key-set names are all allowlisted. They are
// public by design: ADR-0010 makes a key set public by default and keeps the
// access credential in an Authorization header precisely so that the URL --
// and therefore the access log -- carries only the non-secret half.
//
// Fingerprints deserve the distinction stated out loud: a fingerprint is not
// secret (it is derived from a public key and is the standard way to name one),
// but it IS owner-identifying, so it is a privacy value rather than a security
// one. It stays loggable because operators cannot diagnose a key-mismatch
// report without it; ADR-0024's erasure obligations apply to it, and ADR-0025
// separately forbids using it as an unbounded metric label.
var defaultAllowedKeys = []string{
	// --- Request correlation and access-log shape -----------------------
	// Route is the matched ServeMux pattern ("GET /{handle}"), which is
	// low-cardinality and never client-controlled. Path is the sanitized
	// request path; it carries a handle, which ADR-0010 treats as public.
	// Neither the query string, nor any header, has a key here at all.
	"request_id",
	"method",
	"path",
	"route",
	"status",
	"bytes",
	"duration",

	// --- Process and deployment identity --------------------------------
	"addr",
	"environment",
	"grace",
	"tls_mode",
	"version",
	"component",

	// --- Diagnostics -----------------------------------------------------
	// "error" and "panic" hold causes, which operators cannot work without.
	// leafValue restricts what may render under them: an error renders via
	// Error(), and any other structured value is redacted.
	"error",
	"panic",
	"reason",

	// internal/secrets warns when a secret file is group/other-readable, and
	// both fields of that warning are the whole point of it: "perm" is a file
	// mode, and "reference" is the path of the offending file. Redacting either
	// would leave an operator told that some file somewhere has bad permissions
	// -- a warning they cannot act on, which is worse than no warning.
	//
	// "reference" is safe to render because a secrets.Ref redacts itself
	// through LogValue no matter what the policy here says, so the only thing
	// this key can print is the plain path string the file provider already
	// puts in its errors, which ADR-0022's provider contract documents as the
	// non-secret diagnostic half of a reference.
	"perm",
	"reference",

	// --- Domain vocabulary, non-secret by ADR-0002 and ADR-0010 ---------
	"handle",
	"key_set",
	"key_set_id",
	"owner_id",
	"key_id",
	"key_type",
	"fingerprint",
	"public_key",
	"count",
	"visibility",
	"audit_action",
}
