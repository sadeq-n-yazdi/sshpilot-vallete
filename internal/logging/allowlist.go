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

	// --- Periodic maintenance jobs ---------------------------------------
	// "sweep" is the name of a background maintenance job. Names are
	// compile-time constants chosen at the registration site
	// ("handle_quarantine_release", "access_key_grace_expiry"); a sweep runs
	// with no request and no principal behind it, so nothing here can be
	// caller-controlled. Without this entry the job name -- the only field
	// that says WHICH sweep a line is about -- renders "[REDACTED]", which
	// leaves an operator unable to tell a stalled sweep from a healthy one
	// running beside it, the exact failure the runner is shaped to surface.
	//
	// "interval" is the configured cadence between passes, an operator-set
	// duration from config that is already visible in the config file the
	// operator wrote. It is generic enough that a future caller could put
	// something richer under it, so the value rules matter more than the key:
	// leafValue redacts any structured value under an allowlisted key, and
	// scrubURLCredentials runs over anything that renders as a string. The
	// list already carries "duration" and "grace" on the same reasoning -- a
	// time quantity is not a category that carries key material -- and this
	// entry is no wider than those.
	"sweep",
	"interval",

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

	// The name of a periodic maintenance job ("handle_quarantine_release",
	// "access_key_grace_expiry"). It is a compile-time constant chosen by the
	// registration site, never derived from a request or a row, so the set of
	// values it can take is fixed and public. It is allowlisted because a
	// redacted job name makes every sweep log line interchangeable -- an
	// operator asking "which sweep stopped" or "which one is failing" gets
	// "[REDACTED]" from both, which is the one question these lines exist to
	// answer. "interval" is its companion on the same lines and is likewise an
	// operator's own configured cadence.
	"sweep",
	"interval",

	// --- Audit retention purge (ADR-0024) -------------------------------
	//
	// The purge is the one irreversible path in this service: it destroys
	// audit evidence, and once a pass has run there is nothing left to
	// reconstruct its scope from. These keys are what an operator reads to
	// confirm a destructive run did what was intended and no more --
	// "records_deleted" and "cutoff" say what was removed, "retention",
	// "batch" and "max_per_run" say under what policy, and "first_cutoff"
	// says what the very first pass will target before it targets it.
	// Redacted, the purge runs with no legible record of its own scope,
	// which is the failure this allowlist's own doctrine calls worse than
	// the missing diagnostic it is meant to cost.
	//
	// Every one is safe by the value's type AND its provenance, not by
	// analogy to a neighbor:
	//
	//   - "retention" is a time.Duration, the configured window
	//     (Retention.AuditRetention), logged via slog.Duration.
	//   - "configured_retention" is the same Duration on the warning that
	//     announces purging is switched off entirely.
	//   - "first_cutoff" and "cutoff" are time.Time, computed as
	//     now-minus-retention by Purger.Cutoff, logged via slog.Time.
	//   - "batch" (int) and "max_per_run" (int64) are the configured
	//     transaction size and per-pass ceiling.
	//   - "records_deleted" (int64) is a row count returned by the purge.
	//
	// None is derived from a request, a row, or any owner: a Purger takes
	// no owner and audit records carry none, and the purge never reads the
	// content of what it deletes. Config is validated positive before any
	// of these can be constructed, so the values are bounded as well as
	// non-secret.
	//
	// RESIDUAL RISK, stated plainly because the argument above is about the
	// call sites that exist today: this allowlist is keyed by name, and
	// leafValue lets a KindString through (URL-scrubbed, nothing more). A
	// future slog.String("batch", someSecret) would therefore render. The
	// names are counts, cutoffs and durations, which do not attract
	// secrets, so the exposure is small -- but it is real, and it is the
	// reason each addition here names the constructor it was cleared for.
	"retention",
	"configured_retention",
	"first_cutoff",
	"cutoff",
	"batch",
	"max_per_run",
	"records_deleted",
}
