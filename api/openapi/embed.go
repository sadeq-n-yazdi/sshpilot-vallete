// Package openapi embeds the API contract document into the binary.
//
// The spec is embedded rather than read from disk at request time for two
// reasons, both security-relevant. A disk read at request time is a path the
// filesystem can influence — the natural next step is a filename derived from
// the request, which is a traversal bug waiting to be written. And a file read
// from disk is whatever happens to be on that disk, which may not be the
// contract the running code implements; embedding pins the served document to
// the build.
//
// The embed lives here, beside the document, because a //go:embed pattern may
// not contain ".." — a consumer package cannot reach up into api/openapi. That
// constraint is load-bearing rather than incidental: it means there is exactly
// one copy of the spec in the tree, so the served bytes cannot drift from the
// authored ones.
package openapi

import _ "embed"

// Spec is the raw OpenAPI 3.1 document, exactly as authored in openapi.yaml.
//
// It is a []byte rather than a string so callers do not pay a copy to hash or
// write it; callers must treat it as read-only, since every caller shares this
// one backing array.
//
//go:embed openapi.yaml
var Spec []byte
