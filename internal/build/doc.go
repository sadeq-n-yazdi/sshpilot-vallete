// Package build holds the verification for the project's release build.
//
// It intentionally contains no production code. The build itself is defined by
// scripts/build.sh, which is the single source of truth for the release flags;
// this package exists so that `go test ./...` -- and therefore CI -- exercises
// the reproducibility guarantee that script is supposed to provide.
package build
