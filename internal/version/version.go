// Package version exposes build version information for sshpilot-vallet.
package version

// Version is the current build version. It defaults to a development
// placeholder and is intended to be overridden at build time via -ldflags.
// It must be a var (not a const): the linker's -X flag can only rewrite
// package-level string variables.
var Version = "0.0.0-dev"

// String returns the human-readable version string.
func String() string {
	return Version
}
