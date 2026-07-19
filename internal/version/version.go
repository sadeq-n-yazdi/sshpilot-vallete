// Package version exposes build version information for sshpilot-vallet.
package version

// Version is the current build version. It defaults to a development
// placeholder and is intended to be overridden at build time via -ldflags.
const Version = "0.0.0-dev"

// String returns the human-readable version string.
func String() string {
	return Version
}
