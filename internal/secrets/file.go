package secrets

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// fileScheme is the reference scheme handled by FileProvider.
const fileScheme = "file"

// PermMode selects how the file provider reacts to a world-readable secret
// file (group- or other-readable permission bits).
type PermMode int

const (
	// PermError rejects world-readable secret files. This is the production
	// posture: a secret readable by other users is a hard, fail-closed error.
	PermError PermMode = iota
	// PermWarn logs a warning but accepts world-readable secret files. This is
	// intended for development.
	PermWarn
)

// worldReadableBits are the group/other read+write+execute permission bits.
// Any of these set on a secret file means it is not owner-private.
const worldReadableBits = os.FileMode(0o077)

// FileOptions configures a FileProvider.
type FileOptions struct {
	// PermMode selects error-vs-warn behavior for world-readable files. The
	// caller (config layer) chooses this based on environment; the secrets
	// package never imports config to make this decision itself.
	PermMode PermMode
	// Logger receives the warning in PermWarn mode; nil means slog.Default.
	Logger *slog.Logger
}

// FileProvider resolves "file:/path" references by reading the referenced file.
type FileProvider struct {
	opts FileOptions
}

// NewFileProvider returns a FileProvider with the given options.
func NewFileProvider(opts FileOptions) *FileProvider {
	return &FileProvider{opts: opts}
}

// Scheme implements Provider.
func (p *FileProvider) Scheme() string { return fileScheme }

// Resolve reads the referenced file, strips one trailing newline, and returns
// the contents as a Redacted value. An empty file (after stripping) is an
// error. World-readable permissions are an error in PermError mode and a
// warning in PermWarn mode. Errors name the reference (the path), never the
// contents.
//
// The permission check and the read operate on a single open descriptor: the
// path is opened once and every subsequent decision (fstat for mode, read for
// contents) uses that descriptor. Statting a path and then separately opening
// or reading it would be a time-of-check/time-of-use race, where the path (or
// a symlink's target, or its permission bits) could change between the two
// syscalls. A symlink is followed by the open; the fstat and read then observe
// the exact inode the open resolved to, so the permission that is checked is
// the permission of the bytes that are read.
func (p *FileProvider) Resolve(_ context.Context, opaque string) (Redacted, error) {
	ref := fileScheme + ":" + opaque

	f, err := os.Open(opaque)
	if err != nil {
		return "", fmt.Errorf("secrets: cannot open file for reference %q: %w", ref, err)
	}
	defer func() { _ = f.Close() }()

	fi, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("secrets: cannot stat file for reference %q: %w", ref, err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("secrets: reference %q is not a regular file", ref)
	}

	if perm := fi.Mode().Perm(); perm&worldReadableBits != 0 {
		switch p.opts.PermMode {
		case PermError:
			return "", fmt.Errorf("secrets: file for reference %q has insecure permissions %#o (group/other access); want 0600 or stricter", ref, perm)
		case PermWarn:
			logger := p.opts.Logger
			if logger == nil {
				logger = slog.Default()
			}
			logger.Warn("secret file has group/other-readable permissions",
				slog.String("reference", ref),
				slog.String("perm", fmt.Sprintf("%#o", perm)),
			)
		}
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("secrets: cannot read file for reference %q: %w", ref, err)
	}

	value := stripOneTrailingNewline(string(data))
	if value == "" {
		return "", fmt.Errorf("secrets: file for reference %q is empty", ref)
	}
	return Redacted(value), nil
}

// stripOneTrailingNewline removes a single trailing "\n" (and a preceding "\r"
// if present), which is the common artifact of writing a secret to a file.
func stripOneTrailingNewline(s string) string {
	s = strings.TrimSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\r")
	return s
}
