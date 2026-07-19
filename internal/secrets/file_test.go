package secrets

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string, perm os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	// WriteFile is subject to umask; enforce exact perm.
	if err := os.Chmod(path, perm); err != nil {
		t.Fatalf("chmod %s: %v", name, err)
	}
	return path
}

func TestFileProviderResolve(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "secret", "the-dsn-value\n", 0o600)

	p := NewFileProvider(FileOptions{PermMode: PermError})
	got, err := p.Resolve(context.Background(), path)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Reveal() != "the-dsn-value" {
		t.Errorf("Resolve = %q, want trailing newline stripped", got.Reveal())
	}
}

func TestFileProviderStripsSingleNewline(t *testing.T) {
	dir := t.TempDir()
	// Two trailing newlines: only one is stripped.
	path := writeFile(t, dir, "secret", "value\n\n", 0o600)
	got, err := NewFileProvider(FileOptions{}).Resolve(context.Background(), path)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Reveal() != "value\n" {
		t.Errorf("Resolve = %q, want %q", got.Reveal(), "value\n")
	}
}

func TestFileProviderEmpty(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "secret", "\n", 0o600)
	_, err := NewFileProvider(FileOptions{}).Resolve(context.Background(), path)
	errNames(t, err, "file:"+path, "")
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error %q should mention empty", err)
	}
}

func TestFileProviderMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope")
	_, err := NewFileProvider(FileOptions{}).Resolve(context.Background(), path)
	errNames(t, err, "file:"+path, "")
}

func TestFileProviderPermError(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "secret", "value", 0o644)
	_, err := NewFileProvider(FileOptions{PermMode: PermError}).Resolve(context.Background(), path)
	errNames(t, err, "file:"+path, "value")
	if !strings.Contains(err.Error(), "permission") {
		t.Errorf("error %q should mention permissions", err)
	}
}

func TestFileProviderPermWarn(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "secret", "value", 0o644)

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	p := NewFileProvider(FileOptions{PermMode: PermWarn, Logger: logger})

	got, err := p.Resolve(context.Background(), path)
	if err != nil {
		t.Fatalf("Resolve should warn not error: %v", err)
	}
	if got.Reveal() != "value" {
		t.Errorf("Resolve = %q", got.Reveal())
	}
	log := buf.String()
	if !strings.Contains(log, "permission") && !strings.Contains(log, "readable") {
		t.Errorf("expected permission warning, got %q", log)
	}
	if strings.Contains(log, "value") {
		t.Errorf("warning leaked secret value: %q", log)
	}
}

func TestFileProviderDirectory(t *testing.T) {
	dir := t.TempDir()
	_, err := NewFileProvider(FileOptions{}).Resolve(context.Background(), dir)
	errNames(t, err, "file:"+dir, "")
}

func TestFileProviderScheme(t *testing.T) {
	if NewFileProvider(FileOptions{}).Scheme() != "file" {
		t.Fatal("file scheme mismatch")
	}
}
