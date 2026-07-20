package httpserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/helperinstall"
)

const (
	installScriptPath = "/install/vallet-helper.sh"
	installDigestPath = "/install/vallet-helper.sh.sha256"
)

// installRequest drives one request through the full handler, so every
// assertion below is made against the stack a real client meets -- middleware
// and router included -- rather than against a handler in isolation the router
// might never reach.
func installRequest(t *testing.T, enabled bool, method, target string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()

	cfg := &config.Config{}
	cfg.Install.Enabled = enabled
	handler := NewHandler(cfg, nil, okPinger{}, stubPublisher{body: []byte("ssh-ed25519 AAAA x\n")})

	req := httptest.NewRequest(method, target, nil)
	for name, values := range header {
		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func installGet(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	return installRequest(t, true, http.MethodGet, target, nil)
}

// TestInstallServesEmbeddedScriptVerbatim is the anti-drift check: the bytes a
// client receives must equal the authored file, so neither the embed nor the
// serving path can quietly transform the script.
//
// On its own this proves nothing about the mechanism -- a handler reading the
// file from disk at request time would pass it too. That gap is what
// TestInstallServingPathNeverTouchesTheFilesystem exists to close.
func TestInstallServesEmbeddedScriptVerbatim(t *testing.T) {
	t.Parallel()

	authored, err := os.ReadFile(installScriptFile(t))
	if err != nil {
		t.Fatalf("read authored script: %v", err)
	}
	if !bytes.Equal(helperinstall.Script(), authored) {
		t.Fatal("embedded script differs from internal/helperinstall/install-vallet-helper.sh")
	}

	rr := installGet(t, installScriptPath)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !bytes.Equal(rr.Body.Bytes(), authored) {
		t.Error("served script is not byte-identical to the authored file")
	}
}

// TestInstallDigestMatchesTheServedBytes is the invariant the whole endpoint
// exists for: the published hash must be the hash of what is published.
//
// The digest is recomputed here from the response body with the standard
// library, independently of anything the production code did, so a change that
// decoupled the two -- a hard-coded constant, a hash taken over a different
// buffer, a digest served for a stale copy -- fails here rather than silently
// teaching operators that verification failures are noise.
func TestInstallDigestMatchesTheServedBytes(t *testing.T) {
	t.Parallel()

	script := installGet(t, installScriptPath)
	if script.Code != http.StatusOK {
		t.Fatalf("script status = %d, want 200", script.Code)
	}
	digest := installGet(t, installDigestPath)
	if digest.Code != http.StatusOK {
		t.Fatalf("digest status = %d, want 200", digest.Code)
	}

	sum := sha256.Sum256(script.Body.Bytes())
	independent := hex.EncodeToString(sum[:])

	// The served digest document, exactly as `sha256sum -c` would read it.
	wantLine := independent + "  " + helperinstall.ScriptName + "\n"
	if got := digest.Body.String(); got != wantLine {
		t.Errorf("digest document = %q, want %q", got, wantLine)
	}

	// And the package-level accessor, which the ETag and the docs both lean on.
	if got := helperinstall.Digest(); got != independent {
		t.Errorf("helperinstall.Digest() = %q, want %q (the hash of the served bytes)", got, independent)
	}

	// The script's ETag is that same digest, so a client that verified a copy
	// can revalidate against the value it verified.
	if got, want := script.Header().Get("ETag"), `"`+independent+`"`; got != want {
		t.Errorf("script ETag = %q, want %q", got, want)
	}
}

// TestInstallDigestLineIsCheckable pins the on-the-wire format, because the
// documented one-liner pipes it into `sha256sum -c -` and that only fails
// closed if the format is one sha256sum accepts.
func TestInstallDigestLineIsCheckable(t *testing.T) {
	t.Parallel()

	line := installGet(t, installDigestPath).Body.String()
	if !strings.HasSuffix(line, "\n") {
		t.Error("digest document does not end in a newline; sha256sum -c wants a complete line")
	}
	fields := strings.Fields(line)
	if len(fields) != 2 {
		t.Fatalf("digest document has %d fields, want 2 (digest and file name): %q", len(fields), line)
	}
	if len(fields[0]) != 64 {
		t.Errorf("digest field is %d chars, want 64 hex chars", len(fields[0]))
	}
	if _, err := hex.DecodeString(fields[0]); err != nil {
		t.Errorf("digest field is not hex: %v", err)
	}
	if fields[1] != helperinstall.ScriptName {
		t.Errorf("digest names %q, want %q; sha256sum -c looks for that file in the cwd",
			fields[1], helperinstall.ScriptName)
	}
	if !strings.Contains(line, "  ") {
		t.Error("digest and name are not separated by two spaces; sha256sum -c will not parse it")
	}
}

// TestInstallHeaders pins the response headers that keep the artifact from
// being rendered, sniffed, or cached for long.
func TestInstallHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		target       string
		wantFilename string
	}{
		{installScriptPath, `attachment; filename="install-vallet-helper.sh"`},
		{installDigestPath, `attachment; filename="install-vallet-helper.sh.sha256"`},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			t.Parallel()

			rr := installGet(t, tt.target)
			assertHeader(t, rr, "Content-Type", "text/plain; charset=utf-8")
			assertHeader(t, rr, "X-Content-Type-Options", "nosniff")
			assertHeader(t, rr, "Cache-Control", installCacheControl)
			assertHeader(t, rr, "Content-Disposition", tt.wantFilename)
			if etag := rr.Header().Get("ETag"); !strings.HasPrefix(etag, `"`) || len(etag) != 66 {
				t.Errorf("ETag = %q, want a quoted sha256", etag)
			}
		})
	}
}

// TestInstallCachingAndConditionalRequests covers the validator round trip and
// HEAD, which must describe the GET it stands in for without carrying a body.
func TestInstallCachingAndConditionalRequests(t *testing.T) {
	t.Parallel()

	for _, target := range []string{installScriptPath, installDigestPath} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			first := installGet(t, target)
			etag := first.Header().Get("ETag")
			if etag == "" {
				t.Fatal("no ETag; a conditional request has nothing to validate against")
			}

			conditional := installRequest(t, true, http.MethodGet, target,
				http.Header{"If-None-Match": {etag}})
			if conditional.Code != http.StatusNotModified {
				t.Errorf("conditional GET = %d, want 304", conditional.Code)
			}

			head := installRequest(t, true, http.MethodHead, target, nil)
			if head.Code != http.StatusOK {
				t.Errorf("HEAD = %d, want 200", head.Code)
			}
			if head.Body.Len() != 0 {
				t.Errorf("HEAD returned %d body bytes, want none", head.Body.Len())
			}
			if got := head.Header().Get("ETag"); got != etag {
				t.Errorf("HEAD ETag = %q, want %q (must describe the GET)", got, etag)
			}
		})
	}
}

// TestInstallDisabledIsIndistinguishableFromAnUnknownPath is the exposure
// check. It compares the whole response -- status, body, and every header --
// with what a path the router never registered produces. Comparing only the
// status would let an "installs are disabled" hint survive in a header and
// still pass, and that hint is exactly what tells a scanner the feature exists.
func TestInstallDisabledIsIndistinguishableFromAnUnknownPath(t *testing.T) {
	t.Parallel()

	// Three segments, so it reaches no route at all: the publish wildcards are
	// one and two segments deep.
	reference := installRequest(t, false, http.MethodGet, "/no/such/path", nil)

	for _, target := range []string{installScriptPath, installDigestPath} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			rr := installRequest(t, false, http.MethodGet, target, nil)
			if rr.Code != reference.Code {
				t.Errorf("status = %d, want %d (same as an unrouted path)", rr.Code, reference.Code)
			}
			if got, want := rr.Body.String(), reference.Body.String(); got != want {
				t.Errorf("body = %q, want %q", got, want)
			}
			// The disabled response must not leak the script or its digest in
			// any form -- a 404 that still carried the bytes would satisfy the
			// status check above and defeat the whole setting.
			if bytes.Contains(rr.Body.Bytes(), []byte("vallet-helper")) {
				t.Error("disabled response body mentions the helper")
			}
			for name, want := range reference.Header() {
				if name == "X-Request-Id" {
					continue
				}
				if got := rr.Header()[name]; len(got) != len(want) || (len(got) > 0 && got[0] != want[0]) {
					t.Errorf("header %s = %v, want %v", name, got, want)
				}
			}
			for name := range rr.Header() {
				if name == "X-Request-Id" {
					continue
				}
				if _, ok := reference.Header()[name]; !ok {
					t.Errorf("header %s is present on the disabled response but not on an unrouted path", name)
				}
			}
		})
	}
}

// TestInstallEnabledByDefault pins the ADR-0013 posture: the installer is a
// bootstrap path, so a deployment that configures nothing serves it.
func TestInstallEnabledByDefault(t *testing.T) {
	t.Parallel()

	if !config.Default().Install.Enabled {
		t.Error("config.Default() disables installs; ADR-0013 requires enabled by default")
	}
	if !installEnabled(nil) {
		t.Error("a nil config must fall back to the documented default posture")
	}
	if installEnabled(&config.Config{Install: config.InstallConfig{Enabled: false}}) {
		t.Error("an explicit enabled:false must be honored")
	}
}

// TestInstallExposesNoParameterizedFetch guards the decision not to ship
// /install/{name}. Nothing under /install/ resolves except the two hard-coded
// artifacts, so there is no segment for a traversal to ride in on.
func TestInstallExposesNoParameterizedFetch(t *testing.T) {
	t.Parallel()

	probes := []string{
		"/install/",
		"/install/vallet-helper.sh/",
		"/install/../../etc/passwd",
		"/install/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"/install/vallet-helper",
		"/install/config.yaml",
		"/install/vallet.example.yaml",
	}
	for _, target := range probes {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			rr := installGet(t, target)
			body := rr.Body.Bytes()

			// The property under test is that no request-derived path selects
			// a file. A two-segment probe under /install/ does legitimately
			// reach the /{handle}/{set} publish wildcard -- that is a datastore
			// lookup for a handle named "install", not a filesystem read -- so
			// the stub publisher's key list is an acceptable body here.
			//
			// What must never happen is a probe reaching an install artifact by
			// a path that is not one of the two literal routes, or reaching
			// anything that looks like a file off the disk.
			if bytes.Contains(body, []byte("#!/bin/sh")) {
				t.Errorf("probe reached the install script through a path that is not a literal route: %.80q", body)
			}
			if bytes.Contains(body, []byte(helperinstall.Digest())) {
				t.Errorf("probe reached the digest through a path that is not a literal route: %.80q", body)
			}
			if bytes.Contains(body, []byte("root:")) {
				t.Error("response body looks like /etc/passwd")
			}
			if ct := rr.Header().Get("Content-Disposition"); ct != "" {
				t.Errorf("probe got Content-Disposition %q; only the two literal install routes set it", ct)
			}
		})
	}
}

// TestInstallRoutesCannotBeShadowedByAHandle checks the consequence of the
// install routes being two-segment literals rather than a subtree.
//
// A handle is any single path segment, so a handle named "install" would own
// /install/<anything> via the /{handle}/{set} wildcard. It must not be able to
// own the two install artifacts: an owner who could serve their own bytes at
// the URL the docs tell strangers to run would have a remote code execution
// primitive against every operator who followed those docs. ServeMux prefers
// the literal, so the artifacts win -- this pins that, because it is a routing
// precedence rule and not something the handler code makes obvious.
func TestInstallRoutesCannotBeShadowedByAHandle(t *testing.T) {
	t.Parallel()

	for _, target := range []string{installScriptPath, installDigestPath} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			// The stub publisher answers every handle lookup with key material.
			// If the wildcard won, that is what would come back.
			rr := installGet(t, target)
			if bytes.Contains(rr.Body.Bytes(), []byte("ssh-ed25519")) {
				t.Fatalf("%s was served by the publish wildcard, not the install route", target)
			}
			assertHeader(t, rr, "Content-Type", "text/plain; charset=utf-8")
			if rr.Header().Get("Content-Disposition") == "" {
				t.Errorf("%s did not reach the install handler", target)
			}
		})
	}
}

// TestInstallServingPathNeverTouchesTheFilesystem is a mechanism check, and it
// exists precisely because TestInstallServesEmbeddedScriptVerbatim is not one.
//
// That test compares the served bytes with the file on disk, which a handler
// that read the file at request time would also satisfy -- passing while doing
// exactly the thing the design forbids. So this reads the source instead and
// asserts the serving path cannot reach the filesystem at all: no os,
// path/filepath, or embed import, and no call to a file-opening function.
// Replacing the embed with a disk read then fails here rather than sailing
// through green.
//
// embed is on the forbidden list even though it is not a disk read: the embed
// belongs in internal/helperinstall beside the file, and an embed directive
// appearing here would mean a second copy of the script in the tree.
func TestInstallServingPathNeverTouchesTheFilesystem(t *testing.T) {
	t.Parallel()

	forbiddenPackages := map[string]bool{
		`"os"`: true, `"io/ioutil"`: true, `"path/filepath"`: true, `"embed"`: true,
		`"io/fs"`: true, `"net/http/httputil"`: true,
	}
	forbiddenCalls := map[string]bool{
		"ReadFile": true, "Open": true, "OpenFile": true, "ReadDir": true,
		"Stat": true, "Sub": true, "ServeFile": true, "FileServer": true,
		"Dir": true, "FS": true, "Create": true,
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(sourceDir(t), "install.go"), nil, 0)
	if err != nil {
		t.Fatalf("parse install.go: %v", err)
	}
	for _, imp := range file.Imports {
		if forbiddenPackages[imp.Path.Value] {
			t.Errorf("install.go imports %s; the script is embedded, never read at request time",
				imp.Path.Value)
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && forbiddenCalls[sel.Sel.Name] {
			t.Errorf("install.go calls %s at %s; the serving path must not open anything",
				sel.Sel.Name, fset.Position(call.Pos()))
		}
		return true
	})
}

// TestInstallScriptFailsClosed reads the artifact itself and asserts the
// properties that make it safe to hand to a stranger.
//
// It is a source-level check on purpose: these are properties of what the
// script may contain, which no single execution can demonstrate the absence of.
// The behavioral tests further down run the script instead, against a stub `go`
// so nothing is installed, for the properties that only appear at runtime.
func TestInstallScriptFailsClosed(t *testing.T) {
	t.Parallel()

	script := string(helperinstall.Script())

	required := map[string]string{
		"set -eu":               "no errexit; a failed step would be ignored and the install would continue",
		"--version is required": "the script would install an unguessable default version",
		"refusing to install an unpinned version": "an explicit 'latest' would slip past the required-version check",
		"GOSUMDB":   "module checksum verification is not forced on",
		"GOFLAGS":   "a caller's GOFLAGS could disable verification",
		"GOPRIVATE": "a caller's GOPRIVATE could bypass the checksum database",
	}
	for needle, why := range required {
		if !strings.Contains(script, needle) {
			t.Errorf("script no longer contains %q: %s", needle, why)
		}
	}

	// Nothing in the installer may itself fetch and execute, disable TLS
	// verification, or weaken module checking. The served script is the one
	// artifact operators are told to run; an unverified fetch hidden inside it
	// would undo every control this endpoint adds.
	//
	// Only executable lines are scanned. The script's comments describe the
	// things it refuses to do, and matching those would fail the test for
	// documenting a hazard rather than for containing one -- which would push
	// the next author to delete the explanation instead of the danger.
	code := shellCode(script)
	forbidden := map[string]string{
		"| sh":                   "a pipe to a shell",
		"| bash":                 "a pipe to a shell",
		"--insecure":             "a TLS verification bypass",
		"--no-check-certificate": "wget's TLS verification bypass",
		"GOSUMDB=off":            "module checksum verification turned off",
		"GOFLAGS=-insecure":      "insecure module fetching",
		"eval ":                  "dynamic shell evaluation",
		"curl ":                  "an unverified network fetch inside the installer",
		"wget ":                  "an unverified network fetch inside the installer",
	}
	for needle, why := range forbidden {
		if strings.Contains(code, needle) {
			t.Errorf("script executes %q: %s", needle, why)
		}
	}

	// "@latest" may appear only in the branch that rejects it. Anywhere else it
	// would be the unpinned install the required checks above forbid.
	for _, line := range strings.Split(code, "\n") {
		if strings.Contains(line, "@latest") && !strings.Contains(line, "die ") &&
			!strings.Contains(line, "case ") {
			t.Errorf("script line uses @latest outside the rejection branch: %q", line)
		}
	}

	if !strings.HasPrefix(script, "#!/bin/sh\n") {
		t.Error("script does not start with a POSIX sh shebang")
	}
}

// shellCode strips comment lines and the shebang, leaving the lines the shell
// would actually execute.
//
// It is a line-level filter, not a shell parser: a trailing comment on a code
// line is kept, which errs toward scanning more rather than less.
func shellCode(script string) string {
	var kept []string
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// TestInstallScriptRefusesToGuessAnInstallDirWhenHomeIsUnset runs the script
// with HOME removed from the environment.
//
// The tempting fix for an unset HOME is a relative fallback such as ./bin, and
// that is what this test exists to prevent: it would drop an executable into
// whatever directory the operator happened to be standing in, which is not on
// PATH and, in a container, may be a mount other processes read. The script is
// fail-closed everywhere else -- unpinned version, missing toolchain -- so it
// refuses here too and names the flag that fixes it.
func TestInstallScriptRefusesToGuessAnInstallDirWhenHomeIsUnset(t *testing.T) {
	t.Parallel()

	res := runInstallScript(t, t.TempDir(), nil, "--version", "v1.2.3")

	if res.err == nil {
		t.Fatalf("script succeeded with HOME unset; stdout=%q", res.stdout)
	}
	if !strings.Contains(res.stderr, "--bin-dir") {
		t.Errorf("stderr does not tell the operator to pass --bin-dir: %q", res.stderr)
	}
	if strings.Contains(res.stdout, "shim-gobin=") {
		t.Errorf("script reached go install without an install directory: %q", res.stdout)
	}
}

// TestInstallScriptResolvesARelativeBinDirToAnAbsolutePath pins the fix for a
// relative --bin-dir: `go install` rejects a relative GOBIN outright, so the
// script has to resolve it before exporting or the documented flag simply does
// not work.
func TestInstallScriptResolvesARelativeBinDirToAnAbsolutePath(t *testing.T) {
	t.Parallel()

	work := realPath(t, t.TempDir())
	res := runInstallScript(t, work, []string{"HOME=" + work},
		"--version", "v1.2.3", "--bin-dir", "bin")

	if res.err != nil {
		t.Fatalf("script failed: %v\nstdout=%q\nstderr=%q", res.err, res.stdout, res.stderr)
	}

	want := "shim-gobin=" + filepath.Join(work, "bin")
	if !strings.Contains(res.stdout, want) {
		t.Errorf("GOBIN handed to go install is not the absolute form of --bin-dir\ngot:  %q\nwant to contain: %q", res.stdout, want)
	}
}

// TestInstallScriptDryRunTouchesNothing keeps the directory creation that the
// absolute-path resolution needs from turning --dry-run into something that
// writes to the filesystem.
func TestInstallScriptDryRunTouchesNothing(t *testing.T) {
	t.Parallel()

	work := realPath(t, t.TempDir())
	res := runInstallScript(t, work, []string{"HOME=" + work},
		"--version", "v1.2.3", "--bin-dir", "bin", "--dry-run")

	if res.err != nil {
		t.Fatalf("dry run failed: %v\nstderr=%q", res.err, res.stderr)
	}
	if strings.Contains(res.stdout, "shim-gobin=") {
		t.Errorf("dry run invoked go: %q", res.stdout)
	}
	if _, err := os.Stat(filepath.Join(work, "bin")); !os.IsNotExist(err) {
		t.Errorf("dry run created the install directory (stat err = %v)", err)
	}
}

type installScriptResult struct {
	stdout string
	stderr string
	err    error
}

// runInstallScript executes the served script with a stub `go` first on PATH,
// so the argument handling can be observed without installing anything.
//
// The source-level checks above cannot see this: whether a relative --bin-dir
// survives to GOBIN is a property of the running script, not of its text. The
// stub prints the GOBIN it was handed, which is the value under test, and
// never contacts the network.
func runInstallScript(t *testing.T, dir string, env []string, args ...string) installScriptResult {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("the installer is a POSIX sh script")
	}

	shimDir := t.TempDir()
	shim := "#!/bin/sh\nprintf 'shim-gobin=%s\\n' \"$GOBIN\"\nprintf 'shim-args=%s\\n' \"$*\"\n"
	if err := os.WriteFile(filepath.Join(shimDir, "go"), []byte(shim), 0o700); err != nil {
		t.Fatalf("write go stub: %v", err)
	}

	// HOME is supplied only by the caller: its absence is one of the behaviors
	// under test, so it must not leak in from the test process.
	cmd := exec.Command("/bin/sh", append([]string{installScriptFile(t)}, args...)...)
	cmd.Dir = dir
	cmd.Env = append([]string{"PATH=" + shimDir + ":/usr/bin:/bin"}, env...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	return installScriptResult{stdout: stdout.String(), stderr: stderr.String(), err: err}
}

// realPath resolves symlinks so a path compared against one the script produced
// with `cd -P` matches; on macOS t.TempDir() sits under a symlinked /tmp.
func realPath(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("resolve %s: %v", path, err)
	}
	return resolved
}

// installScriptFile locates the authored script relative to this source file,
// so the test does not depend on the working directory.
func installScriptFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(sourceDir(t), "..", "..", "helperinstall", helperinstall.ScriptName)
}
