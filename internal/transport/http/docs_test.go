package httpserver

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/api/openapi"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// docsRequest drives one request through the full handler, so every assertion
// below is made against the stack a real client meets — middleware included —
// rather than against a handler in isolation that the router might not even
// reach.
func docsRequest(t *testing.T, enabled bool, method, target string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()

	cfg := &config.Config{}
	cfg.Docs.Enabled = enabled
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

func docsGet(t *testing.T, target string, accept string) *httptest.ResponseRecorder {
	t.Helper()

	header := http.Header{}
	if accept != "" {
		header.Set("Accept", accept)
	}
	return docsRequest(t, true, http.MethodGet, target, header)
}

// TestDocsContentNegotiation pins the representation chosen for each shape of
// Accept a client can send.
//
// The unsatisfiable and malformed rows are the point of the table: both must
// land on JSON, because the failure mode worth preventing is not "wrong
// representation" but "the negotiation fell through to an error, or to
// whichever branch happened to be last".
func TestDocsContentNegotiation(t *testing.T) {
	t.Parallel()

	const (
		jsonType = "application/json; charset=utf-8"
		yamlType = "application/yaml; charset=utf-8"
		htmlType = "text/html; charset=utf-8"
	)

	tests := []struct {
		name   string
		accept string
		want   string
	}{
		{"absent accept defaults to json", "", jsonType},
		{"explicit json", "application/json", jsonType},
		{"wildcard is ambiguous and yields json", "*/*", jsonType},
		{"type wildcard for json", "application/*", jsonType},
		{"explicit yaml", "application/yaml", yamlType},
		{"legacy text yaml spelling", "text/yaml", yamlType},
		{"legacy x-yaml spelling", "application/x-yaml", yamlType},
		{"yaml preferred by quality", "application/json;q=0.2, application/yaml;q=0.9", yamlType},
		{"json preferred by quality", "application/json;q=0.9, application/yaml;q=0.2", jsonType},
		{"equal quality ties to json", "application/yaml;q=0.5, application/json;q=0.5", jsonType},
		{"unsatisfiable type falls back to json", "application/xml", jsonType},
		{"unparseable accept falls back to json", "application/json;;;=", jsonType},
		{"garbage accept falls back to json", "\x00not a media type", jsonType},
		{"empty elements are ignored", ",,,", jsonType},
		{"out of range quality is ignored", "application/yaml;q=9", jsonType},
		// A specific range outranks a wildcard even when the wildcard carries
		// the higher q: RFC 9110 selects by specificity first. Scoring by
		// quality alone would read this as a request for YAML.
		{"specificity beats quality", "application/json, */*;q=0.9", jsonType},
		{"explicit html", "text/html", htmlType},
		{"a real browser accept yields the ui", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", htmlType},
		{"html declined by quality stays json", "text/html;q=0.1, application/json;q=0.9", jsonType},
		{"yaml outranks html", "text/html;q=0.3, application/yaml;q=0.8", yamlType},
		{"html outranks yaml", "text/html;q=0.8, application/yaml;q=0.3", htmlType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rr := docsGet(t, "/docs/", tt.accept)
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rr.Code)
			}
			if got := rr.Header().Get("Content-Type"); got != tt.want {
				t.Errorf("Content-Type = %q, want %q", got, tt.want)
			}
			if got := rr.Header().Get("Vary"); got != "Accept" {
				t.Errorf("Vary = %q, want Accept; caches would cross representations", got)
			}
		})
	}
}

// TestDocsServesEmbeddedSpecVerbatim is the anti-drift check. It compares the
// bytes a client receives against the authored file on disk, so neither the
// embed nor the serving path can quietly transform the contract.
func TestDocsServesEmbeddedSpecVerbatim(t *testing.T) {
	t.Parallel()

	authored, err := os.ReadFile(specFile(t))
	if err != nil {
		t.Fatalf("read authored spec: %v", err)
	}
	if !bytes.Equal(openapi.Spec, authored) {
		t.Fatal("embedded spec differs from api/openapi/openapi.yaml")
	}

	for _, target := range []string{"/docs/", "/docs/spec/openapi.yaml"} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			rr := docsGet(t, target, "application/yaml")
			if !bytes.Equal(rr.Body.Bytes(), authored) {
				t.Errorf("%s body is not byte-identical to the authored spec", target)
			}
		})
	}
}

// TestDocsJSONIsTheSameDocument checks the JSON representation is a faithful
// conversion rather than an independent file that could drift.
func TestDocsJSONIsTheSameDocument(t *testing.T) {
	t.Parallel()

	rr := docsGet(t, "/docs/spec/openapi.json", "application/json")
	var doc struct {
		OpenAPI string                    `json:"openapi"`
		Paths   map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("served JSON does not parse: %v", err)
	}
	if doc.OpenAPI == "" {
		t.Error("served JSON has no openapi version field")
	}
	for _, want := range []string{"/docs/", "/docs/spec/openapi.json", "/healthz"} {
		if _, ok := doc.Paths[want]; !ok {
			t.Errorf("served JSON is missing path %q", want)
		}
	}
}

// TestDocsFixedURLsIgnoreAccept proves the explicit paths are explicit: their
// representation is a property of the URL, so tooling that pins one gets the
// same bytes whatever it happens to send.
func TestDocsFixedURLsIgnoreAccept(t *testing.T) {
	t.Parallel()

	tests := []struct {
		target string
		want   string
	}{
		{"/docs/spec/openapi.json", "application/json; charset=utf-8"},
		{"/docs/spec/openapi.yaml", "application/yaml; charset=utf-8"},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			t.Parallel()

			for _, accept := range []string{"", "*/*", "application/json", "application/yaml", "text/html"} {
				rr := docsGet(t, tt.target, accept)
				if got := rr.Header().Get("Content-Type"); got != tt.want {
					t.Errorf("Accept %q: Content-Type = %q, want %q", accept, got, tt.want)
				}
			}
		})
	}
}

// TestDocsDisabledIsIndistinguishableFromAnUnknownPath is the exposure check.
//
// It asserts the whole response — status, body, and every header — matches what
// a path the router never registered produces. Comparing only the status would
// let a "docs are disabled" hint survive in a header or body and still pass,
// and that hint is precisely what tells a scanner the feature exists.
func TestDocsDisabledIsIndistinguishableFromAnUnknownPath(t *testing.T) {
	t.Parallel()

	// Three segments, so it reaches no route at all: the publish wildcards are
	// one and two segments deep.
	reference := docsRequest(t, false, http.MethodGet, "/no/such/path", nil)

	for _, target := range []string{"/docs", "/docs/", "/docs/spec/openapi.json", "/docs/spec/openapi.yaml"} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			rr := docsRequest(t, false, http.MethodGet, target, nil)
			if rr.Code != reference.Code {
				t.Errorf("status = %d, want %d (same as an unrouted path)", rr.Code, reference.Code)
			}
			if got, want := rr.Body.String(), reference.Body.String(); got != want {
				t.Errorf("body = %q, want %q", got, want)
			}
			for name, want := range reference.Header() {
				// Request-correlation headers legitimately differ per request.
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
					t.Errorf("header %s is present on the disabled docs response but not on an unrouted path", name)
				}
			}
		})
	}
}

// TestDocsEnabledByDefault pins the ADR-0021 posture. The contract is public,
// so a deployment that configures nothing serves it.
func TestDocsEnabledByDefault(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	if !cfg.Docs.Enabled {
		t.Error("config.Default() disables docs; ADR-0021 requires enabled by default")
	}
	if !docsEnabled(nil) {
		t.Error("a nil config must fall back to the documented default posture")
	}
	if docsEnabled(&config.Config{Docs: config.DocsConfig{Enabled: false}}) {
		t.Error("an explicit enabled:false must be honored")
	}
}

// TestDocsCachingAndConditionalRequests covers the validator round trip and
// HEAD, which must describe the GET it stands in for without carrying a body.
func TestDocsCachingAndConditionalRequests(t *testing.T) {
	t.Parallel()

	for _, target := range []string{"/docs/", "/docs/spec/openapi.json", "/docs/spec/openapi.yaml"} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			first := docsGet(t, target, "")
			etag := first.Header().Get("ETag")
			if etag == "" {
				t.Fatal("no ETag; a conditional request has nothing to validate against")
			}
			if got := first.Header().Get("Cache-Control"); got != docsCacheControl {
				t.Errorf("Cache-Control = %q, want %q", got, docsCacheControl)
			}
			if got := first.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
			}

			conditional := docsRequest(t, true, http.MethodGet, target, http.Header{"If-None-Match": {etag}})
			if conditional.Code != http.StatusNotModified {
				t.Errorf("conditional GET = %d, want 304", conditional.Code)
			}

			head := docsRequest(t, true, http.MethodHead, target, nil)
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

// TestDocsExposeNoParameterizedFetch guards the decision not to ship
// /docs/spec/{name}. Nothing under /docs/spec/ resolves except the two
// hard-coded documents, so there is no segment for a traversal to ride in on.
func TestDocsExposeNoParameterizedFetch(t *testing.T) {
	t.Parallel()

	probes := []string{
		"/docs/spec/openapi.json/",
		"/docs/spec/../../etc/passwd",
		"/docs/spec/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"/docs/spec/openapi.txt",
		"/docs/spec/config.yaml",
		"/docs/../docs/spec/openapi.json",
	}
	for _, target := range probes {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			rr := docsGet(t, target, "")
			// A traversal that reached a file would be a 200 carrying bytes
			// that are not this contract. Anything that is not a 200 is fine;
			// a 200 is only fine if the mux normalized the path onto one of
			// the real routes.
			if rr.Code == http.StatusOK && !bytes.Contains(rr.Body.Bytes(), []byte("openapi")) {
				t.Errorf("status 200 with a body that is not the contract: %.80q", rr.Body.String())
			}
			if bytes.Contains(rr.Body.Bytes(), []byte("root:")) {
				t.Error("response body looks like /etc/passwd")
			}
		})
	}
}

// TestDocsServingPathNeverTouchesTheFilesystem is a mechanism check, and it
// exists because the byte-identity test above is not one.
//
// That test compares the served bytes with the file on disk, which a handler
// that read the file at request time would also satisfy — passing while doing
// precisely the thing the design forbids. So this reads the source instead and
// asserts the serving path cannot reach the filesystem at all: no os or
// path/filepath import, and no call to a file-opening function. Replacing the
// embed with a disk read then fails here rather than sailing through green.
func TestDocsServingPathNeverTouchesTheFilesystem(t *testing.T) {
	t.Parallel()

	forbiddenPackages := map[string]bool{
		`"os"`: true, `"io/ioutil"`: true, `"path/filepath"`: true, `"embed"`: true,
	}
	forbiddenCalls := map[string]bool{
		"ReadFile": true, "Open": true, "OpenFile": true, "ReadDir": true,
		"Stat": true, "Sub": true, "ServeFile": true, "FileServer": true, "Dir": true,
	}

	for _, name := range []string{"docs.go", "docsui.go"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, filepath.Join(sourceDir(t), name), nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			for _, imp := range file.Imports {
				if forbiddenPackages[imp.Path.Value] {
					t.Errorf("%s imports %s; the contract is embedded, never read at request time",
						name, imp.Path.Value)
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && forbiddenCalls[sel.Sel.Name] {
					t.Errorf("%s calls %s at %s; the serving path must not open anything",
						name, sel.Sel.Name, fset.Position(call.Pos()))
				}
				return true
			})
		})
	}
}
