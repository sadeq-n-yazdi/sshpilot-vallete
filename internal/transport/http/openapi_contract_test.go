package httpserver

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/publish"
)

// The contract tests hold api/openapi/openapi.yaml and the router to each
// other. A hand-authored spec with no test is a document that rots silently:
// it keeps looking authoritative while the code moves out from under it, and
// the first consumer to trust it is the one who finds out.
//
// The checks run in both directions on purpose. A spec entry with no route is a
// promise the server does not keep; a route with no spec entry is an endpoint
// nobody reviewed against the contract, which is the drift that actually
// matters here — an unlisted route is how an endpoint reaches production
// without anyone deciding what it should return.
//
// The spec is parsed with gopkg.in/yaml.v3, already a direct dependency, rather
// than with an OpenAPI toolkit. The drift being detected is route-level, not
// schema-level, so a validator's object model would be a large new dependency
// bought for a document this test reads four fields out of.

// routeParams are the concrete values substituted for the wildcard segments of
// a spec path so it can be requested. Any value routes; these are only readable
// stand-ins.
var routeParams = map[string]string{"{handle}": "alice", "{set}": "work"}

// minRegisteredRoutes guards against a vacuous pass.
//
// The router scan reads string literals out of the source. If the registrations
// are ever moved behind a constant, a slice, or a helper, the scan would find
// nothing, every route would trivially "appear in the spec", and this test
// would go green precisely when it stopped testing anything. Asserting a floor
// on the count turns that refactor into a visible failure that says to update
// the scanner, rather than a silent loss of coverage.
const minRegisteredRoutes = 4

// specDoc is the sliver of OpenAPI this test needs: which methods each path
// declares, and which status codes each of those declares.
//
// A path item's children are decoded lazily, because they are not homogeneous:
// alongside the operations sits a "parameters" sequence, which does not fit an
// operation's shape.
type specDoc struct {
	Paths map[string]map[string]yaml.Node `yaml:"paths"`
}

type specOperation struct {
	Responses map[string]yaml.Node `yaml:"responses"`
}

// httpMethods are the operation keys OpenAPI defines on a path item. Anything
// else under a path (parameters, summary) is not an operation.
var httpMethods = []string{"get", "head", "post", "put", "patch", "delete", "options", "trace"}

// operation is one path+method pair drawn from the spec.
type operation struct {
	path     string
	method   string
	statuses []string
}

// loadSpec reads and parses the OpenAPI document.
func loadSpec(t *testing.T) []operation {
	t.Helper()

	raw, err := os.ReadFile(specFile(t))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	var doc specDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse spec: %v", err)
	}

	var ops []operation
	for path, item := range doc.Paths {
		for method, node := range item {
			if !slices.Contains(httpMethods, method) {
				continue
			}
			var op specOperation
			if err := node.Decode(&op); err != nil {
				t.Fatalf("spec: decode %s %s: %v", strings.ToUpper(method), path, err)
			}
			if len(op.Responses) == 0 {
				t.Errorf("spec: %s %s declares no responses", strings.ToUpper(method), path)
			}
			statuses := make([]string, 0, len(op.Responses))
			for code := range op.Responses {
				statuses = append(statuses, code)
			}
			slices.Sort(statuses)
			ops = append(ops, operation{path: path, method: method, statuses: statuses})
		}
	}
	if len(ops) == 0 {
		t.Fatal("spec declares no operations; the parse is not reading the document")
	}
	slices.SortFunc(ops, func(a, b operation) int {
		return strings.Compare(a.path+a.method, b.path+b.method)
	})
	return ops
}

// registeredRoutes extracts the route patterns the router registers, by reading
// the string literals passed to mux.Handle in router.go.
//
// It parses the source rather than interrogating the ServeMux because the mux
// does not expose its patterns, and rather than duplicating the table in a
// variable the router would read — that would only prove the copy matches
// itself. Reading the registrations means this test tracks whatever the router
// actually does, and requires no change to router.go.
func registeredRoutes(t *testing.T) []string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, routerFile(t), nil, 0)
	if err != nil {
		t.Fatalf("parse router: %v", err)
	}

	var patterns []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc") {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			// A non-literal pattern is invisible to this scan, so it must not
			// pass unnoticed: it would be a route with no contract check.
			t.Errorf("router registers a non-literal pattern at %s; update this scanner",
				fset.Position(call.Pos()))
			return true
		}
		pattern, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Errorf("unquote pattern %s: %v", lit.Value, err)
			return true
		}
		patterns = append(patterns, pattern)
		return true
	})

	if len(patterns) < minRegisteredRoutes {
		t.Fatalf("found %d registered routes, expected at least %d; the scanner is no longer reading the router",
			len(patterns), minRegisteredRoutes)
	}
	slices.Sort(patterns)
	return patterns
}

// TestSpecCoversEveryRegisteredRoute is the direction that catches a new
// endpoint shipped without a contract. Every pattern the router registers must
// appear in the spec as that path and method.
func TestSpecCoversEveryRegisteredRoute(t *testing.T) {
	t.Parallel()

	spec := loadSpec(t)
	for _, pattern := range registeredRoutes(t) {
		method, path, ok := strings.Cut(pattern, " ")
		if !ok {
			t.Errorf("route %q is not method-qualified; it cannot be matched to the spec", pattern)
			continue
		}
		method = strings.ToLower(method)
		documented := slices.ContainsFunc(spec, func(op operation) bool {
			return op.path == path && op.method == method
		})
		if !documented {
			t.Errorf("route %q is registered but absent from the OpenAPI spec", pattern)
		}
	}
}

// TestEverySpecOperationIsRoutable is the other direction: a documented
// operation that does not route is a promise the server does not keep. Each is
// driven through the real handler and must answer with a status the spec
// declares for it — which also rules out the router answering 404 or 405
// because the path or method was never registered.
//
// Known limit, and the reason this is not the only direction checked: the
// /{handle} wildcard genuinely routes EVERY single-segment path, so a spec
// entry like /nonexistent would be served as a handle lookup and pass here. The
// check has real teeth from two segments up, where a bogus path reaches no
// route and 404s. Single-segment overreach is caught by review rather than by
// this test, because at the HTTP level such a path is not in fact unroutable —
// there is no failure for the test to observe.
func TestEverySpecOperationIsRoutable(t *testing.T) {
	t.Parallel()

	handler := NewHandler(nil, nil, okPinger{}, stubPublisher{body: []byte("ssh-ed25519 AAAA x\n")})
	for _, op := range loadSpec(t) {
		t.Run(op.method+" "+op.path, func(t *testing.T) {
			t.Parallel()

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, httptest.NewRequest(strings.ToUpper(op.method), concretePath(op.path), nil))
			got := strconv.Itoa(rr.Code)
			if !slices.Contains(op.statuses, got) {
				t.Errorf("got %s, which the spec does not document for this operation (documents %v)",
					got, op.statuses)
			}
		})
	}
}

// TestSpecDocumentsEveryReachableStatus drives each status the spec declares
// for the publish and probe paths and checks the code can actually produce it.
// A documented status no handler emits is as much a lie as an undocumented one.
func TestSpecDocumentsEveryReachableStatus(t *testing.T) {
	t.Parallel()

	body := []byte("ssh-ed25519 AAAA x\n")
	publishPaths := []string{"/{handle}", "/{handle}/{set}"}

	reached := map[string]map[string]bool{}
	mark := func(path string, code int) {
		if reached[path] == nil {
			reached[path] = map[string]bool{}
		}
		reached[path][strconv.Itoa(code)] = true
	}

	for _, path := range publishPaths {
		target := concretePath(path)

		ok := contractDo(t, stubPublisher{body: body}, http.MethodGet, target, "")
		mark(path, ok.Code)
		mark(path, contractDo(t, stubPublisher{body: body}, http.MethodGet, target, ok.Header().Get("ETag")).Code)
		mark(path, contractDo(t, stubPublisher{err: publish.ErrNotFound}, http.MethodGet, target, "").Code)
		mark(path, contractDo(t, stubPublisher{err: errors.New("datastore down")}, http.MethodGet, target, "").Code)
	}

	for _, op := range loadSpec(t) {
		if !slices.Contains(publishPaths, op.path) {
			continue
		}
		for _, want := range op.statuses {
			if !reached[op.path][want] {
				t.Errorf("spec documents %s for %s %s, but no handler path produces it",
					want, strings.ToUpper(op.method), op.path)
			}
		}
	}
}

// TestSpecMatchesPublishResponseDetails pins the security-relevant details the
// spec advertises, so the document cannot keep claiming them after the handler
// stops doing them.
func TestSpecMatchesPublishResponseDetails(t *testing.T) {
	t.Parallel()

	body := []byte("ssh-ed25519 AAAA x\n")
	target := concretePath("/{handle}/{set}")

	t.Run("success carries a strong etag and the bounded public ttl", func(t *testing.T) {
		t.Parallel()

		rr := contractDo(t, stubPublisher{body: body}, http.MethodGet, target, "")
		assertHeader(t, rr, "Content-Type", "text/plain; charset=utf-8")
		assertHeader(t, rr, "Cache-Control", "public, max-age=60")
		assertHeader(t, rr, "X-Content-Type-Options", "nosniff")
		if etag := rr.Header().Get("ETag"); !strings.HasPrefix(etag, `"`) || len(etag) != 66 {
			t.Errorf("ETag = %q, want a quoted sha256 as the spec describes", etag)
		}
	})

	t.Run("not modified retains its validators", func(t *testing.T) {
		t.Parallel()

		first := contractDo(t, stubPublisher{body: body}, http.MethodGet, target, "")
		rr := contractDo(t, stubPublisher{body: body}, http.MethodGet, target, first.Header().Get("ETag"))
		if rr.Code != http.StatusNotModified {
			t.Fatalf("conditional request = %d, want 304", rr.Code)
		}
		// The spec documents both headers on the 304. Dropping the validator
		// would leave a consumer nothing to revalidate against, quietly turning
		// every later request into a full fetch.
		assertHeader(t, rr, "ETag", first.Header().Get("ETag"))
		assertHeader(t, rr, "Cache-Control", "public, max-age=60")
		if rr.Body.Len() != 0 {
			t.Errorf("304 carried a %d-byte body, want none", rr.Body.Len())
		}
	})

	t.Run("not found is uncacheable and uniform", func(t *testing.T) {
		t.Parallel()

		rr := contractDo(t, stubPublisher{err: publish.ErrNotFound}, http.MethodGet, target, "")
		if rr.Code != http.StatusNotFound {
			t.Fatalf("got %d, want 404", rr.Code)
		}
		assertHeader(t, rr, "Cache-Control", "no-store")
		assertHeader(t, rr, "X-Content-Type-Options", "nosniff")
		if etag := rr.Header().Get("ETag"); etag != "" {
			t.Errorf("404 carried ETag %q; the spec documents none, and a cached negative would outlive the fix", etag)
		}

		// The spec documents ONE 404 for every negative verdict. Two requests
		// that differ only in whether the set exists must be byte-identical, or
		// the difference is an existence oracle a stranger can enumerate with.
		other := contractDo(t, stubPublisher{err: publish.ErrNotFound}, http.MethodGet, concretePath("/{handle}"), "")
		if got, want := other.Body.String(), rr.Body.String(); got != want {
			t.Errorf("404 bodies differ between routes: %q vs %q", got, want)
		}
		if got, want := other.Code, rr.Code; got != want {
			t.Errorf("404 statuses differ between routes: %d vs %d", got, want)
		}
	})

}

// contractDo drives one request through the real handler with the given publisher.
func contractDo(t *testing.T, p Publisher, method, target, ifNoneMatch string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, target, nil)
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	rr := httptest.NewRecorder()
	NewHandler(nil, nil, okPinger{}, p).ServeHTTP(rr, req)
	return rr
}

func assertHeader(t *testing.T, rr *httptest.ResponseRecorder, name, want string) {
	t.Helper()

	if got := rr.Header().Get(name); got != want {
		t.Errorf("%s = %q, want %q", name, got, want)
	}
}

// concretePath substitutes the wildcard segments of a spec path.
func concretePath(path string) string {
	for placeholder, value := range routeParams {
		path = strings.ReplaceAll(path, placeholder, value)
	}
	return path
}

// specFile and routerFile locate the two documents relative to this source
// file, so the tests do not depend on the working directory.
func specFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(sourceDir(t), "..", "..", "..", "api", "openapi", "openapi.yaml")
}

func routerFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(sourceDir(t), "router.go")
}

func sourceDir(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this source file")
	}
	return filepath.Dir(file)
}
