package httpserver

import (
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/publish"
)

// sampleBody is a stand-in authorized_keys body. Its exact contents do not
// matter to the transport, which must treat it as opaque bytes.
const sampleBody = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJm7t7g6Uu1PL7lxQvfLh7dGxzZBLcYqLxYUlD8HpXTd me@laptop\n"

// newPublishHandler builds the full handler chain around a fixed publisher.
func newPublishHandler(t *testing.T, p Publisher) http.Handler {
	t.Helper()
	return NewHandler(nil, slog.New(slog.DiscardHandler), okPinger{}, p)
}

// do issues a request through the handler and returns the recorder.
func do(t *testing.T, h http.Handler, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestPublishGetServesAuthorizedKeys(t *testing.T) {
	t.Parallel()

	h := newPublishHandler(t, stubPublisher{body: []byte(sampleBody)})
	rec := do(t, h, http.MethodGet, "/alice", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != sampleBody {
		t.Errorf("body = %q, want %q", got, sampleBody)
	}
	// text/plain is what makes the response consumable by curl and
	// AuthorizedKeysCommand without any client-side unwrapping.
	if got := rec.Header().Get("Content-Type"); got != publishContentType {
		t.Errorf("Content-Type = %q, want %q", got, publishContentType)
	}
	if got, want := rec.Header().Get("Content-Length"), strconv.Itoa(len(sampleBody)); got != want {
		t.Errorf("Content-Length = %q, want %q", got, want)
	}
	if got, want := rec.Header().Get("Cache-Control"), "public, max-age=60"; got != want {
		t.Errorf("Cache-Control = %q, want %q", got, want)
	}
	if rec.Header().Get("ETag") == "" {
		t.Error("ETag is missing; conditional requests would be impossible")
	}
}

// TestPublishRoutesPassPathSegments proves the default-set selection is driven
// by an ABSENT set segment rather than by a literal name the transport invents.
func TestPublishRoutesPassPathSegments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		target     string
		wantHandle string
		wantSet    string
	}{
		{name: "handle only selects default", target: "/alice", wantHandle: "alice", wantSet: ""},
		{name: "handle and set", target: "/alice/work", wantHandle: "alice", wantSet: "work"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var gotHandle, gotSet string
			h := newPublishHandler(t, stubPublisher{gotHandle: &gotHandle, gotSet: &gotSet})
			do(t, h, http.MethodGet, tc.target, nil)

			if gotHandle != tc.wantHandle {
				t.Errorf("handle = %q, want %q", gotHandle, tc.wantHandle)
			}
			if gotSet != tc.wantSet {
				t.Errorf("set = %q, want %q", gotSet, tc.wantSet)
			}
		})
	}
}

func TestPublishETagIsStableAndContentDerived(t *testing.T) {
	t.Parallel()

	h := newPublishHandler(t, stubPublisher{body: []byte(sampleBody)})

	first := do(t, h, http.MethodGet, "/alice", nil).Header().Get("ETag")
	for range 5 {
		if again := do(t, h, http.MethodGet, "/alice", nil).Header().Get("ETag"); again != first {
			t.Fatalf("ETag changed across identical requests: %q then %q", first, again)
		}
	}

	// A different body must produce a different tag, or a client would keep a
	// stale key list after the owner changed it — the failure mode that matters
	// far more than an unnecessary refetch.
	other := newPublishHandler(t, stubPublisher{body: []byte(sampleBody + "x\n")})
	if changed := do(t, other, http.MethodGet, "/alice", nil).Header().Get("ETag"); changed == first {
		t.Error("different bodies produced the same ETag")
	}

	// An empty body still gets a tag: "no keys" is a representation a client
	// must be able to revalidate like any other.
	empty := newPublishHandler(t, stubPublisher{})
	if tag := do(t, empty, http.MethodGet, "/alice", nil).Header().Get("ETag"); tag == "" {
		t.Error("empty body has no ETag")
	}
}

func TestPublishConditionalRequests(t *testing.T) {
	t.Parallel()

	h := newPublishHandler(t, stubPublisher{body: []byte(sampleBody)})
	etag := do(t, h, http.MethodGet, "/alice", nil).Header().Get("ETag")

	t.Run("matching tag yields 304 with no body", func(t *testing.T) {
		t.Parallel()

		rec := do(t, h, http.MethodGet, "/alice", map[string]string{"If-None-Match": etag})
		if rec.Code != http.StatusNotModified {
			t.Fatalf("status = %d, want 304", rec.Code)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("304 carries a body: %q", rec.Body.String())
		}
		// The validators must survive onto the 304, or the client has nothing
		// to revalidate with next time and silently falls back to full fetches.
		if got := rec.Header().Get("ETag"); got != etag {
			t.Errorf("304 ETag = %q, want %q", got, etag)
		}
		if rec.Header().Get("Cache-Control") == "" {
			t.Error("304 has no Cache-Control")
		}
	})

	t.Run("accepted forms", func(t *testing.T) {
		t.Parallel()

		accepted := map[string]string{
			"exact":            etag,
			"weak prefix":      "W/" + etag,
			"wildcard":         "*",
			"list":             `"other", ` + etag,
			"surrounding wsp":  "  " + etag + "  ",
			"list with weak":   `W/"other", W/` + etag,
			"trailing element": etag + `, "another"`,
		}
		for name, header := range accepted {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				rec := do(t, h, http.MethodGet, "/alice", map[string]string{"If-None-Match": header})
				if rec.Code != http.StatusNotModified {
					t.Errorf("If-None-Match %q = %d, want 304", header, rec.Code)
				}
			})
		}
	})

	t.Run("non-matching forms serve the body", func(t *testing.T) {
		t.Parallel()

		// Every one of these must fall through to a 200. Answering 304 to a tag
		// that does not match would leave a client trusting a key list it
		// should have replaced, so unparseable input must fail OPEN into a full
		// response rather than closed into a cache hit.
		rejected := map[string]string{
			"empty":           "",
			"different tag":   `"nope"`,
			"unquoted":        "deadbeef",
			"partial prefix":  etag[:len(etag)-2] + `"`,
			"garbage":         ",,,",
			"wildcard inside": `"nope", *x`,
		}
		for name, header := range rejected {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				rec := do(t, h, http.MethodGet, "/alice", map[string]string{"If-None-Match": header})
				if rec.Code != http.StatusOK {
					t.Errorf("If-None-Match %q = %d, want 200", header, rec.Code)
				}
			})
		}
	})
}

// TestPublishHeadMatchesGet is the HEAD parity check: identical headers, no
// body. A HEAD whose Content-Length disagreed with the GET would mislead every
// client that uses it to size a fetch.
func TestPublishHeadMatchesGet(t *testing.T) {
	t.Parallel()

	cases := map[string]Publisher{
		"success":   stubPublisher{body: []byte(sampleBody)},
		"empty":     stubPublisher{},
		"not found": stubPublisher{err: publish.ErrNotFound},
		"error":     stubPublisher{err: errors.New("boom")},
	}

	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h := newPublishHandler(t, p)
			get := do(t, h, http.MethodGet, "/alice", nil)
			head := do(t, h, http.MethodHead, "/alice", nil)

			if get.Code != head.Code {
				t.Errorf("status GET %d != HEAD %d", get.Code, head.Code)
			}
			if head.Body.Len() != 0 {
				t.Errorf("HEAD returned a body: %q", head.Body.String())
			}
			assertSameHeaders(t, get.Header(), head.Header())
		})
	}
}

func TestPublishNotFoundResponsesAreIdentical(t *testing.T) {
	t.Parallel()

	h := newPublishHandler(t, stubPublisher{err: publish.ErrNotFound})

	// Different shapes of request, all denied. At the transport level they must
	// already be indistinguishable; the service-level proof that the CAUSES are
	// indistinguishable lives in the end-to-end test against a real store.
	targets := []string{"/nobody", "/alice/secret", "/alice", "/x/y"}

	first := do(t, h, http.MethodGet, targets[0], nil)
	if first.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", first.Code)
	}
	if first.Header().Get("ETag") != "" {
		t.Error("404 carries an ETag; a negative answer must not be revalidatable")
	}
	if got := first.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("404 Cache-Control = %q, want no-store: a cached 404 would outlive the fix", got)
	}

	for _, target := range targets[1:] {
		rec := do(t, h, http.MethodGet, target, nil)
		if rec.Code != first.Code {
			t.Errorf("%s status = %d, want %d", target, rec.Code, first.Code)
		}
		if rec.Body.String() != first.Body.String() {
			t.Errorf("%s body = %q, want %q", target, rec.Body.String(), first.Body.String())
		}
		assertSameHeaders(t, first.Header(), rec.Header())
	}
}

func TestPublishInternalErrorLeaksNothing(t *testing.T) {
	t.Parallel()

	const secret = "table public_keys column comment is corrupt"
	h := newPublishHandler(t, stubPublisher{err: errors.New(secret)})
	rec := do(t, h, http.MethodGet, "/alice", nil)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	// An internal fault must not be reported as 404: that would make a
	// corrupted row look to an operator like an empty account.
	if body := rec.Body.String(); body != "internal server error\n" {
		t.Errorf("body = %q, want the fixed generic text", body)
	}
	if rec.Header().Get("ETag") != "" {
		t.Error("500 carries an ETag")
	}
}

func TestPublishLogsCarryNoResponseDetail(t *testing.T) {
	t.Parallel()

	const secret = "fingerprint SHA256:supersecretvalue is unrenderable"
	logger, buf := newTestLogger()
	h := NewHandler(nil, logger, okPinger{}, stubPublisher{err: errors.New(secret)})

	rec := do(t, h, http.MethodGet, "/alice", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}

	// The detail belongs in the log and nowhere else; assert both halves of
	// that so the test fails if the value ever moves to the wire.
	if logged := buf.String(); !strings.Contains(logged, secret) {
		t.Errorf("cause is absent from the log, so the failure is undiagnosable: %s", logged)
	}
	if strings.Contains(rec.Body.String(), "SHA256:") {
		t.Error("the response body leaked internal detail")
	}
}

func TestPublishNilPublisherFailsClosed(t *testing.T) {
	t.Parallel()

	// A missing publisher is a broken deployment. It must surface as a 500,
	// not a 404 that an operator would read as "the account is empty".
	h := NewHandler(nil, slog.New(slog.DiscardHandler), okPinger{}, nil)
	rec := do(t, h, http.MethodGet, "/alice", nil)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
}

// assertSameHeaders compares two header maps, ignoring the ones that are
// legitimately per-response.
func assertSameHeaders(t *testing.T, want, got http.Header) {
	t.Helper()

	// Date moves with the clock and X-Request-Id is unique per request by
	// design; neither says anything about the property under test.
	skip := map[string]bool{"Date": true, RequestIDHeader: true}

	for _, name := range append(headerNames(want), headerNames(got)...) {
		if skip[name] {
			continue
		}
		w, g := want.Values(name), got.Values(name)
		if len(w) != len(g) {
			t.Errorf("header %q: %v vs %v", name, w, g)
			continue
		}
		for i := range w {
			if w[i] != g[i] {
				t.Errorf("header %q: %q vs %q", name, w[i], g[i])
			}
		}
	}
}

// headerNames returns the header names present in h.
func headerNames(h http.Header) []string {
	return slices.Collect(maps.Keys(h))
}
