package httpserver

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// wantDocsCSP is the policy, spelled out.
//
// It is written as a literal rather than rebuilt from the same constants the
// handler uses, because a test that recomputes the policy would agree with any
// policy at all. Pinned like this, dropping a directive or adding
// 'unsafe-inline' cannot reach main without showing up in this file's diff,
// where a reviewer will see it.
//
// The hashes change whenever the inline script or style is edited, so a
// deliberate UI change updates this string; TestDocsUIHashesMatchServedContent
// is what proves the new value is honest rather than merely current.
const wantDocsCSP = "default-src 'none'; " +
	"script-src 'sha256-ETyjpObOmmqFiDG/nTBjC73D8DazSVV2GVmeW+7UHro='; " +
	"style-src 'sha256-ZdLrWf3LQ9rykb/IJj24H7xuH7K3Ujbjzp5Fm/zb38k='; " +
	"connect-src 'self'; " +
	"base-uri 'none'; " +
	"form-action 'none'; " +
	"frame-ancestors 'none'; " +
	"object-src 'none'"

func docsUIResponse(t *testing.T) (string, http.Header) {
	t.Helper()

	rr := docsGet(t, "/docs/", "text/html")
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /docs/ with Accept: text/html = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/html; charset=utf-8", got)
	}
	return rr.Body.String(), rr.Header()
}

// TestDocsUISecurityHeaders pins the exact policy and the headers beside it.
func TestDocsUISecurityHeaders(t *testing.T) {
	t.Parallel()

	_, header := docsUIResponse(t)

	if got := header.Get("Content-Security-Policy"); got != wantDocsCSP {
		t.Errorf("CSP mismatch\n got: %s\nwant: %s", got, wantDocsCSP)
	}
	for name, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

// TestDocsCSPForbidsTheDangerousSources states the prohibitions directly, so
// they hold even if wantDocsCSP is ever updated carelessly alongside a change.
func TestDocsCSPForbidsTheDangerousSources(t *testing.T) {
	t.Parallel()

	_, header := docsUIResponse(t)
	csp := header.Get("Content-Security-Policy")

	for _, forbidden := range []string{"unsafe-inline", "unsafe-eval", "unsafe-hashes", "strict-dynamic", "data:", "blob:", "*"} {
		if strings.Contains(csp, forbidden) {
			t.Errorf("CSP contains %q: %s", forbidden, csp)
		}
	}
	for _, required := range []string{"default-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "object-src 'none'"} {
		if !strings.Contains(csp, required) {
			t.Errorf("CSP is missing %q: %s", required, csp)
		}
	}
	// No source expression may name a host. Anything that is not a quoted
	// keyword or a hash is one, and a host in script-src is exactly how a CDN
	// gets reintroduced.
	for _, directive := range strings.Split(csp, ";") {
		fields := strings.Fields(strings.TrimSpace(directive))
		for _, source := range fields[1:] {
			if !strings.HasPrefix(source, "'") || !strings.HasSuffix(source, "'") {
				t.Errorf("CSP source %q in %q is not a quoted keyword or hash", source, fields[0])
			}
		}
	}
}

// TestDocsUIHashesMatchServedContent recomputes the hashes from the bytes the
// client actually receives and checks the policy names them.
//
// Without this, an edit to the inline script would leave the pinned CSP above
// still passing while the page silently stopped executing in every browser —
// the policy would be strict, correct-looking, and wrong.
func TestDocsUIHashesMatchServedContent(t *testing.T) {
	t.Parallel()

	body, header := docsUIResponse(t)
	csp := header.Get("Content-Security-Policy")

	for _, block := range []struct{ tag, directive string }{
		{"script", "script-src"},
		{"style", "style-src"},
	} {
		content := between(t, body, "<"+block.tag+">", "</"+block.tag+">")
		sum := sha256.Sum256([]byte(content))
		want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
		if !strings.Contains(csp, block.directive+" "+want) {
			t.Errorf("%s does not name the hash of the served <%s> block (%s)\nCSP: %s",
				block.directive, block.tag, want, csp)
		}
	}
}

// between returns the single region delimited by open and close, failing if
// there is not exactly one — more than one inline block would mean a hash the
// policy does not cover.
func between(t *testing.T, body, open, close string) string {
	t.Helper()

	if n := strings.Count(body, open); n != 1 {
		t.Fatalf("found %d %s elements, want exactly 1", n, open)
	}
	start := strings.Index(body, open) + len(open)
	end := strings.Index(body[start:], close)
	if end < 0 {
		t.Fatalf("no %s in the served page", close)
	}
	return body[start : start+end]
}

// absoluteScheme matches any scheme-qualified URL: "https://", but equally
// "HTTPS://", "ftp://", or a novel one. Matching the syntax rather than a list
// of protocols is what stops this test from being a grep that a slightly
// different spelling walks past.
var absoluteScheme = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.\-]*://`)

// protocolRelative matches "//host" where it can only be a URL: after a quote,
// a CSS url(, or an = sign. Requiring that context avoids colliding with "//"
// as a JavaScript comment, which appears legitimately in the page.
var protocolRelative = regexp.MustCompile(`(?i)(["'(=]|url\()\s*//[a-z0-9]`)

// urlAttribute matches every HTML attribute whose value is fetched or
// navigated to.
var urlAttribute = regexp.MustCompile(`(?i)\b(src|href|srcset|action|formaction|data|poster|background|manifest|codebase|xlink:href)\s*=\s*["']([^"']*)["']`)

// subresourceElement matches the elements that pull in external content. The
// page must contain none of them; its script and style are inline.
var subresourceElement = regexp.MustCompile(`(?i)<\s*(script[^>]*\bsrc\b|link|iframe|frame|object|embed|applet|audio|video|source|track|img)\b`)

// TestDocsUIReferencesNoExternalOrigin is the test that keeps the no-CDN rule
// true after everyone who agreed to it has moved on.
//
// It works on the served bytes and checks four independent things, because any
// one of them alone is a grep somebody eventually slips past: no absolute URL
// of any scheme anywhere in the document, no protocol-relative URL in a
// position where it would be fetched, every URL-bearing attribute pointing at a
// same-origin path, and no subresource-loading element present at all. A CDN
// added in the markup fails the fourth; one added from inside the script fails
// the first.
func TestDocsUIReferencesNoExternalOrigin(t *testing.T) {
	t.Parallel()

	body, _ := docsUIResponse(t)

	if found := absoluteScheme.FindAllString(body, -1); found != nil {
		t.Errorf("page contains absolute URLs, so it is not self-contained: %v", found)
	}
	if found := protocolRelative.FindAllString(body, -1); found != nil {
		t.Errorf("page contains protocol-relative URLs: %q", found)
	}
	if found := subresourceElement.FindAllString(body, -1); found != nil {
		t.Errorf("page loads subresources, which must be inlined instead: %v", found)
	}
	for _, match := range urlAttribute.FindAllStringSubmatch(body, -1) {
		attr, value := match[1], strings.TrimSpace(match[2])
		switch {
		case strings.HasPrefix(value, "#"):
		case strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//"):
		default:
			t.Errorf("%s=%q is not a same-origin absolute path", attr, value)
		}
	}
	// CSS can fetch without an element or an attribute.
	for _, forbidden := range []string{"@import", "url(", "image-set(", "src:"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("stylesheet uses %q, which can fetch an external resource", forbidden)
		}
	}
}

// TestDocsUIFetchesTheSpecFromThisOrigin checks the page is actually wired to
// the local spec route, so "self-contained" does not quietly mean "broken".
func TestDocsUIFetchesTheSpecFromThisOrigin(t *testing.T) {
	t.Parallel()

	body, _ := docsUIResponse(t)
	if !strings.Contains(body, "'/docs/spec/openapi.json'") {
		t.Error("the page does not fetch the spec from this origin's fixed URL")
	}
	// The route the page depends on must exist and answer.
	if rr := docsGet(t, "/docs/spec/openapi.json", "application/json"); rr.Code != http.StatusOK {
		t.Errorf("the spec URL the page fetches returned %d", rr.Code)
	}
}

// TestDocsUIUsesNoDynamicCodeExecution guards the claim that 'unsafe-eval' is
// unnecessary. If any of these appeared, the page would need a weaker policy.
func TestDocsUIUsesNoDynamicCodeExecution(t *testing.T) {
	t.Parallel()

	body, _ := docsUIResponse(t)
	for _, construct := range []string{"eval(", "new Function", "setTimeout('", "innerHTML", "outerHTML", "document.write", "insertAdjacentHTML"} {
		if strings.Contains(body, construct) {
			t.Errorf("page uses %q; it is both an injection sink and a reason to weaken the CSP", construct)
		}
	}
	// Inline event handlers are not covered by a script hash, so a page using
	// them would need 'unsafe-inline' to work.
	if regexp.MustCompile(`(?i)\son[a-z]+\s*=`).MatchString(body) {
		t.Error("page uses an inline event handler attribute, which a script hash cannot cover")
	}
}

// TestDocsUIIsNotServedWhenDocsAreDisabled closes the obvious gap in the
// exposure switch: the UI is a separate branch from the spec representations
// and could be left reachable on its own.
func TestDocsUIIsNotServedWhenDocsAreDisabled(t *testing.T) {
	t.Parallel()

	rr := docsRequest(t, false, http.MethodGet, "/docs/", http.Header{"Accept": {"text/html"}})
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
	if rr.Header().Get("Content-Security-Policy") != "" {
		t.Error("a disabled deployment still emitted the docs CSP, which reveals the feature")
	}
}
