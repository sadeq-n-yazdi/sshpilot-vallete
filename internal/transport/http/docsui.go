package httpserver

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
)

// mediaHTML is the rendered documentation UI.
const mediaHTML = "text/html"

// docsUIStyle is the entire stylesheet, inlined.
//
// Inlined rather than served from a second route because a self-contained
// document is the property being defended: one response, no subresources, so
// there is no fetch for anything to be substituted into.
const docsUIStyle = `
:root { color-scheme: light dark; --fg: #16181d; --bg: #fbfbfc; --muted: #5b6270;
  --line: #d9dce3; --card: #ffffff; --accent: #1c4f9c; }
@media (prefers-color-scheme: dark) {
  :root { --fg: #e6e8ec; --bg: #14161a; --muted: #9aa2b1; --line: #2b2f38;
    --card: #1b1e24; --accent: #7aa7e8; }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 2rem 1rem 4rem; background: var(--bg); color: var(--fg);
  font: 16px/1.6 ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
header, main, footer { max-width: 52rem; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
#tagline { color: var(--muted); margin: 0 0 2rem; }
.op { border: 1px solid var(--line); border-radius: .5rem; background: var(--card);
  padding: 1rem 1.25rem; margin: 0 0 1rem; }
.op h2 { font-size: 1rem; margin: 0 0 .5rem; display: flex; gap: .6rem; align-items: center;
  flex-wrap: wrap; }
.method { font: 600 .75rem/1 ui-monospace, SFMono-Regular, Menlo, monospace;
  letter-spacing: .04em; padding: .35rem .5rem; border-radius: .25rem;
  border: 1px solid var(--line); color: var(--accent); }
.path { font: .95rem/1 ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-all; }
.summary { margin: 0 0 .5rem; }
.desc { color: var(--muted); margin: 0 0 .75rem; white-space: pre-wrap; font-size: .93rem; }
.responses { margin: 0; padding-left: 1.1rem; color: var(--muted); font-size: .9rem; }
footer { margin-top: 2.5rem; color: var(--muted); font-size: .9rem;
  border-top: 1px solid var(--line); padding-top: 1rem; }
a { color: var(--accent); }
`

// docsUIScript renders the contract the page fetches from this same origin.
//
// Every value taken from the document is written with textContent, never
// innerHTML. The spec is trusted here, but the habit is what matters: the day
// any part of it becomes operator-supplied, this page does not become an
// injection sink. There is no eval, no Function constructor, and no dynamic
// import, so the CSP below needs no 'unsafe-eval'.
const docsUIScript = `
(function () {
  var status = document.getElementById('status');

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) { node.className = cls; }
    if (text !== undefined) { node.textContent = text; }
    return node;
  }

  // Follows a local $ref so shared responses show their description instead of
  // a blank line. Only same-document "#/" pointers are followed — a $ref naming
  // another document would be a fetch, and this page makes none. The hop count
  // is bounded so a cyclic pointer cannot hang the tab.
  function deref(spec, node) {
    for (var hops = 0; node && typeof node.$ref === 'string' && node.$ref.indexOf('#/') === 0 && hops < 8; hops++) {
      var target = spec;
      node.$ref.slice(2).split('/').forEach(function (part) {
        target = target ? target[part.replace(/~1/g, '/').replace(/~0/g, '~')] : undefined;
      });
      node = target;
    }
    return node || {};
  }

  function render(spec) {
    var info = spec.info || {};
    if (info.title) { document.title = info.title; }
    document.getElementById('tagline').textContent =
      (info.summary || '') + (info.version ? ' — v' + info.version : '');

    var main = document.getElementById('ops');
    main.textContent = '';
    var methods = ['get', 'put', 'post', 'delete', 'patch', 'head', 'options', 'trace'];
    var paths = spec.paths || {};

    Object.keys(paths).sort().forEach(function (path) {
      methods.forEach(function (method) {
        var op = paths[path][method];
        if (!op) { return; }
        var card = el('section', 'op');
        var heading = el('h2');
        heading.appendChild(el('span', 'method', method.toUpperCase()));
        heading.appendChild(el('code', 'path', path));
        card.appendChild(heading);
        if (op.summary) { card.appendChild(el('p', 'summary', op.summary)); }
        if (op.description) { card.appendChild(el('p', 'desc', op.description.trim())); }
        var codes = Object.keys(op.responses || {}).sort();
        if (codes.length) {
          var list = el('ul', 'responses');
          codes.forEach(function (code) {
            var body = deref(spec, op.responses[code]);
            list.appendChild(el('li', null, code + ' — ' + (body.description || '').trim()));
          });
          card.appendChild(list);
        }
        main.appendChild(card);
      });
    });

    if (!main.childNodes.length) { main.appendChild(el('p', null, 'This contract declares no operations.')); }
  }

  fetch('/docs/spec/openapi.json', { headers: { 'Accept': 'application/json' } })
    .then(function (response) {
      if (!response.ok) { throw new Error('HTTP ' + response.status); }
      return response.json();
    })
    .then(render)
    .catch(function (err) { status.textContent = 'Could not load the contract: ' + err.message; });
})();
`

// docsUIPage is the complete response body: markup, style, and behavior in one
// document with no subresources of any kind.
//
// Both links point at this server's own fixed spec URLs. There is no external
// origin referenced anywhere in this page, which is the no-CDN rule ADR-0021
// states, and which a test enforces by parsing the served bytes rather than by
// trusting this comment.
var docsUIPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sshpilot-vallete API</title>
<style>` + docsUIStyle + `</style>
</head>
<body>
<header>
<h1>sshpilot-vallete API</h1>
<p id="tagline"></p>
</header>
<main id="ops"><p id="status">Loading the contract&hellip;</p></main>
<footer>
<p>Served from this binary, with no external assets. Machine-readable:
<a href="/docs/spec/openapi.json">openapi.json</a> &middot;
<a href="/docs/spec/openapi.yaml">openapi.yaml</a></p>
</footer>
<script>` + docsUIScript + `</script>
</body>
</html>
`

// cspHash renders one inline block's CSP source expression.
//
// The hash is taken over the constant that is concatenated into the page above,
// so the value in the header and the bytes in the document cannot disagree: one
// is computed from the other. Hashes are used rather than a nonce because a
// nonce is per-response and random, which would make the policy untestable as a
// fixed string and would leave a loosening invisible in review.
func cspHash(block string) string {
	sum := sha256.Sum256([]byte(block))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// docsCSP is the Content-Security-Policy for the documentation UI.
//
// Directive by directive:
//
//   - default-src 'none' — deny by default. Every capability the page needs is
//     then granted explicitly below, so anything injected later (an iframe, a
//     websocket, a font) is refused until someone deliberately widens this.
//   - script-src <hash> — the one inline script, pinned by content hash. No
//     'unsafe-inline', so an injected <script> cannot run; no 'unsafe-eval', so
//     a string cannot become code; no host source, so no third party can ever
//     execute in this origin. Editing the script changes its hash, and the page
//     stops working until the policy is regenerated — which is the intended
//     failure mode.
//   - style-src <hash> — the one inline stylesheet, same reasoning. The page
//     uses no style="" attributes, which a hash would not cover.
//   - connect-src 'self' — the script fetches the spec from this origin. This
//     is the only network capability granted, and it cannot reach off-origin,
//     so the page has no exfiltration path.
//   - base-uri 'none' — an injected <base> would silently retarget the
//     relative spec URL. default-src does not cover this directive.
//   - form-action 'none' — the page has no forms; this denies an injected one
//     a destination to post to.
//   - frame-ancestors 'none' — nothing may frame this page. Paired with
//     X-Frame-Options for user agents that predate the directive.
//   - object-src 'none' — stated explicitly rather than left to default-src,
//     because plugin content is the one legacy vector where falling back has
//     historically been unreliable.
var docsCSP = strings.Join([]string{
	"default-src 'none'",
	"script-src " + cspHash(docsUIScript),
	"style-src " + cspHash(docsUIStyle),
	"connect-src 'self'",
	"base-uri 'none'",
	"form-action 'none'",
	"frame-ancestors 'none'",
	"object-src 'none'",
}, "; ")

// writeDocsUI serves the rendered documentation page.
//
// The body is a build-time constant, so this shares the spec responses' ETag
// and conditional-request handling by going through the same writer: HEAD and
// If-None-Match behave identically across every docs route rather than each
// route growing its own version.
func writeDocsUI(w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	header.Set("Content-Security-Policy", docsCSP)
	// Deny framing for user agents older than frame-ancestors. Belt and
	// braces, but the braces cost one header.
	header.Set("X-Frame-Options", "DENY")
	// The docs page links only to this origin, but a referrer is never useful
	// to anyone here and leaks the path a reader came from.
	header.Set("Referrer-Policy", "no-referrer")
	writeSpec(w, r, mediaHTML, []byte(docsUIPage))
}
