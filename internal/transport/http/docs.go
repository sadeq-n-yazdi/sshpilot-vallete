package httpserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/api/openapi"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
)

// The media types the docs endpoints can produce. These are the complete set:
// there is no code path that emits any other representation, which is what
// makes "no request data influences the bytes returned beyond the negotiated
// media type" checkable rather than aspirational.
const (
	mediaJSON = "application/json"
	mediaYAML = "application/yaml"
)

// docsCacheControl allows shared caches to hold the contract briefly. The
// document is fixed at build time, so it can never go stale within the life of
// a process; the five-minute ceiling exists only so that a deployment which
// changes the contract is not shadowed by caches for long. Revalidation is
// cheap because every response carries a strong ETag.
const docsCacheControl = "public, max-age=300"

// specJSON converts the embedded YAML contract to JSON, once per process.
//
// The conversion is done here rather than by checking in a second file so that
// both representations provably come from the same source bytes; a checked-in
// JSON copy is one more thing that can drift. json.Marshal emits object keys in
// sorted order, so the result is deterministic across runs, which is what lets
// the ETag be a stable content hash.
var specJSON = sync.OnceValues(func() ([]byte, error) {
	var doc any
	if err := yaml.Unmarshal(openapi.Spec, &doc); err != nil {
		return nil, err
	}
	return json.Marshal(doc)
})

// acceptRange is one parsed element of an Accept header: a media range and the
// quality the client attached to it.
type acceptRange struct {
	typ string
	sub string
	q   float64
}

// parseAccept parses an Accept header into its media ranges.
//
// It is deliberately tolerant. A malformed element is skipped rather than
// failing the request, because the alternative — answering 4xx to a header the
// client may not even know it sent — turns a cosmetic client bug into an
// outage, and because a parser that rejects is a parser an attacker can use to
// probe. Anything unparseable simply does not vote, and an Accept header that
// contributes no votes at all lands on the JSON default.
func parseAccept(header string) []acceptRange {
	var ranges []acceptRange
	for _, element := range strings.Split(header, ",") {
		element = strings.TrimSpace(element)
		if element == "" {
			continue
		}
		mediaType, params, err := mime.ParseMediaType(element)
		if err != nil {
			continue
		}
		typ, sub, ok := strings.Cut(mediaType, "/")
		if !ok {
			continue
		}
		q := 1.0
		if raw, present := params["q"]; present {
			parsed, err := strconv.ParseFloat(raw, 64)
			if err != nil || parsed < 0 || parsed > 1 {
				continue
			}
			q = parsed
		}
		ranges = append(ranges, acceptRange{typ: typ, sub: sub, q: q})
	}
	return ranges
}

// quality returns the client's stated preference for one concrete media type.
//
// Per RFC 9110 the most specific matching range wins outright, not the highest
// quality: "text/html;q=0.1, */*;q=0.9" asks for HTML at 0.1, not 0.9. Getting
// this backwards would make a browser's trailing "*/*;q=0.8" outrank its own
// explicit preferences. A type nothing matches scores zero.
func quality(ranges []acceptRange, typ, sub string) float64 {
	bestSpecificity, bestQuality := 0, 0.0
	for _, r := range ranges {
		specificity := 0
		switch {
		case r.typ == typ && r.sub == sub:
			specificity = 3
		case r.typ == typ && r.sub == "*":
			specificity = 2
		case r.typ == "*" && r.sub == "*":
			specificity = 1
		default:
			continue
		}
		if specificity > bestSpecificity || (specificity == bestSpecificity && r.q > bestQuality) {
			bestSpecificity, bestQuality = specificity, r.q
		}
	}
	return bestQuality
}

// yamlQuality scores YAML across the spellings in the wild. application/yaml is
// the registered type (RFC 9512); the other two predate it and are still what
// most tooling sends, so honouring only the modern one would quietly serve JSON
// to clients that clearly asked for YAML.
func yamlQuality(ranges []acceptRange) float64 {
	return max(
		quality(ranges, "application", "yaml"),
		quality(ranges, "text", "yaml"),
		quality(ranges, "application", "x-yaml"),
	)
}

// negotiateDocs picks the representation for /docs/ from an Accept header.
//
// JSON is the floor, not merely one option among equals: ADR-0021 requires that
// anything unspecified or ambiguous resolves to JSON. Another representation is
// chosen only when the client ranks it strictly above JSON, so */*, an absent
// header, an unparseable header, and a type this server does not produce all
// land on JSON. Nothing here can produce a 406 — an endpoint whose whole job is
// to hand out one static document has no business refusing to.
func negotiateDocs(accept string) string {
	ranges := parseAccept(accept)
	chosen, chosenQuality := mediaJSON, quality(ranges, "application", "json")
	if q := yamlQuality(ranges); q > chosenQuality {
		chosen = mediaYAML
	}
	return chosen
}

// writeSpec writes one representation of the contract.
//
// http.ServeContent does the conditional-request and HEAD handling: it honours
// If-None-Match against the ETag set below and, for HEAD, writes the headers
// and no body. Delegating means those behaviours cannot be got subtly wrong
// here, and a HEAD can never disagree with the GET it describes because the
// same call produces both.
func writeSpec(w http.ResponseWriter, r *http.Request, mediaType string, body []byte) {
	sum := sha256.Sum256(body)
	header := w.Header()
	header.Set("Content-Type", mediaType+"; charset=utf-8")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Cache-Control", docsCacheControl)
	header.Set("ETag", `"`+hex.EncodeToString(sum[:])+`"`)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(body))
}

// writeSpecAs writes the contract in mediaType, converting if needed.
func writeSpecAs(w http.ResponseWriter, r *http.Request, mediaType string) {
	if mediaType == mediaYAML {
		// The embedded bytes, verbatim. Not re-serialised: a round trip
		// through a YAML parser would reformat the document and silently
		// discard its comments, so what is served would no longer be what was
		// reviewed.
		writeSpec(w, r, mediaYAML, openapi.Spec)
		return
	}
	body, err := specJSON()
	if err != nil {
		// Unreachable with the embedded document, which a test parses. It is
		// handled rather than ignored because the alternative is serving a
		// truncated contract as if it were whole.
		http.Error(w, "documentation unavailable", http.StatusInternalServerError)
		return
	}
	writeSpec(w, r, mediaJSON, body)
}

// docsRootHandler serves GET /docs/ with the representation the client asked
// for.
//
// enabled is captured at construction: the route is registered either way and
// answers exactly like an unregistered path when off. Deciding here rather than
// at registration keeps the disabled response identical to the mux's own 404 by
// construction — both are http.NotFound — instead of depending on which
// unrelated wildcard a /docs/ request would otherwise fall into.
func docsRootHandler(enabled bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !enabled {
			http.NotFound(w, r)
			return
		}
		// Caches must key on Accept or the first client to ask for YAML poisons
		// the entry for every client that wanted JSON.
		w.Header().Set("Vary", "Accept")
		writeSpecAs(w, r, negotiateDocs(r.Header.Get("Accept")))
	})
}

// docsSpecHandler serves one of the fixed spec URLs.
//
// mediaType is bound at construction, one handler per route, so the served
// representation is a property of the URL and nothing in the request can move
// it. That is the reason there is no /docs/spec/{name} route: the moment a path
// segment selects the document, the endpoint has a traversal surface and an
// enumeration oracle. Two hard-coded routes have neither.
func docsSpecHandler(enabled bool, mediaType string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !enabled {
			http.NotFound(w, r)
			return
		}
		writeSpecAs(w, r, mediaType)
	})
}

// docsRedirectHandler sends GET /docs to GET /docs/.
//
// The target is a constant, never anything derived from the request, so this
// cannot be turned into an open redirect. It is registered explicitly because
// leaving /docs unclaimed would drop it into the /{handle} publish route and
// spend a datastore lookup on a name ADR-0017 reserves anyway.
func docsRedirectHandler(enabled bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !enabled {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/docs/", http.StatusMovedPermanently)
	})
}

// docsEnabled reports whether the docs endpoints should answer.
//
// A nil config means "no configuration was supplied", which resolves to the
// product default ADR-0021 states: enabled and public, because the contract is
// not secret. A non-nil config is believed as written — config.Default() sets
// Enabled true, so an operator who loaded configuration normally keeps the
// default and one who wrote enabled: false gets what they asked for.
func docsEnabled(cfg *config.Config) bool {
	if cfg == nil {
		return true
	}
	return cfg.Docs.Enabled
}
