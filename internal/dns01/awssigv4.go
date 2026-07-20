package dns01

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWS Signature Version 4 signing, implemented here rather than taken from
// aws-sdk-go-v2.
//
// # Why hand-rolled
//
// The Route 53 provider needs exactly three API calls. Pulling in
// aws-sdk-go-v2's route53 client to make them would add the SDK core, its
// credential-provider chain, its retry and endpoint-resolution machinery and
// roughly twenty modules to a dependency graph that is currently four direct
// requirements. This project runs govulncheck and publishes an SBOM
// (ADR-0027), so every module is a standing cost that has to be triaged for
// the life of the project, and ADR-0015 explicitly leaves the choice of DNS
// client library as an implementation detail rather than a design decision.
//
// The security argument cuts the same way. The SDK's default credential chain
// is a feature this program must NOT have: it silently falls back to
// environment variables, ~/.aws/credentials, and the EC2/ECS instance metadata
// endpoint. ADR-0022 requires credentials to come from the configured secret
// provider, and a chain that quietly picks up an instance role instead would
// mean the process signs with an identity the operator never configured and
// cannot see in the config. Signing explicitly with one supplied key is the
// property we want, and it is the smaller amount of code.
//
// The risk of hand-rolling is getting the signature wrong, which is checked in
// awssigv4_test.go against AWS's own published SigV4 test-suite vector rather
// than against this implementation's own output.

const (
	// sigV4Algorithm is the only algorithm this signer emits.
	sigV4Algorithm = "AWS4-HMAC-SHA256"

	// sigV4TimeFormat and sigV4DateFormat are SigV4's two required renderings
	// of the request instant.
	sigV4TimeFormat = "20060102T150405Z"
	sigV4DateFormat = "20060102"
)

// signV4 signs req in place with AWS Signature Version 4.
//
// payload must be the exact request body bytes (nil for a bodyless request);
// SigV4 signs its digest, so a mismatch here produces a signature AWS rejects.
//
// The secret is taken as a string parameter and used only to derive the signing
// key. It is never stored on a struct, never logged, and never rendered into
// the error values below — the errors describe the REQUEST, not the credential.
func signV4(req *http.Request, payload []byte, accessKeyID, secretAccessKey, region, service string, now time.Time) error {
	if accessKeyID == "" || secretAccessKey == "" {
		// Refused rather than signed with an empty key: an empty secret still
		// produces a syntactically valid signature, so without this check the
		// failure would surface as an opaque 403 from AWS rather than as a
		// configuration error the operator can act on.
		return fmt.Errorf("sigv4: empty credential")
	}

	amzDate := now.UTC().Format(sigV4TimeFormat)
	dateStamp := now.UTC().Format(sigV4DateFormat)

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	req.Header.Set("X-Amz-Date", amzDate)

	// Only host and x-amz-date are signed, plus content-type when the caller
	// set one. Signing the minimum set is deliberate: every signed header is a
	// header a proxy must not alter, and a broader set makes the signature
	// fragile without making it stronger.
	signed := []string{"host", "x-amz-date"}
	canonicalHeaders := "host:" + host + "\n" + "x-amz-date:" + amzDate + "\n"
	if ct := req.Header.Get("Content-Type"); ct != "" {
		signed = []string{"content-type", "host", "x-amz-date"}
		canonicalHeaders = "content-type:" + ct + "\n" + canonicalHeaders
	}
	signedHeaders := strings.Join(signed, ";")

	payloadHash := sha256Hex(payload)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL),
		canonicalQuery(req.URL),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		sigV4Algorithm,
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	signature := hex.EncodeToString(hmacSHA256(signingKey(secretAccessKey, dateStamp, region, service), []byte(stringToSign)))

	req.Header.Set("Authorization", fmt.Sprintf(
		"%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		sigV4Algorithm, accessKeyID, credentialScope, signedHeaders, signature,
	))
	return nil
}

// signingKey derives the per-day, per-region, per-service key.
//
// The chained derivation is the reason a leaked signature is not a leaked
// credential: each HMAC is one-way, so a signature discloses nothing about the
// secret, and the derived key is useless outside its date, region and service.
func signingKey(secret, dateStamp, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	k = hmacSHA256(k, []byte(region))
	k = hmacSHA256(k, []byte(service))
	return hmacSHA256(k, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// canonicalURI renders the path as SigV4 requires: an empty path becomes "/",
// and each segment is URI-encoded.
//
// Route 53's paths are built by this package from a fixed prefix and a hosted
// zone ID that is validated against a strict character class before it gets
// here, so no segment can contain a character that needs escaping. The encoding
// is applied anyway rather than skipped, because a path that is signed
// differently from how it is sent is a request AWS rejects, and relying on
// "the input happens to be safe" is exactly the assumption that stops holding
// when someone adds a call later.
func canonicalURI(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

// canonicalQuery renders the query string with parameters sorted by name and
// then value, each component encoded per RFC 3986.
func canonicalQuery(u *url.URL) string {
	values := u.Query()
	if len(values) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(values))
	for key, vals := range values {
		sorted := append([]string(nil), vals...)
		sort.Strings(sorted)
		for _, v := range sorted {
			pairs = append(pairs, uriEncode(key)+"="+uriEncode(v))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// uriEncode percent-encodes per RFC 3986, which is stricter than
// url.QueryEscape: SigV4 requires a space to be "%20" rather than "+", and
// requires "~" to be left alone. Using QueryEscape here would produce a
// signature that does not match the request AWS reconstructs.
func uriEncode(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
	var b strings.Builder
	for i := range len(s) {
		c := s[i]
		if strings.IndexByte(unreserved, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}
