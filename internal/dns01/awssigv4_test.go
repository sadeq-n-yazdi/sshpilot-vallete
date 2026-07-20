package dns01

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// The credential AWS publishes with its SigV4 test suite. It is a documented
// example key, not a live one.
const (
	sigV4TestAccessKey = "AKIDEXAMPLE"
	sigV4TestSecret    = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
)

var sigV4TestTime = time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)

// TestSignV4MatchesAWSPublishedVector checks the signer against AWS's own
// "get-vanilla" test-suite case.
//
// This is the test that makes hand-rolling SigV4 defensible instead of hopeful.
// Every other test in this package could pass against a signer that is
// self-consistently wrong, because they compare this code's output with this
// code's expectations. This one compares it with a signature AWS published,
// computed by AWS's implementation, so a canonicalization mistake — an
// unsorted header, a "+" where "%20" belongs, a missing trailing newline in the
// canonical headers block — fails here and nowhere else.
func TestSignV4MatchesAWSPublishedVector(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	if err := signV4(req, nil, sigV4TestAccessKey, sigV4TestSecret, "us-east-1", "service", sigV4TestTime); err != nil {
		t.Fatalf("signV4: %v", err)
	}

	const want = "AWS4-HMAC-SHA256 " +
		"Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
		"SignedHeaders=host;x-amz-date, " +
		"Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"

	if got := req.Header.Get("Authorization"); got != want {
		t.Errorf("Authorization header mismatch\n got: %s\nwant: %s", got, want)
	}
	if got := req.Header.Get("X-Amz-Date"); got != "20150830T123600Z" {
		t.Errorf("X-Amz-Date = %q", got)
	}
}

// TestSignV4RefusesEmptyCredential checks that an empty key is refused rather
// than signed with.
//
// An empty secret produces a perfectly well-formed signature, so without the
// explicit check the operator's diagnostic would be a bare 403 from AWS with
// nothing pointing at the real cause.
func TestSignV4RefusesEmptyCredential(t *testing.T) {
	for _, tc := range []struct{ name, id, secret string }{
		{"no access key id", "", sigV4TestSecret},
		{"no secret", sigV4TestAccessKey, ""},
		{"neither", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
			err := signV4(req, nil, tc.id, tc.secret, "us-east-1", "service", sigV4TestTime)
			if err == nil {
				t.Fatal("signV4 accepted an empty credential")
			}
			if req.Header.Get("Authorization") != "" {
				t.Error("a refused signing attempt still set an Authorization header")
			}
		})
	}
}

// TestSignV4ErrorNeverCarriesSecret guards the property the whole package is
// built around: no error path renders the credential.
func TestSignV4ErrorNeverCarriesSecret(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	err := signV4(req, nil, "", sigV4TestSecret, "us-east-1", "service", sigV4TestTime)
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), sigV4TestSecret) {
		t.Errorf("error text carries the secret access key: %v", err)
	}
}

// TestCanonicalQueryEncoding pins the RFC 3986 rules SigV4 requires and
// url.QueryEscape gets wrong.
//
// A space must be "%20" and not "+", and "~" must be left unescaped. Both are
// silent failures: the request still goes out, AWS reconstructs a different
// canonical string, and the only symptom is a signature mismatch.
func TestCanonicalQueryEncoding(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"a b", "a%20b"},
		{"a~b", "a~b"},
		{"a/b", "a%2Fb"},
		{"example.com.", "example.com."},
		{"a+b", "a%2Bb"},
	} {
		if got := uriEncode(tc.in); got != tc.want {
			t.Errorf("uriEncode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestSignV4SignsContentTypeWhenPresent pins the one branch the published
// vector does not reach.
//
// AWS's get-vanilla case is a GET with no body, no query and no content-type,
// so it verifies the key derivation, the string-to-sign and the empty-payload
// hash but never exercises the content-type header. That branch is used by the
// POST that actually writes records, where a mistake would mean the provider
// can read zones but never publish a challenge.
//
// This test is SELF-REFERENTIAL and does not prove AWS-correctness: it locks in
// the two things that are easy to get wrong and easy to regress -- content-type
// sorts before host, and it must appear in SignedHeaders -- against a value
// derived by reading the specification, not one AWS published. A wrong
// signature here fails loudly as a 403 on the first real call, so this is a
// regression lock rather than a security control.
func TestSignV4SignsContentTypeWhenPresent(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://route53.amazonaws.com/2013-04-01/hostedzone/Z1/rrset/", nil)
	req.Header.Set("Content-Type", "application/xml")

	if err := signV4(req, []byte("<body/>"), sigV4TestAccessKey, sigV4TestSecret, "us-east-1", "route53", sigV4TestTime); err != nil {
		t.Fatalf("signV4: %v", err)
	}

	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "SignedHeaders=content-type;host;x-amz-date") {
		t.Errorf("SignedHeaders must list content-type first and include it at all: %s", auth)
	}
	if strings.Contains(auth, sigV4TestSecret) {
		t.Errorf("the Authorization header carries the secret: %s", auth)
	}

	// A body must change the signature: the payload hash is part of the
	// canonical request, so a signer that ignored the body would produce the
	// same signature for different content.
	other, _ := http.NewRequest(http.MethodPost, "https://route53.amazonaws.com/2013-04-01/hostedzone/Z1/rrset/", nil)
	other.Header.Set("Content-Type", "application/xml")
	if err := signV4(other, []byte("<different/>"), sigV4TestAccessKey, sigV4TestSecret, "us-east-1", "route53", sigV4TestTime); err != nil {
		t.Fatalf("signV4: %v", err)
	}
	if other.Header.Get("Authorization") == auth {
		t.Error("two different bodies produced the same signature: the payload is not being signed")
	}
}

// TestCanonicalQuerySortsParameters checks that parameters are ordered by name,
// which SigV4 requires and Go's map iteration does not provide.
func TestCanonicalQuerySortsParameters(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/p?zeta=1&alpha=2&mid=3", nil)
	if got, want := canonicalQuery(req.URL), "alpha=2&mid=3&zeta=1"; got != want {
		t.Errorf("canonicalQuery = %q, want %q", got, want)
	}
}
