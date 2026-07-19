package keys

import (
	"encoding/base64"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// AuthorizedKeyLine reconstructs a canonical, options-free authorized_keys line
// from a ParsedKey. It never consults raw input: the line is rebuilt from the
// stored algorithm, blob, and comment. authorized_keys options are structurally
// unrepresentable here and can never be emitted.
func AuthorizedKeyLine(k ParsedKey) (string, error) {
	return AuthorizedKeyLineFrom(k.Algorithm, k.Blob, k.Comment)
}

// AuthorizedKeyLineFrom reconstructs a canonical authorized_keys line from an
// algorithm, wire-format blob, and comment. The output is
// "<alg> <base64(blob)>[ <comment>]" followed by a single "\n".
//
// Defense in depth: the algorithm must be allowlisted; the blob is re-parsed
// and its type must match alg (a tampered blob is refused); the strength check
// is re-run; and the emitted blob is the re-normalized ssh.PublicKey.Marshal,
// never the caller's bytes verbatim. The comment is re-validated and must carry
// no line breaks.
func AuthorizedKeyLineFrom(alg domain.Algorithm, blob []byte, comment string) (string, error) {
	if !alg.IsValid() {
		return "", ErrUnsupportedAlgorithm
	}

	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return "", ErrMalformed
	}
	if pub.Type() != string(alg) {
		return "", ErrMalformed
	}
	if _, err := strength(alg, pub); err != nil {
		return "", err
	}

	comment = strings.TrimSpace(comment)
	if domain.ValidateKeyComment(comment) != nil ||
		strings.ContainsAny(comment, "\n\r") {
		return "", ErrBadComment
	}

	marshaled := pub.Marshal()
	var b strings.Builder
	// Pre-size the buffer for "<alg> <base64(blob)>[ <comment>]\n" so the line is
	// built without intermediate re-allocations. Marshal is called once and
	// reused for both the size hint and the encoding.
	b.Grow(len(alg) + 1 + base64.StdEncoding.EncodedLen(len(marshaled)) + 1 + len(comment) + 1)
	b.WriteString(string(alg))
	b.WriteByte(' ')
	b.WriteString(base64.StdEncoding.EncodeToString(marshaled))
	if comment != "" {
		b.WriteByte(' ')
		b.WriteString(comment)
	}
	b.WriteByte('\n')
	return b.String(), nil
}
