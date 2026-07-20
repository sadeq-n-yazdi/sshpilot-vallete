// Command vallet-helper syncs a published sshpilot-vallet key set into the
// managed block of a user's authorized_keys file.
//
// It is run on the server whose access is being managed, typically from cron
// or a systemd timer:
//
//	vallet-helper -url https://vallet.example/keysets/<id>/authorized_keys
//	vallet-helper -url https://... -dry-run
//
// The key set is fetched over HTTPS -- plain HTTP is refused, and there is no
// flag to disable certificate verification -- and every line is validated and
// canonicalized before anything is written. Only the region between the
// managed-block markers is replaced; the rest of the file, including the
// user's own keys, is left byte for byte as it was. See internal/managedblock
// for the marker format and the fail-closed rules.
//
// The exit code is 0 on success, 1 on any failure. In -dry-run mode nothing is
// written and the report says whether a real run would change the file.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/managedblock"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/version"
)

// defaultTimeout bounds the whole fetch. A helper on a timer must never wedge
// waiting on an unresponsive server.
const defaultTimeout = 30 * time.Second

// maxResponseBytes bounds the key set a server may return, so a hostile or
// broken endpoint cannot exhaust memory on the managed host.
const maxResponseBytes = managedblock.MaxFileBytes

// source supplies the published key set. It is an interface so the local
// merge-and-write path is testable without a network.
type source interface {
	Fetch(ctx context.Context) ([]string, error)
}

// main stays thin: it only turns run's error into an exit code.
func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr, defaultClient()); err != nil {
		fmt.Fprintf(os.Stderr, "vallet-helper: %v\n", err)
		os.Exit(1)
	}
}

// defaultClient is the HTTPS client used in production. It pins a modern TLS
// floor and never disables verification; there is deliberately no flag to
// weaken it, because a helper that trusts any certificate would let anyone on
// the path install keys on the host.
func defaultClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
		},
	}
}

// run parses flags, fetches the key set, and applies it.
func run(args []string, stdout, stderr io.Writer, client *http.Client) error {
	fs := flag.NewFlagSet("vallet-helper", flag.ContinueOnError)
	fs.SetOutput(stderr)
	endpoint := fs.String("url", "", "HTTPS URL of the published key set (required)")
	path := fs.String("path", "", "authorized_keys file to maintain (default ~/.ssh/authorized_keys)")
	dryRun := fs.Bool("dry-run", false, "report what would change and write nothing")
	check := fs.Bool("check", false, "alias for -dry-run")
	timeout := fs.Duration("timeout", defaultTimeout, "bound on the fetch")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		_, _ = fmt.Fprintln(stdout, version.String())
		return nil
	}

	target, err := targetPath(*path)
	if err != nil {
		return err
	}
	var src source
	src, err = newHTTPSource(*endpoint, client)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	pubkeys, err := src.Fetch(ctx)
	if err != nil {
		return err
	}

	return apply(managedblock.Options{Path: target, DryRun: *dryRun || *check}, pubkeys, stdout)
}

// apply performs the merge and prints a one-line report.
func apply(opts managedblock.Options, pubkeys []string, stdout io.Writer) error {
	rep, err := managedblock.Apply(pubkeys, opts)
	if err != nil {
		return err
	}
	if !rep.Changed {
		_, _ = fmt.Fprintf(stdout, "%s is up to date (%d keys)\n", rep.Path, len(pubkeys))
		return nil
	}
	verb := "updated"
	if opts.DryRun {
		verb = "would change"
	}
	_, _ = fmt.Fprintf(stdout, "%s %s (%d keys, %d bytes, mode %04o)\n",
		rep.Path, verb, len(pubkeys), rep.Size, rep.Mode)
	return nil
}

// targetPath resolves the authorized_keys path, defaulting to the current
// user's ~/.ssh/authorized_keys.
func targetPath(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine the home directory; pass -path: %w", err)
	}
	return filepath.Join(home, ".ssh", "authorized_keys"), nil
}

// httpSource fetches a published key set over HTTPS.
type httpSource struct {
	url    string
	client *http.Client
}

// newHTTPSource validates the endpoint. Only absolute https URLs are accepted:
// over plain HTTP anyone on the path could serve their own key set, and the
// content is about to become login credentials on this host.
func newHTTPSource(endpoint string, client *http.Client) (*httpSource, error) {
	if endpoint == "" {
		return nil, errors.New("-url is required")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, errors.New("-url is not a valid URL")
	}
	if u.Scheme != "https" {
		return nil, errors.New("-url must be an https URL")
	}
	if u.Host == "" {
		return nil, errors.New("-url must include a host")
	}
	return &httpSource{url: endpoint, client: client}, nil
}

// Fetch retrieves the key set and returns its non-blank lines. Validation is
// left to internal/managedblock, which rejects anything that is not a plain
// public key; this layer only bounds the size and refuses a non-200 response.
func (s *httpSource) Fetch(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", "vallet-helper/"+version.String())

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch key set: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch key set: server returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read key set: %w", err)
	}
	if len(body) > maxResponseBytes {
		return nil, errors.New("read key set: response exceeds the maximum permitted size")
	}
	return splitLines(string(body)), nil
}

// splitLines returns the non-blank lines of the response. Blank lines are
// dropped because a published set may end with one; anything else, including a
// comment line, is passed through and rejected by validation.
func splitLines(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		if strings.TrimSpace(strings.TrimSuffix(line, "\r")) == "" {
			continue
		}
		out = append(out, strings.TrimSuffix(line, "\r"))
	}
	return out
}
