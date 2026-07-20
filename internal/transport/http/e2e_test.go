package httpserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/keys"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/migrate"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/schema"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/bootstrap"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/publish"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
)

// e2eNow is the fixed timestamp stamped on seeded rows.
var e2eNow = time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)

// e2e is the whole slice assembled: a migrated SQLite database, the real
// publish service over it, the real router and middleware chain, and a real
// HTTP listener with a real client talking to it.
//
// Nothing is stubbed. The point of this harness is that every assertion below
// is a statement about the shipped system rather than about a test double, and
// in particular that the seeding path is the same one an operator runs.
type e2e struct {
	t      *testing.T
	db     *sql.DB
	store  *sqlite.Store
	server *httptest.Server
	client *http.Client
}

func newE2E(t *testing.T) *e2e {
	t.Helper()

	db, err := sqlite.Open(sqlite.Options{Path: ":memory:"})
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	reg, err := schema.Registry()
	if err != nil {
		t.Fatalf("schema.Registry: %v", err)
	}
	runner, err := migrate.NewRunner(sqlite.NewMigrateDB(db), migrate.EngineSQLite, reg)
	if err != nil {
		t.Fatalf("migrate.NewRunner: %v", err)
	}
	if _, err := runner.Up(context.Background()); err != nil {
		t.Fatalf("migrate Up: %v", err)
	}

	store := sqlite.NewStore(db)
	svc, err := publish.New(store.Repos())
	if err != nil {
		t.Fatalf("publish.New: %v", err)
	}

	srv := httptest.NewServer(NewHandler(nil, slog.New(slog.DiscardHandler), okPinger{}, svc))
	t.Cleanup(srv.Close)

	return &e2e{
		t:      t,
		db:     db,
		store:  store,
		server: srv,
		// Redirects are not followed: a publish response must be the answer
		// itself, and a silently followed redirect would mask a routing bug.
		client: &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// response is a fully-read HTTP response, so the body and headers can be
// compared after the connection is released.
type response struct {
	status  int
	header  http.Header
	body    string
	rawBody []byte
}

func (e *e2e) request(method, path string, headers map[string]string) response {
	e.t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), method, e.server.URL+path, nil)
	if err != nil {
		e.t.Fatalf("new request: %v", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatalf("read body: %v", err)
	}
	return response{status: resp.StatusCode, header: resp.Header, body: string(body), rawBody: body}
}

func (e *e2e) get(path string) response { return e.request(http.MethodGet, path, nil) }

// seed creates an owner through the real bootstrap path.
func (e *e2e) seed(handle string, comment string) bootstrap.Result {
	e.t.Helper()

	res, err := bootstrap.Seed(context.Background(), e.store, bootstrap.Params{
		Handle:  handle,
		KeyLine: e2eKeyLine(e.t, comment),
		Now:     e2eNow,
		Guard:   mustGuard(e.t),
	})
	if err != nil {
		e.t.Fatalf("bootstrap.Seed(%q): %v", handle, err)
	}
	return res
}

// addKey attaches another generated key to an existing owner's set.
func (e *e2e) addKey(ownerID domain.OwnerID, setID domain.KeySetID, comment string) domain.PublicKeyID {
	e.t.Helper()

	parsed, err := keys.Parse(e2eKeyLine(e.t, comment))
	if err != nil {
		e.t.Fatalf("keys.Parse: %v", err)
	}

	var res bootstrap.Result
	err = e.store.WithTx(context.Background(), func(ctx context.Context, r repository.Repos) error {
		var addErr error
		res, addErr = bootstrap.AddKey(ctx, r, bootstrap.AddKeyParams{
			OwnerID: ownerID, KeySetID: setID, DeviceName: "e2e", Key: parsed, Now: e2eNow,
		})
		return addErr
	})
	if err != nil {
		e.t.Fatalf("AddKey: %v", err)
	}
	return res.PublicKeyID
}

func (e *e2e) exec(query string, args ...any) {
	e.t.Helper()

	if _, err := e.db.Exec(query, args...); err != nil {
		e.t.Fatalf("exec: %v", err)
	}
}

func e2eKeyLine(t *testing.T, comment string) []byte {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	if comment != "" {
		line += " " + comment
	}
	return []byte(line + "\n")
}

// TestEndToEndPublishFlow walks the whole slice the way a real consumer does:
// bootstrap an owner with a key, fetch the published file, confirm it is
// something sshd would accept, then revalidate with the returned ETag.
func TestEndToEndPublishFlow(t *testing.T) {
	t.Parallel()

	e := newE2E(t)
	e.seed("alice", "alice@laptop")

	resp := e.get("/alice")
	if resp.status != http.StatusOK {
		t.Fatalf("GET /alice = %d, want 200 (body %q)", resp.status, resp.body)
	}
	if ct := resp.header.Get("Content-Type"); ct != publishContentType {
		t.Errorf("Content-Type = %q, want %q", ct, publishContentType)
	}
	if cl := resp.header.Get("Content-Length"); cl != strconv.Itoa(len(resp.rawBody)) {
		t.Errorf("Content-Length = %q, want %d", cl, len(resp.rawBody))
	}
	if cc := resp.header.Get("Cache-Control"); cc != "public, max-age=60" {
		t.Errorf("Cache-Control = %q", cc)
	}

	// The body must be a real authorized_keys file, not merely a 200.
	if !strings.HasSuffix(resp.body, "\n") {
		t.Errorf("body does not end with a newline: %q", resp.body)
	}
	entries := strings.Split(strings.TrimSuffix(resp.body, "\n"), "\n")
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1: %q", len(entries), resp.body)
	}
	pub, comment, options, rest, err := ssh.ParseAuthorizedKey(resp.rawBody)
	if err != nil {
		t.Fatalf("published body is not valid authorized_keys: %v", err)
	}
	if len(options) != 0 {
		t.Errorf("published entry carries options %v", options)
	}
	if len(rest) != 0 {
		t.Errorf("published body has trailing content %q", rest)
	}
	if comment != "alice@laptop" {
		t.Errorf("comment = %q, want alice@laptop", comment)
	}
	if pub.Type() != string(domain.AlgEd25519) {
		t.Errorf("algorithm = %q", pub.Type())
	}

	etag := resp.header.Get("ETag")
	if etag == "" {
		t.Fatal("no ETag returned, so a client cannot revalidate")
	}

	// Re-fetch with the tag we were just given: the whole point of the caching
	// contract is that an unchanged key list costs a 304 and no body.
	cond := e.request(http.MethodGet, "/alice", map[string]string{"If-None-Match": etag})
	if cond.status != http.StatusNotModified {
		t.Fatalf("conditional GET = %d, want 304", cond.status)
	}
	if cond.body != "" {
		t.Errorf("304 carried a body: %q", cond.body)
	}
	if got := cond.header.Get("ETag"); got != etag {
		t.Errorf("304 ETag = %q, want %q", got, etag)
	}

	// The named default set must serve exactly what the bare handle does.
	byName := e.get("/alice/default")
	if byName.body != resp.body {
		t.Errorf("/alice/default differs from /alice:\n %q\n %q", byName.body, resp.body)
	}
	if byName.header.Get("ETag") != etag {
		t.Error("/alice/default has a different ETag from /alice")
	}
}

// TestEndToEndETagChangesWhenKeysChange confirms the cache contract does not
// pin a stale key list: adding and revoking keys must both move the tag.
func TestEndToEndETagChangesWhenKeysChange(t *testing.T) {
	t.Parallel()

	e := newE2E(t)
	owner := e.seed("alice", "first")

	before := e.get("/alice")
	added := e.addKey(owner.OwnerID, owner.KeySetID, "second")

	afterAdd := e.get("/alice")
	if afterAdd.header.Get("ETag") == before.header.Get("ETag") {
		t.Error("ETag did not change after a key was added")
	}
	if n := len(strings.Split(strings.TrimSuffix(afterAdd.body, "\n"), "\n")); n != 2 {
		t.Fatalf("got %d entries after adding, want 2", n)
	}

	// A stale 304 here would be the caching bug that matters most: a client
	// holding the pre-revocation list would keep trusting a withdrawn key.
	cond := e.request(http.MethodGet, "/alice", map[string]string{"If-None-Match": before.header.Get("ETag")})
	if cond.status == http.StatusNotModified {
		t.Error("stale ETag was accepted as current after the key list changed")
	}

	repos := e.store.Repos()
	if err := repos.PublicKeys.Revoke(context.Background(), owner.OwnerID, added, e2eNow); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	afterRevoke := e.get("/alice")
	if afterRevoke.body != before.body {
		t.Errorf("after revoking the added key the body should match the original:\n got  %q\n want %q",
			afterRevoke.body, before.body)
	}
	if n := len(strings.Split(strings.TrimSuffix(afterRevoke.body, "\n"), "\n")); n != 1 {
		t.Errorf("revoked key is still published: %q", afterRevoke.body)
	}
}

// TestEndToEndNotFoundResponsesAreByteIdentical is the anti-oracle test.
//
// Each case below fails for a DIFFERENT reason, and an unauthenticated stranger
// must not be able to tell which. If "no such handle" were distinguishable from
// "that handle exists but the set belongs to someone else", the endpoint would
// be a free enumeration tool for other people's accounts and set names.
//
// The comparison is over status, body bytes, and every header except the two
// that are per-response by construction.
func TestEndToEndNotFoundResponsesAreByteIdentical(t *testing.T) {
	t.Parallel()

	e := newE2E(t)

	alice := e.seed("alice", "alice@laptop")
	bob := e.seed("bob", "bob@laptop")

	// Give bob a second, distinctly named set, and make one of alice's private.
	e.exec(`UPDATE key_sets SET name = 'bobprivate' WHERE id = ?`, string(bob.KeySetID))
	e.exec(`INSERT INTO key_sets (id, owner_id, name, visibility, is_default, state,
flagged_for_review, quarantine_on_release, created_at, updated_at)
VALUES ('setprivate', ?, 'hidden', 'protected', 0, 'active', 0, 0, ?, ?)`,
		string(alice.OwnerID), e2eNow.Format(e2eTimeLayout), e2eNow.Format(e2eTimeLayout))

	cases := []struct {
		name string
		path string
	}{
		{name: "unknown handle", path: "/nosuchhandle"},
		{name: "unknown set on a real handle", path: "/alice/nosuchset"},
		{name: "another owner's set", path: "/alice/bobprivate"},
		{name: "a protected set of the same owner", path: "/alice/hidden"},
		{name: "malformed handle", path: "/NotAHandle"},
		{name: "malformed set name", path: "/alice/Not_A_Set"},
		{name: "unknown handle with a set", path: "/nosuchhandle/nosuchset"},
	}

	first := e.get(cases[0].path)
	if first.status != http.StatusNotFound {
		t.Fatalf("%s = %d, want 404", cases[0].path, first.status)
	}

	for _, tc := range cases[1:] {
		t.Run(tc.name, func(t *testing.T) {
			got := e.get(tc.path)

			if got.status != first.status {
				t.Errorf("status = %d, want %d (distinguishable from %q)", got.status, first.status, cases[0].path)
			}
			if got.body != first.body {
				t.Errorf("body = %q, want %q", got.body, first.body)
			}
			assertSameHeaders(t, first.header, got.header)
		})
	}

	// Sanity: the fixture really does contain the things being probed for, so
	// the identical 404s are a genuine refusal rather than an empty database.
	if resp := e.get("/alice"); resp.status != http.StatusOK {
		t.Fatalf("alice's own default set = %d, want 200; the fixture is wrong", resp.status)
	}
	if resp := e.get("/bob/bobprivate"); resp.status != http.StatusOK {
		t.Fatalf("bob's own set = %d, want 200; the fixture is wrong", resp.status)
	}
}

// e2eTimeLayout mirrors the SQLite adapter's fixed-width UTC layout, so raw-SQL
// fixtures write rows the adapter can decode.
const e2eTimeLayout = "2006-01-02T15:04:05.000000000Z07:00"

// TestEndToEndHeadParity checks HEAD against a real server, where net/http's
// own body handling is in play, complementing the recorder-level check.
func TestEndToEndHeadParity(t *testing.T) {
	t.Parallel()

	e := newE2E(t)
	e.seed("alice", "alice@laptop")

	for _, path := range []string{"/alice", "/alice/default", "/nosuchhandle"} {
		t.Run(path, func(t *testing.T) {
			get := e.get(path)
			head := e.request(http.MethodHead, path, nil)

			if head.status != get.status {
				t.Errorf("status HEAD %d != GET %d", head.status, get.status)
			}
			if head.body != "" {
				t.Errorf("HEAD returned a body: %q", head.body)
			}
			// Content-Length in particular must describe the GET's body, not
			// the zero bytes HEAD actually sent.
			if hcl, gcl := head.header.Get("Content-Length"), get.header.Get("Content-Length"); hcl != gcl {
				t.Errorf("Content-Length HEAD %q != GET %q", hcl, gcl)
			}
			assertSameHeaders(t, get.header, head.header)
		})
	}
}

// TestEndToEndCommentInjectionOverHTTP repeats the injection defense across the
// full stack, so the guarantee is proven where a consumer actually observes it:
// in the bytes on the wire.
func TestEndToEndCommentInjectionOverHTTP(t *testing.T) {
	t.Parallel()

	e := newE2E(t)
	owner := e.seed("alice", "harmless")

	const forged = `no-pty,command="/bin/sh" ssh-ed25519 ` +
		`AAAAC3NzaC1lZDI1NTE5AAAAIJm7t7g6Uu1PL7lxQvfLh7dGxzZBLcYqLxYUlD8HpXTd attacker@evil`

	e.exec(`UPDATE public_keys SET comment = ? WHERE owner_id = ?`,
		"ok\n"+forged, string(owner.OwnerID))

	resp := e.get("/alice")

	if strings.Contains(resp.body, "attacker@evil") {
		t.Fatalf("FORGED ENTRY SERVED OVER HTTP: %q", resp.body)
	}
	if resp.status == http.StatusOK {
		t.Fatalf("a corrupted row was served as 200: %q", resp.body)
	}
	// It must be a 500, not a 404: a corrupted row is an internal fault, and
	// reporting it as "not found" would present data corruption to an operator
	// as an ordinary empty account.
	if resp.status != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.status)
	}
}

// mustGuard builds the real blocklist guard. Tests seed through the same
// enforcement an operator gets, so a name these fixtures use is a name the
// product actually permits.
func mustGuard(t *testing.T) *nameguard.Guard {
	t.Helper()
	g, err := nameguard.Default()
	if err != nil {
		t.Fatalf("nameguard.Default(): %v", err)
	}
	return g
}
