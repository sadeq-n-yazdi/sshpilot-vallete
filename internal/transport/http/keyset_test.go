package httpserver_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/keyset"
)

const (
	setOwnerA domain.OwnerID = "owner-set-a"
	setOwnerB domain.OwnerID = "owner-set-b"
)

func TestKeySetRoundTripOverHTTP(t *testing.T) {
	t.Parallel()
	env := newSetEnv(t)
	env.seedOwner(t, setOwnerA)
	token := env.fullToken(t, setOwnerA)

	created := env.mustCreate(t, token, "prod")
	if created.Name != "prod" || created.Visibility != "protected" || created.IsDefault {
		t.Fatalf("created = %+v, want a protected, non-default set named prod", created)
	}

	if got := env.mustList(t, token); len(got) != 1 || got[0].ID != created.ID {
		t.Fatalf("list = %+v, want the created set", got)
	}

	rr := env.do(t, http.MethodPatch, setPath(created.ID), token, nameBody(t, "production"))
	if rr.Code != http.StatusOK {
		t.Fatalf("rename = %d (%s), want 200", rr.Code, rr.Body.String())
	}
	var renamed setJSON
	decodeInto(t, rr, &renamed)
	if renamed.Name != "production" {
		t.Errorf("renamed name = %q, want production", renamed.Name)
	}
	// The old identifier now names a tombstone and must answer exactly as an
	// identifier that never existed does.
	if rr := env.do(t, http.MethodDelete, setPath(created.ID), token, ""); rr.Code != http.StatusNotFound {
		t.Errorf("delete via the pre-rename id = %d, want 404", rr.Code)
	}

	if rr := env.do(t, http.MethodDelete, setPath(renamed.ID), token, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("delete = %d (%s), want 204", rr.Code, rr.Body.String())
	}
	if got := env.mustList(t, token); len(got) != 0 {
		t.Fatalf("list after delete = %+v, want empty", got)
	}

	for _, action := range []domain.AuditAction{
		domain.AuditActionKeySetCreated,
		domain.AuditActionKeySetRenamed,
		domain.AuditActionKeySetDeleted,
	} {
		if len(env.auditRecords(action)) != 1 {
			t.Errorf("audit records for %s = %d, want 1", action, len(env.auditRecords(action)))
		}
	}
}

// TestEmptyListIsAnArrayNotNull pins the transport's half of the nil-collection
// convention: the service returns nil, and the wire form is "[]" so a client
// need not special-case an owner with no sets.
func TestEmptyListIsAnArrayNotNull(t *testing.T) {
	t.Parallel()
	env := newSetEnv(t)
	env.seedOwner(t, setOwnerA)

	rr := env.do(t, http.MethodGet, keySetsPath, env.fullToken(t, setOwnerA), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200", rr.Code)
	}
	if got := strings.TrimSpace(rr.Body.String()); !strings.Contains(got, `"key_sets":[]`) {
		t.Errorf("body = %s, want an empty array rather than null", got)
	}
}

func TestKeySetNameRejectionsAre400(t *testing.T) {
	t.Parallel()
	env := newSetEnv(t)
	env.seedOwner(t, setOwnerA)
	token := env.fullToken(t, setOwnerA)

	for _, name := range []string{"", "Prod", "-lead", "trail-", strings.Repeat("a", 65), "has space"} {
		rr := env.do(t, http.MethodPost, keySetsPath, token, nameBody(t, name))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("create %q = %d, want 400", name, rr.Code)
		}
	}
	// A blocked name is refused with the SAME status and the same reasonless
	// body as a malformed one, so a caller cannot enumerate the blocklist by
	// comparing the two answers.
	malformed := env.do(t, http.MethodPost, keySetsPath, token, nameBody(t, "has space"))
	blocked := env.do(t, http.MethodPost, keySetsPath, token, nameBody(t, "admin"))
	if blocked.Code != malformed.Code || blocked.Body.String() != malformed.Body.String() {
		t.Errorf("a blocked name is distinguishable from a malformed one:\n  blocked   = %d %s\n  malformed = %d %s",
			blocked.Code, blocked.Body.String(), malformed.Code, malformed.Body.String())
	}
}

// TestUnknownFieldsAreRefused is what makes the absence of visibility,
// is_default, and an owner field a control rather than a convention.
func TestUnknownFieldsAreRefused(t *testing.T) {
	t.Parallel()
	env := newSetEnv(t)
	env.seedOwner(t, setOwnerA)
	token := env.fullToken(t, setOwnerA)

	for _, body := range []string{
		`{"name":"prod","visibility":"public"}`,
		`{"name":"prod","is_default":true}`,
		`{"name":"prod","owner_id":"owner-set-b"}`,
		`{"name":"prod"}{"name":"other"}`, // trailing JSON value
		`{"name":`,                        // truncated
	} {
		if rr := env.do(t, http.MethodPost, keySetsPath, token, body); rr.Code != http.StatusBadRequest {
			t.Errorf("create %s = %d, want 400", body, rr.Code)
		}
	}
	if got := env.mustList(t, token); len(got) != 0 {
		t.Errorf("a refused create produced a set: %+v", got)
	}
}

func TestKeySetConflictsCarryAReason(t *testing.T) {
	t.Parallel()
	env := newSetEnv(t, keyset.WithMaxSets(2))
	env.seedOwner(t, setOwnerA)
	token := env.fullToken(t, setOwnerA)

	first := env.mustCreate(t, token, "prod")

	dup := env.do(t, http.MethodPost, keySetsPath, token, nameBody(t, "prod"))
	if dup.Code != http.StatusConflict || reason(t, dup) != "name_taken" {
		t.Errorf("duplicate = %d %s, want 409 name_taken", dup.Code, dup.Body.String())
	}

	env.mustCreate(t, token, "staging")
	capped := env.do(t, http.MethodPost, keySetsPath, token, nameBody(t, "dev"))
	if capped.Code != http.StatusConflict || reason(t, capped) != "limit_reached" {
		t.Errorf("past the cap = %d %s, want 409 limit_reached", capped.Code, capped.Body.String())
	}

	if err := env.store.Repos().KeySets.SetDefault(t.Context(), setOwnerA, domain.KeySetID(first.ID)); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}
	def := env.do(t, http.MethodDelete, setPath(first.ID), token, confirmBody(t, true))
	if def.Code != http.StatusConflict || reason(t, def) != "default_set" {
		t.Errorf("deleting the default = %d %s, want 409 default_set", def.Code, def.Body.String())
	}
}

// TestNonEmptyDeleteConfirmationFailsClosed drives every way a client can fail
// to confirm. All of them must leave the set standing.
func TestNonEmptyDeleteConfirmationFailsClosed(t *testing.T) {
	t.Parallel()
	env := newSetEnv(t)
	env.seedOwner(t, setOwnerA)
	token := env.fullToken(t, setOwnerA)
	set := env.mustCreate(t, token, "prod")
	env.seedMember(t, setOwnerA, domain.KeySetID(set.ID), "key-one")

	cases := map[string]struct {
		body string
		want int
	}{
		"no body":            {"", http.StatusConflict},
		"empty object":       {`{}`, http.StatusConflict},
		"explicit false":     {`{"confirm":false}`, http.StatusConflict},
		"wrong type":         {`{"confirm":"yes"}`, http.StatusBadRequest},
		"unknown field":      {`{"confirmed":true}`, http.StatusBadRequest},
		"malformed":          {`{"confirm":`, http.StatusBadRequest},
		"trailing JSON":      {`{"confirm":false}{"confirm":true}`, http.StatusBadRequest},
		"array not object":   {`[true]`, http.StatusBadRequest},
		"bare true":          {`true`, http.StatusBadRequest},
		"confirm in a query": {"", http.StatusConflict},
	}
	for name, tc := range cases {
		target := setPath(set.ID)
		if name == "confirm in a query" {
			// A query parameter is not the confirmation channel. If it were
			// honored, a link or a redirect could carry a destructive delete.
			target += "?confirm=true"
		}
		rr := env.do(t, http.MethodDelete, target, token, tc.body)
		if rr.Code != tc.want {
			t.Errorf("%s: delete = %d (%s), want %d", name, rr.Code, rr.Body.String(), tc.want)
		}
		if got := env.mustList(t, token); len(got) != 1 {
			t.Fatalf("%s: the set was deleted without confirmation", name)
		}
	}

	if rr := env.do(t, http.MethodDelete, setPath(set.ID), token, confirmBody(t, true)); rr.Code != http.StatusNoContent {
		t.Fatalf("confirmed delete = %d (%s), want 204", rr.Code, rr.Body.String())
	}
}

// TestCrossOwnerResponsesAreIndistinguishable is the security test this file
// exists for. B addressing A's set must produce byte-identical status AND body
// to B addressing an identifier that never existed.
func TestCrossOwnerResponsesAreIndistinguishable(t *testing.T) {
	t.Parallel()
	env := newSetEnv(t)
	env.seedOwner(t, setOwnerA)
	env.seedOwner(t, setOwnerB)

	tokenA := env.fullToken(t, setOwnerA)
	tokenB := env.fullToken(t, setOwnerB)

	plain := env.mustCreate(t, tokenA, "prod")
	def := env.mustCreate(t, tokenA, "primary")
	full := env.mustCreate(t, tokenA, "shared")
	env.seedMember(t, setOwnerA, domain.KeySetID(full.ID), "key-one")
	if err := env.store.Repos().KeySets.SetDefault(t.Context(), setOwnerA, domain.KeySetID(def.ID)); err != nil {
		t.Fatalf("SetDefault: %v", err)
	}

	const invented = "INVENTEDIDENTIFIER00000000"

	// Each of A's sets is one whose refusal for A carries information: the
	// default answers 409 default_set, the non-empty one answers 409
	// confirmation_required. For B, all three must look like nothing at all.
	for _, target := range []string{plain.ID, def.ID, full.ID} {
		checks := []struct {
			name   string
			method string
			body   string
		}{
			{"rename", http.MethodPatch, nameBody(t, "stolen")},
			{"delete", http.MethodDelete, confirmBody(t, true)},
			{"unconfirmed delete", http.MethodDelete, ""},
		}
		for _, c := range checks {
			foreign := env.do(t, c.method, setPath(target), tokenB, c.body)
			unknown := env.do(t, c.method, setPath(invented), tokenB, c.body)
			if foreign.Code != http.StatusNotFound {
				t.Errorf("%s another owner's set = %d, want 404", c.name, foreign.Code)
			}
			if foreign.Code != unknown.Code || foreign.Body.String() != unknown.Body.String() {
				t.Errorf("%s is distinguishable for another owner's set:\n  foreign = %d %s\n  unknown = %d %s",
					c.name, foreign.Code, foreign.Body.String(), unknown.Code, unknown.Body.String())
			}
			if r := reason(t, foreign); r != "" {
				t.Errorf("%s: the 404 carried reason %q; it must carry none", c.name, r)
			}
		}
	}

	// A's sets are untouched, and B sees none of them.
	if got := env.mustList(t, tokenA); len(got) != 3 {
		t.Errorf("A's sets after B's attempts = %+v, want all three", got)
	}
	if got := env.mustList(t, tokenB); len(got) != 0 {
		t.Errorf("B's list contains A's sets: %+v", got)
	}
}

// TestReadOnlyTokenCannotMutate covers the scope check the Guardian derives
// from the HTTP method, so no route has to declare it and none can forget to.
func TestReadOnlyTokenCannotMutateKeySets(t *testing.T) {
	t.Parallel()
	env := newSetEnv(t)
	env.seedOwner(t, setOwnerA)
	set := env.mustCreate(t, env.fullToken(t, setOwnerA), "prod")
	readOnly := env.readOnlyToken(t, setOwnerA)

	mutations := []struct {
		name   string
		method string
		target string
		body   string
	}{
		{"create", http.MethodPost, keySetsPath, nameBody(t, "other")},
		{"rename", http.MethodPatch, setPath(set.ID), nameBody(t, "production")},
		{"delete", http.MethodDelete, setPath(set.ID), confirmBody(t, true)},
	}
	for _, m := range mutations {
		if rr := env.do(t, m.method, m.target, readOnly, m.body); rr.Code != http.StatusForbidden {
			t.Errorf("%s with a read-only token = %d (%s), want 403", m.name, rr.Code, rr.Body.String())
		}
	}
	// Reading still works, so the refusals above are about mutation and not
	// about the token being rejected outright.
	if got := env.mustList(t, readOnly); len(got) != 1 {
		t.Errorf("read-only list = %+v, want the one set", got)
	}
}

// TestSetBoundTokenIsConfinedToItsSet is why the single-set routes declare
// KeySetAccess rather than AccountAccess. Under AccountAccess a set-bound token
// would pass the resource check on every one of the owner's sets.
func TestSetBoundTokenIsConfinedToItsSet(t *testing.T) {
	t.Parallel()
	env := newSetEnv(t)
	env.seedOwner(t, setOwnerA)
	full := env.fullToken(t, setOwnerA)
	mine := env.mustCreate(t, full, "mine")
	other := env.mustCreate(t, full, "other")

	bound := env.setBoundToken(t, setOwnerA, mine.ID)

	// Its own set: allowed.
	if rr := env.do(t, http.MethodPatch, setPath(mine.ID), bound, nameBody(t, "renamed")); rr.Code != http.StatusOK {
		t.Errorf("rename of its own set = %d (%s), want 200", rr.Code, rr.Body.String())
	}
	// A different set of the SAME owner: refused. The owner check would pass
	// here, so only the resource binding can produce this.
	if rr := env.do(t, http.MethodDelete, setPath(other.ID), bound, confirmBody(t, true)); rr.Code != http.StatusForbidden {
		t.Errorf("delete of a sibling set = %d (%s), want 403", rr.Code, rr.Body.String())
	}
	// The account-wide routes: refused, because they name no resource for the
	// binding to be satisfied by.
	if rr := env.do(t, http.MethodPost, keySetsPath, bound, nameBody(t, "third")); rr.Code != http.StatusForbidden {
		t.Errorf("create with a set-bound token = %d, want 403", rr.Code)
	}
	if rr := env.do(t, http.MethodGet, keySetsPath, bound, ""); rr.Code != http.StatusForbidden {
		t.Errorf("list with a set-bound token = %d, want 403", rr.Code)
	}
}

// TestUnauthenticatedRequestsAreRefused checks the routes are guarded at all,
// and that no handler runs before the Guardian.
func TestUnauthenticatedRequestsAreRefused(t *testing.T) {
	t.Parallel()
	env := newSetEnv(t)
	env.seedOwner(t, setOwnerA)
	set := env.mustCreate(t, env.fullToken(t, setOwnerA), "prod")

	for _, c := range []struct{ method, target string }{
		{http.MethodPost, keySetsPath},
		{http.MethodGet, keySetsPath},
		{http.MethodPatch, setPath(set.ID)},
		{http.MethodDelete, setPath(set.ID)},
	} {
		rr := env.do(t, c.method, c.target, "", nameBody(t, "x"))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with no token = %d, want 401", c.method, c.target, rr.Code)
		}
		if got := rr.Header().Get("Vary"); got != "Authorization" {
			t.Errorf("%s %s: Vary = %q, want Authorization", c.method, c.target, got)
		}
	}
}

// TestKeySetRoutesFailClosedWithoutAService pins that a wiring fault is a 500
// and never a 404: degrading into "not found" would hide a broken deployment
// behind a plausible answer.
func TestKeySetRoutesFailClosedWithoutAService(t *testing.T) {
	t.Parallel()
	env := newSetEnvWithoutService(t)
	env.seedOwner(t, setOwnerA)
	token := env.fullToken(t, setOwnerA)

	for _, c := range []struct {
		method, target, body string
	}{
		{http.MethodPost, keySetsPath, nameBody(t, "prod")},
		{http.MethodGet, keySetsPath, ""},
		{http.MethodPatch, setPath("some-id"), nameBody(t, "prod")},
		{http.MethodDelete, setPath("some-id"), ""},
	} {
		if rr := env.do(t, c.method, c.target, token, c.body); rr.Code != http.StatusInternalServerError {
			t.Errorf("%s %s with no service = %d, want 500", c.method, c.target, rr.Code)
		}
	}
}
