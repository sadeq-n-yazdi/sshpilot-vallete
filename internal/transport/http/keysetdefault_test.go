package httpserver_test

import (
	"net/http"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// defaultPath and visibilityPath address the two C4 sub-resources. They are
// built from the same route constant the other tests use, so a test cannot
// address a path the router does not serve while still passing.
func defaultPath(id string) string    { return setPath(id) + "/default" }
func visibilityPath(id string) string { return setPath(id) + "/visibility" }

// visibilityBody renders a visibility request body verbatim, so a test can send
// values a typed helper would not let it construct.
func visibilityBody(v string) string { return `{"visibility":"` + v + `"}` }

// TestDefaultAndVisibilityOverHTTP is the happy path for both routes, asserted
// on the wire shape rather than on the server's own structs.
func TestDefaultAndVisibilityOverHTTP(t *testing.T) {
	t.Parallel()
	env := newSetEnv(t)
	env.seedOwner(t, setOwnerA)
	token := env.fullToken(t, setOwnerA)

	first := env.mustCreate(t, token, "prod")
	second := env.mustCreate(t, token, "staging")

	rr := env.do(t, http.MethodPut, defaultPath(first.ID), token, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("set default = %d (%s), want 200", rr.Code, rr.Body.String())
	}
	var got setJSON
	decodeInto(t, rr, &got)
	if !got.IsDefault {
		t.Error("the response does not report the set as default")
	}
	// The identifier is unchanged: unlike a rename, this does not replace the
	// row, so a client holding the id may keep using it.
	if got.ID != first.ID {
		t.Errorf("set default returned id %q, want %q", got.ID, first.ID)
	}

	// Moving it leaves exactly one default, which is what the bare handle
	// depends on. Read through List so the assertion is on stored state.
	if rr := env.do(t, http.MethodPut, defaultPath(second.ID), token, ""); rr.Code != http.StatusOK {
		t.Fatalf("move default = %d (%s), want 200", rr.Code, rr.Body.String())
	}
	defaults := 0
	for _, s := range env.mustList(t, token) {
		if s.IsDefault {
			defaults++
			if s.ID != second.ID {
				t.Errorf("default is %q, want %q", s.ID, second.ID)
			}
		}
	}
	if defaults != 1 {
		t.Fatalf("%d sets report as default, want exactly 1", defaults)
	}

	for _, want := range []string{"public", "protected"} {
		rr := env.do(t, http.MethodPut, visibilityPath(first.ID), token, visibilityBody(want))
		if rr.Code != http.StatusOK {
			t.Fatalf("set visibility %s = %d (%s), want 200", want, rr.Code, rr.Body.String())
		}
		var out setJSON
		decodeInto(t, rr, &out)
		if out.Visibility != want {
			t.Errorf("visibility = %q, want %q", out.Visibility, want)
		}
	}

	// Both are access-affecting, so both are recorded, and a visibility change
	// is recorded in either direction.
	if n := len(env.auditRecords(domain.AuditActionKeySetDefaultChanged)); n != 2 {
		t.Errorf("default-changed records = %d, want 2", n)
	}
	if n := len(env.auditRecords(domain.AuditActionKeySetVisibilityChanged)); n != 2 {
		t.Errorf("visibility-changed records = %d, want 2", n)
	}
}

// TestVisibilityRequestFailsClosed is the fail-closed check at the transport
// boundary. There is no safe default visibility a malformed request could fall
// back to -- protected would silently narrow and public would silently publish
// -- so every way of not naming one refuses, and none of them changes the set.
func TestVisibilityRequestFailsClosed(t *testing.T) {
	t.Parallel()
	env := newSetEnv(t)
	env.seedOwner(t, setOwnerA)
	token := env.fullToken(t, setOwnerA)
	set := env.mustCreate(t, token, "prod")

	for _, c := range []struct{ name, body string }{
		{"absent body", ""},
		{"empty object", `{}`},
		{"null value", `{"visibility":null}`},
		{"empty string", visibilityBody("")},
		{"unknown value", visibilityBody("unlisted")},
		{"wrong case", visibilityBody("PUBLIC")},
		{"trailing space", visibilityBody("public ")},
		{"malformed json", `{"visibility":`},
		{"unknown field", `{"visibility":"public","is_default":true}`},
		{"wrong type", `{"visibility":true}`},
	} {
		rr := env.do(t, http.MethodPut, visibilityPath(set.ID), token, c.body)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s = %d (%s), want 400", c.name, rr.Code, rr.Body.String())
		}
	}

	// Nothing moved. A refusal that had published the set would be the worst
	// possible outcome of a request that failed to say what it wanted.
	for _, s := range env.mustList(t, token) {
		if s.ID == set.ID && s.Visibility != string(domain.VisibilityProtected) {
			t.Errorf("visibility = %q after refusals, want protected", s.Visibility)
		}
	}
	if n := len(env.auditRecords(domain.AuditActionKeySetVisibilityChanged)); n != 0 {
		t.Errorf("visibility-changed records = %d after refusals, want 0", n)
	}
}

// TestCrossOwnerDefaultAndVisibilityAre404 checks the new routes give another
// owner's set the same reasonless 404 an invented identifier gets. A 403 here,
// or a 404 carrying a reason, would confirm the set exists.
func TestCrossOwnerDefaultAndVisibilityAre404(t *testing.T) {
	t.Parallel()
	env := newSetEnv(t)
	env.seedOwner(t, setOwnerA)
	env.seedOwner(t, setOwnerB)

	victim := env.mustCreate(t, env.fullToken(t, setOwnerA), "prod")
	attacker := env.fullToken(t, setOwnerB)

	for _, c := range []struct{ name, target, body string }{
		{"default, another owner's set", defaultPath(victim.ID), ""},
		{"default, invented id", defaultPath("INVENTEDIDENTIFIER00000000"), ""},
		{"visibility, another owner's set", visibilityPath(victim.ID), visibilityBody("public")},
		{"visibility, invented id", visibilityPath("INVENTEDIDENTIFIER00000000"), visibilityBody("public")},
	} {
		rr := env.do(t, http.MethodPut, c.target, attacker, c.body)
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s = %d (%s), want 404", c.name, rr.Code, rr.Body.String())
		}
		if got := reason(t, rr); got != "" {
			t.Errorf("%s: 404 carried reason %q; it must carry none", c.name, got)
		}
	}

	// A's set is untouched: still protected, still not the default.
	for _, s := range env.mustList(t, env.fullToken(t, setOwnerA)) {
		if s.Visibility != string(domain.VisibilityProtected) || s.IsDefault {
			t.Errorf("A's set changed under B's attempts: %+v", s)
		}
	}
}

// TestSetBoundTokenCannotDesignateTheDefault is the reason the default route
// declares AccountAccess while the visibility route declares KeySetAccess.
//
// Designating a default writes the PREVIOUS default's row -- the repository
// clears is_default on it in the same transaction -- and repoints bare
// GET /{handle}, which is account-wide state. Under KeySetAccess a token
// confined to one set would reach both. Visibility is the opposite case: its
// write touches only the addressed row, so the binding is a sufficient check.
func TestSetBoundTokenCannotDesignateTheDefault(t *testing.T) {
	t.Parallel()
	env := newSetEnv(t)
	env.seedOwner(t, setOwnerA)
	full := env.fullToken(t, setOwnerA)
	mine := env.mustCreate(t, full, "mine")
	other := env.mustCreate(t, full, "other")

	bound := env.setBoundToken(t, setOwnerA, mine.ID)

	// Not even for the set it is bound to.
	if rr := env.do(t, http.MethodPut, defaultPath(mine.ID), bound, ""); rr.Code != http.StatusForbidden {
		t.Errorf("set-bound token designating its own set = %d (%s), want 403", rr.Code, rr.Body.String())
	}
	if rr := env.do(t, http.MethodPut, defaultPath(other.ID), bound, ""); rr.Code != http.StatusForbidden {
		t.Errorf("set-bound token designating a sibling set = %d, want 403", rr.Code)
	}
	// Nothing was designated by either attempt.
	for _, s := range env.mustList(t, full) {
		if s.IsDefault {
			t.Errorf("set %q became the default under a set-bound token", s.ID)
		}
	}

	// Visibility on its own set is allowed; on a sibling it is not.
	if rr := env.do(t, http.MethodPut, visibilityPath(mine.ID), bound, visibilityBody("public")); rr.Code != http.StatusOK {
		t.Errorf("set-bound visibility on its own set = %d (%s), want 200", rr.Code, rr.Body.String())
	}
	if rr := env.do(t, http.MethodPut, visibilityPath(other.ID), bound, visibilityBody("public")); rr.Code != http.StatusForbidden {
		t.Errorf("set-bound visibility on a sibling set = %d, want 403", rr.Code)
	}
	for _, s := range env.mustList(t, full) {
		if s.ID == other.ID && s.Visibility != string(domain.VisibilityProtected) {
			t.Errorf("the sibling set was published by a token bound elsewhere: %+v", s)
		}
	}
}

// TestDefaultAndVisibilityRefuseUnauthenticatedAndReadOnly checks both routes
// are guarded at all, and that the Guardian derives Mutating from the method
// without either route having to declare it.
func TestDefaultAndVisibilityRefuseUnauthenticatedAndReadOnly(t *testing.T) {
	t.Parallel()
	env := newSetEnv(t)
	env.seedOwner(t, setOwnerA)
	set := env.mustCreate(t, env.fullToken(t, setOwnerA), "prod")
	readOnly := env.readOnlyToken(t, setOwnerA)

	for _, c := range []struct{ name, target, body string }{
		{"default", defaultPath(set.ID), ""},
		{"visibility", visibilityPath(set.ID), visibilityBody("public")},
	} {
		rr := env.do(t, http.MethodPut, c.target, "", c.body)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("%s with no token = %d, want 401", c.name, rr.Code)
		}
		if got := rr.Header().Get("Vary"); got != "Authorization" {
			t.Errorf("%s: Vary = %q, want Authorization", c.name, got)
		}
		if rr := env.do(t, http.MethodPut, c.target, readOnly, c.body); rr.Code != http.StatusForbidden {
			t.Errorf("%s with a read-only token = %d, want 403", c.name, rr.Code)
		}
	}
}

// TestDefaultAndVisibilityFailClosedWithoutAService pins that a wiring fault is
// a 500 on these routes too, never a 404 that would hide a broken deployment
// behind a plausible answer.
func TestDefaultAndVisibilityFailClosedWithoutAService(t *testing.T) {
	t.Parallel()
	env := newSetEnvWithoutService(t)
	env.seedOwner(t, setOwnerA)
	token := env.fullToken(t, setOwnerA)

	for _, c := range []struct{ target, body string }{
		{defaultPath("some-id"), ""},
		{visibilityPath("some-id"), visibilityBody("public")},
	} {
		if rr := env.do(t, http.MethodPut, c.target, token, c.body); rr.Code != http.StatusInternalServerError {
			t.Errorf("PUT %s with no service = %d, want 500", c.target, rr.Code)
		}
	}
}
