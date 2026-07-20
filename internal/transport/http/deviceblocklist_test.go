package httpserver_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// TestRegisterDeviceRejectsBlockedNames is the boundary half of the blocklist
// enforcement: the service refuses the name, and the transport has to turn that
// refusal into an answer that is both correct and quiet.
//
// Correct: 400, not 500. domain.ErrBlockedName has no arm in the error mapper
// until one is added, so without it a blocked name falls to the default and the
// server reports its own fault for what is squarely a client error -- while
// logging the error text at ERROR level on every attempt.
//
// Quiet: the response must not identify what matched. Both spellings are
// checked because they fail differently -- "adm1n" is refused only by leetspeak
// folding, so it also proves the normalized form is what the handler's service
// consulted, and it lets the body be checked for the curated term "admin" that
// the client never sent and must not learn.
func TestRegisterDeviceRejectsBlockedNames(t *testing.T) {
	t.Parallel()

	for label, name := range map[string]string{
		"exact curated term": "admin",
		"leetspeak evasion":  "adm1n",
		"cyrillic homoglyph": "аdmin",
	} {
		t.Run(label, func(t *testing.T) {
			t.Parallel()

			env := newDeviceEnv(t)
			token := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeFullOwner})

			body, err := json.Marshal(map[string]string{"name": name})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			rr := env.do(t, http.MethodPost, devicesPath, token, string(body))

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; a blocked name is a client error, "+
					"and 500 here means the ErrBlockedName arm is missing", rr.Code)
			}

			// The refusal must not name the curated term, the list, or the
			// mechanism. "admin" is the term that matched in every case above,
			// including the two the client did not spell that way.
			got := strings.ToLower(rr.Body.String())
			for _, leak := range []string{"admin", "block", "reserved", "routing", "impersonation", "offensive"} {
				if strings.Contains(got, leak) {
					t.Errorf("response body %q leaks %q; a rejected registration "+
						"must not be a probe of the curated list", rr.Body.String(), leak)
				}
			}

			// Nothing may have been created.
			if n := env.auditCount(domain.AuditActionDeviceRegistered); n != 0 {
				t.Errorf("%d device-registered audit records for a refused name", n)
			}
			if list := env.mustList(t, token); len(list) != 0 {
				t.Errorf("device list = %v, want empty after a refused registration", list)
			}
		})
	}
}

// TestRegisterDeviceStillAcceptsOrdinaryNames pins that the new error arm did
// not turn into a blanket refusal, and that the ordinary 201 path is unchanged.
func TestRegisterDeviceStillAcceptsOrdinaryNames(t *testing.T) {
	t.Parallel()

	env := newDeviceEnv(t)
	token := env.token(t, "owner-a", domain.Scope{Kind: domain.ScopeFullOwner})

	created := env.mustRegister(t, token, "work laptop")
	if created.Name != "work laptop" {
		t.Errorf("name = %q, want %q", created.Name, "work laptop")
	}
}
