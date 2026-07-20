package device_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/blocklist"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/device"
)

// The engine and the choke point are tested in internal/blocklist and
// internal/nameguard. These tests are about the WIRING: that Register consults
// the guard at all, that it does so on the normalized form, that a refusal
// reaches no storage, and that the allowlist survives the trip through this
// service. They are deliberately not a second copy of the matcher's own suite.

// TestRegisterRefusesBlockedNames covers the create path for each spelling a
// blocked name can arrive in.
//
// The three cases are not variations on one test. Each one fails under a
// different mutation, which is the only reason to have three:
//
//   - "admin" is raw-equal to a curated term. It fails if the guard is not
//     called at all, and passes under every normalization bug, so on its own it
//     proves almost nothing.
//   - "adm1n" is caught only by leetspeak folding. It passes the device charset
//     rule and is raw-equal to nothing on any list.
//   - "аdmin" leads with Cyrillic U+0430, and is caught only by confusable
//     folding.
//
// The homoglyph case is the load-bearing one and it is testable HERE and
// essentially nowhere else in the system. Handles and key-set names are
// confined to [a-z0-9-] by their slug rule, so a Cyrillic character is refused
// by charset validation before the blocklist is ever consulted -- a homoglyph
// test on those Kinds would pass even if the matcher compared raw strings,
// asserting the artifact (refused) rather than the mechanism (folding). Device
// names permit any printable UTF-8, so "аdmin" reaches the matcher and is
// refused only because the skeleton is compared. Replace Skeleton with the raw
// string and this subtest, specifically, fails.
func TestRegisterRefusesBlockedNames(t *testing.T) {
	t.Parallel()

	names := map[string]string{
		"exact curated term": "admin",
		"leetspeak evasion":  "adm1n",
		"cyrillic homoglyph": "аdmin",
	}
	for label, name := range names {
		t.Run(label, func(t *testing.T) {
			t.Parallel()

			repo, auditor, svc := newService(t)
			_, err := svc.Register(t.Context(), "owner-a", name, "req-1")
			if !errors.Is(err, domain.ErrBlockedName) {
				t.Fatalf("Register(%q) = %v, want ErrBlockedName", name, err)
			}
			// A refusal must cost no write and no audit record. Asserting only
			// the error would pass for a service that rejected the caller after
			// persisting the row.
			if len(repo.devices) != 0 {
				t.Errorf("%d devices persisted for a refused name", len(repo.devices))
			}
			if len(auditor.events) != 0 {
				t.Errorf("%d audit records emitted for a device that was never created", len(auditor.events))
			}
		})
	}
}

// TestRefusalDoesNotNameTheMatchedTerm asserts the error is not an oracle.
//
// An error that named the term that matched would let an attacker enumerate the
// curated list one rejected registration at a time: submit a candidate, read
// back whether it was the thing that fired. The list is operator-curated
// precisely because publishing it is not the intent, so the refusal carries the
// matcher's fixed public message and nothing derived from the comparison.
//
// The check is on the whole error chain, since a wrapper added anywhere between
// the matcher and the caller could reintroduce the term.
func TestRefusalDoesNotNameTheMatchedTerm(t *testing.T) {
	t.Parallel()

	_, _, svc := newService(t)
	_, err := svc.Register(t.Context(), "owner-a", "adm1n", "req-1")
	if !errors.Is(err, domain.ErrBlockedName) {
		t.Fatalf("Register = %v, want ErrBlockedName", err)
	}

	got := strings.ToLower(err.Error())
	// "admin" is the curated term that matched; "routing" and "impersonation"
	// are the list names. None of the three may appear. The submitted name
	// itself is separately checked below.
	for _, leak := range []string{"admin", "routing", "impersonation", "offensive"} {
		if strings.Contains(got, leak) {
			t.Errorf("error %q leaks %q; the refusal must not identify what matched", got, leak)
		}
	}
	// The skeleton must not appear either. It is a normalized form of the
	// input, and echoing it would disclose how the folding works even without
	// naming a term.
	if skel := blocklist.Skeleton("adm1n"); strings.Contains(got, skel) {
		t.Errorf("error %q contains the skeleton %q", got, skel)
	}
}

// TestAllowlistWinsOverBlocklist is the false-positive escape hatch working
// through this service.
//
// ADR-0017 adds the allowlist because folding over-blocks legitimate names (the
// Scunthorpe problem), and it is only useful if it takes precedence. That
// precedence lives inside blocklist.Check; this test proves the device service
// does not defeat it -- a Register that consulted the blocklist and then
// re-derived its own verdict would refuse a name the policy permits.
//
// The matcher is built fresh rather than mutating blocklist.DefaultMatcher().
// That constructor is a sync.OnceValues singleton, so SetAllowlist on it would
// alter policy for every other test in the binary and race under -race. A
// separate matcher is also the honest shape: this is what a deployment with an
// administrator-added allowlist entry looks like.
func TestAllowlistWinsOverBlocklist(t *testing.T) {
	t.Parallel()

	const name = "admin"

	// Same lists, same folding; the only difference from the default guard is
	// the allowlist entry.
	m, err := blocklist.NewMatcher(blocklist.DefaultLists()...)
	if err != nil {
		t.Fatalf("blocklist.NewMatcher: %v", err)
	}

	// First establish that this matcher blocks the name WITHOUT the allowlist.
	// Without this the test could pass because the term was never blocked, and
	// would then prove nothing about precedence.
	repo := newFakeRepo()
	auditor := &fakeAuditor{}
	svc, err := device.New(repo, auditor, nameguard.New(m))
	if err != nil {
		t.Fatalf("device.New: %v", err)
	}
	if _, err := svc.Register(t.Context(), "owner-a", name, ""); !errors.Is(err, domain.ErrBlockedName) {
		t.Fatalf("precondition: Register(%q) = %v, want ErrBlockedName before allowlisting", name, err)
	}

	if err := m.SetAllowlist([]string{name}); err != nil {
		t.Fatalf("SetAllowlist: %v", err)
	}

	// Same service, same name, allowlist now present: it must be accepted and
	// actually persisted.
	d, err := svc.Register(t.Context(), "owner-a", name, "")
	if err != nil {
		t.Fatalf("Register(%q) after allowlisting = %v, want success", name, err)
	}
	if d.Name != name {
		t.Errorf("persisted name = %q, want %q", d.Name, name)
	}
	if _, ok := repo.devices[d.ID]; !ok {
		t.Errorf("device %q was not persisted", d.ID)
	}
}

// TestOrdinaryDeviceNamesStillPass guards against the enforcement being so
// aggressive that it breaks the ordinary case. A control that refuses
// everything would pass every test above.
//
// Non-ASCII names are included on purpose: device names are private labels that
// permit any printable UTF-8, and an owner naming a laptop in Japanese or with
// an accented word must not be caught by folding meant for evasions.
func TestOrdinaryDeviceNamesStillPass(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"laptop", "work-macbook", "Ana's Desktop", "ノートPC", "büro-pc"} {
		_, _, svc := newService(t)
		if _, err := svc.Register(t.Context(), "owner-a", name, ""); err != nil {
			t.Errorf("Register(%q) = %v, want success", name, err)
		}
	}
}
