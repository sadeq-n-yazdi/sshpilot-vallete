package erasure

import (
	"context"
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// # The owner graph
//
// EraseOwner erases the identifiers it is given; it does not discover them.
// Graph is the traversal that discovers them: given one owner ID it returns
// every identifier that owner's audit records may carry, so the caller can hand
// EraseOwner a complete set. A missed identifier is the silent failure this
// type exists to prevent — the erasure reports success while a real identity is
// left standing in the log.
//
// # What is collected, and what deliberately is not
//
// Collected: the owner ID itself, and the primary key of every row in every
// owner-scoped table — handles, devices, public keys, key sets, access keys,
// refresh credentials, linked identities and device pairings. These are exactly
// the tables carrying an owner_id column in internal/schema, and their IDs are
// exactly the values that reach audit_records.actor_id and target_id, which the
// services write as a plain string conversion of the same typed ID.
//
// Not collected, each for a reason that is load-bearing rather than an
// oversight:
//
//   - audit_records has no owner_id and no foreign key on purpose: its rows must
//     outlive the owners they mention. It is the thing being rewritten, not a
//     source of identifiers.
//   - owner_erasure_salts likewise has no foreign key. It holds the key to the
//     erasure and is destroyed by it; it names no subject of its own.
//   - administrators has no owner_id, deliberately. An administrator is a
//     system-axis principal, not an owner's property, and erasing an owner must
//     not reach it. Collecting an administrator ID here would tombstone that
//     administrator's actions across every owner's history.
//   - key_set_members has no owner_id. Its rows are (key_set_id, public_key_id)
//     pairs, and both of those IDs are already collected from key_sets and
//     public_keys. It contributes no identifier that is not already covered, so
//     traversing it would add a query and no coverage.
//   - reserved-list edits (internal/service/listadmin) are not owner data and
//     are out of erasure scope by the same principle as administrators, plus
//     one more. Their audit records name an administrator as actor and a
//     reserved TERM as target — a policy decision about which words may be
//     registered, not a fact about any owner — and they carry no metadata. A
//     term can coincide with some owner's handle, but the record is still the
//     administrator's act, must outlive every owner for accountability, and is
//     reached by neither this traversal (which collects owner-row IDs, never
//     name strings) nor the metadata scrub (there is no metadata). ADR-0024's
//     "Open items" records this conclusion; the erasure_test suite proves it.
//
// # Why this cannot erase across owners
//
// Every port below takes an owner ID and nothing else, and each adapter binds
// that owner in its own WHERE clause. The traversal writes no SQL of its own and
// has no way to express a join, a list of owners, or an unscoped read: there is
// no argument it could be given that would widen its reach beyond the single
// owner named. The cross-tenant mistake is not guarded against here, it is
// unsayable — which is the standard set by the retention work, where the
// dangerous state was made inexpressible rather than merely validated.
//
// The listers are deliberately narrower than the repository interfaces that
// satisfy them. A port that also offered Revoke or Delete would let a future
// edit turn a read-only traversal into a destructive one without changing the
// type's dependencies; these cannot.

// handleLister lists an owner's handles. repository.HandleRepository satisfies
// it. Each port below follows the same shape and the same rule: one owner ID in,
// that owner's rows out, no other reachable state.
type handleLister interface {
	ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.Handle, error)
}

type deviceLister interface {
	ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.Device, error)
}

type publicKeyLister interface {
	ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.PublicKey, error)
}

type keySetLister interface {
	ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.KeySet, error)
}

type accessKeyLister interface {
	ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.AccessKey, error)
}

type refreshCredentialLister interface {
	ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.RefreshCredential, error)
}

type linkedIdentityLister interface {
	ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.LinkedIdentity, error)
}

type pairingLister interface {
	ListByOwner(ctx context.Context, ownerID domain.OwnerID) ([]domain.DevicePairing, error)
}

// GraphPorts is the set of owner-scoped readers the traversal needs, one per
// owner-scoped table.
//
// It is a struct of named fields rather than a positional constructor because
// the failure it guards against is a silent one. If a new owner-scoped table is
// added and its lister is not wired in, the traversal stops being complete while
// still compiling and still reporting success; a named field that must be filled
// makes the omission visible at the call site, and NewGraph rejects a nil one
// outright.
type GraphPorts struct {
	Handles            handleLister
	Devices            deviceLister
	PublicKeys         publicKeyLister
	KeySets            keySetLister
	AccessKeys         accessKeyLister
	RefreshCredentials refreshCredentialLister
	LinkedIdentities   linkedIdentityLister
	Pairings           pairingLister
}

// Graph walks one owner's rows and collects the identifiers their audit records
// may carry. It holds only ports and no state, so it is safe for concurrent use
// when those ports are.
type Graph struct {
	ports GraphPorts
}

// NewGraph returns a Graph over the given ports. Every port is required.
//
// A nil port is rejected rather than skipped, and that is the whole point: a
// skipped table would make Collect return a short list that no caller can tell
// apart from a complete one, so the erasure would succeed while leaving that
// table's identifiers in the log. Failing here turns a silent incompleteness
// into a loud startup error.
func NewGraph(ports GraphPorts) (*Graph, error) {
	var missing []string
	if ports.Handles == nil {
		missing = append(missing, "handles")
	}
	if ports.Devices == nil {
		missing = append(missing, "devices")
	}
	if ports.PublicKeys == nil {
		missing = append(missing, "public keys")
	}
	if ports.KeySets == nil {
		missing = append(missing, "key sets")
	}
	if ports.AccessKeys == nil {
		missing = append(missing, "access keys")
	}
	if ports.RefreshCredentials == nil {
		missing = append(missing, "refresh credentials")
	}
	if ports.LinkedIdentities == nil {
		missing = append(missing, "linked identities")
	}
	if ports.Pairings == nil {
		missing = append(missing, "pairings")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("erasure: graph is missing owner-scoped readers %v: %w", missing, domain.ErrInvalidInput)
	}
	return &Graph{ports: ports}, nil
}

// Collect returns every identifier belonging to the owner, beginning with the
// owner ID itself and followed by the IDs of that owner's rows in each
// owner-scoped table. The result is deduplicated and never contains an empty
// string.
//
// The traversal reads rows in every lifecycle state, which matters more than it
// looks: revoked devices and revoked keys are among the likeliest subjects in
// the audit log — device.revoked and key.revoked name them — so a collector
// built on active-only reads would miss exactly the identities most worth
// erasing. Every ListByOwner it calls is unfiltered, and the test suite pins
// that by seeding rows in both active and inactive states.
//
// A partially deleted owner is a normal input, not an error. Rows that are gone
// yield nothing and the traversal continues, which is what lets a second pass
// over a half-erased owner converge instead of failing.
//
// Any read failing aborts the collection. A partial list must never be returned:
// the caller cannot distinguish it from a complete one, and would erase against
// it and report success.
func (g *Graph) Collect(ctx context.Context, ownerID domain.OwnerID) ([]string, error) {
	if ownerID == "" {
		return nil, fmt.Errorf("erasure: empty owner id: %w", domain.ErrInvalidInput)
	}

	// The owner ID is the identifier that appears most often in the owner's own
	// records — as the actor of nearly every action they took — so it is seeded
	// before any table is read and does not depend on any row surviving.
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	add(string(ownerID))

	if err := collectInto(ctx, ownerID, g.ports.Handles.ListByOwner, add,
		func(h domain.Handle) string { return string(h.ID) }, "handles"); err != nil {
		return nil, err
	}
	if err := collectInto(ctx, ownerID, g.ports.Devices.ListByOwner, add,
		func(d domain.Device) string { return string(d.ID) }, "devices"); err != nil {
		return nil, err
	}
	if err := collectInto(ctx, ownerID, g.ports.PublicKeys.ListByOwner, add,
		func(k domain.PublicKey) string { return string(k.ID) }, "public keys"); err != nil {
		return nil, err
	}
	if err := collectInto(ctx, ownerID, g.ports.KeySets.ListByOwner, add,
		func(s domain.KeySet) string { return string(s.ID) }, "key sets"); err != nil {
		return nil, err
	}
	if err := collectInto(ctx, ownerID, g.ports.AccessKeys.ListByOwner, add,
		func(k domain.AccessKey) string { return string(k.ID) }, "access keys"); err != nil {
		return nil, err
	}
	if err := collectInto(ctx, ownerID, g.ports.RefreshCredentials.ListByOwner, add,
		func(c domain.RefreshCredential) string { return string(c.ID) }, "refresh credentials"); err != nil {
		return nil, err
	}
	if err := collectInto(ctx, ownerID, g.ports.LinkedIdentities.ListByOwner, add,
		func(li domain.LinkedIdentity) string { return string(li.ID) }, "linked identities"); err != nil {
		return nil, err
	}
	if err := collectInto(ctx, ownerID, g.ports.Pairings.ListByOwner, add,
		func(p domain.DevicePairing) string { return string(p.ID) }, "pairings"); err != nil {
		return nil, err
	}

	return out, nil
}

// collectInto reads one owner-scoped table and feeds each row's ID to add.
//
// It is generic over the row type so that every table is traversed by the same
// code path. Per-table loops would each be a place for the owner argument to be
// dropped or the wrong field to be read; here there is one loop, and what varies
// per table is only which lister to call and which field is the ID.
func collectInto[T any](
	ctx context.Context,
	ownerID domain.OwnerID,
	list func(context.Context, domain.OwnerID) ([]T, error),
	add func(string),
	id func(T) string,
	table string,
) error {
	rows, err := list(ctx, ownerID)
	if err != nil {
		return fmt.Errorf("erasure: collect %s: %w", table, err)
	}
	for _, row := range rows {
		add(id(row))
	}
	return nil
}
