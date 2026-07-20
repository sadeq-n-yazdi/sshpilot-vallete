package sqlite

import (
	"context"
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// listOverrideRepo is the SQLite adapter for durable runtime edits to the
// reserved-identifier lists (ADR-0017, Fb3).
//
// Every method is unscoped, because the reserved-identifier lists are global
// service policy rather than any owner's data; see
// repository.ListOverrideRepository and migration0011ListOverrides.
//
// # Reads validate what they decode
//
// List refuses a row whose list or state is not a known domain value rather
// than returning it, for the same reason adminRepo refuses an unknown status.
// These rows are a policy input: they decide which identifiers the service will
// refuse and which exemptions stand. A row that cannot be interpreted must never
// be replayed as though it could be, and the direction of a misinterpretation is
// exactly the fail-open one this table exists to close -- a tombstone read as
// anything other than a tombstone lets the seed resurrect a removed entry. The
// CHECK constraints already refuse such a row on write, so a decode failure here
// means the table was modified out from under the application, which is
// precisely when returning the row would be worst. Failing the read makes the
// caller fail closed.
type listOverrideRepo struct {
	e execer
}

// Compile-time assertion that listOverrideRepo satisfies the port.
var _ repository.ListOverrideRepository = (*listOverrideRepo)(nil)

// listOverrideColumns is the column list shared by Put and List, so the two
// cannot drift into different shapes.
const listOverrideColumns = `list, skeleton, entry, state, actor_id, updated_at`

// Put records an override, replacing any previous decision for the same list
// and skeleton.
//
// The upsert targets the (list, skeleton) primary key, so an entry that is
// added, removed, and added again stays one row carrying its current state
// rather than accumulating decisions a reader would have to order. The history
// belongs to the append-only audit log.
//
// Both enum fields are validated before the insert as well as by the table's
// CHECKs, so a caller's mistake surfaces as domain.ErrInvalidInput rather than
// an opaque driver error. The skeleton is required and not derived here:
// repositories never compute hashes or normalized forms, and deriving it in the
// adapter would let SQLite and Postgres disagree about an entry's identity.
func (r *listOverrideRepo) Put(ctx context.Context, o *domain.ListOverride) error {
	if o == nil {
		return fmt.Errorf("%s: nil list override: %w", errPrefix, domain.ErrInvalidInput)
	}
	if !o.List.IsValid() {
		return fmt.Errorf("%s: invalid list kind: %w", errPrefix, domain.ErrInvalidInput)
	}
	if !o.State.IsValid() {
		return fmt.Errorf("%s: invalid list override state: %w", errPrefix, domain.ErrInvalidInput)
	}
	if o.Skeleton == "" {
		return fmt.Errorf("%s: empty list override skeleton: %w", errPrefix, domain.ErrInvalidInput)
	}
	// The raw entry is required even for a tombstone. A removal with no
	// spelling would leave a reviewer with only a skeleton, which must never be
	// displayed as the thing that was decided.
	if o.Entry == "" {
		return fmt.Errorf("%s: empty list override entry: %w", errPrefix, domain.ErrInvalidInput)
	}
	if o.ActorID == "" {
		return fmt.Errorf("%s: empty list override actor id: %w", errPrefix, domain.ErrInvalidInput)
	}

	const q = `INSERT INTO list_overrides (` + listOverrideColumns + `)
	VALUES (?, ?, ?, ?, ?, ?)
	ON CONFLICT (list, skeleton) DO UPDATE SET
		entry = excluded.entry,
		state = excluded.state,
		actor_id = excluded.actor_id,
		updated_at = excluded.updated_at`
	_, err := r.e.ExecContext(ctx, q,
		string(o.List), o.Skeleton, o.Entry, string(o.State),
		string(o.ActorID), encTime(o.UpdatedAt))
	if err != nil {
		return mapError(err)
	}
	return nil
}

// List returns every override, ordered by list then skeleton.
//
// The order is explicit rather than incidental because replay applies these
// over a seed: an unstable order would let the composed policy depend on how
// the database happened to return rows. It returns a nil slice when there are
// no overrides.
//
// UNSCOPED: the reserved-identifier lists are global service policy on the
// system axis, not owner-owned data.
func (r *listOverrideRepo) List(ctx context.Context) ([]domain.ListOverride, error) {
	const q = `SELECT ` + listOverrideColumns + ` FROM list_overrides ORDER BY list, skeleton`
	rows, err := r.e.QueryContext(ctx, q)
	if err != nil {
		return nil, mapError(err)
	}
	defer func() { _ = rows.Close() }()

	var out []domain.ListOverride
	for rows.Next() {
		o, serr := scanListOverride(rows)
		if serr != nil {
			return nil, serr
		}
		out = append(out, *o)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	return out, nil
}

// scanListOverride decodes one override row, validating both enums and the
// timestamp. See listOverrideRepo for why an unrecognized value is an error
// rather than a value passed through to the caller.
func scanListOverride(s rowScanner) (*domain.ListOverride, error) {
	var list, skeleton, entry, state, actorID, updatedAt string
	if err := s.Scan(&list, &skeleton, &entry, &state, &actorID, &updatedAt); err != nil {
		return nil, mapError(err)
	}

	kind := domain.ListKind(list)
	if !kind.IsValid() {
		return nil, fmt.Errorf("%s: list override has unknown list %q: %w",
			errPrefix, list, domain.ErrInvalidInput)
	}
	st := domain.ListOverrideState(state)
	if !st.IsValid() {
		return nil, fmt.Errorf("%s: list override for %q has unknown state: %w",
			errPrefix, list, domain.ErrInvalidInput)
	}

	updated, err := decTime(updatedAt)
	if err != nil {
		return nil, err
	}

	return &domain.ListOverride{
		List:      kind,
		Skeleton:  skeleton,
		Entry:     entry,
		State:     st,
		ActorID:   domain.AdministratorID(actorID),
		UpdatedAt: updated,
	}, nil
}
