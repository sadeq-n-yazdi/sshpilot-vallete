package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
)

// ErrNestedTx is returned by Store.WithTx when it is called with a context that
// is already inside a WithTx. Phase 1 has no savepoints, so a nested
// transaction cannot be composed and the attempt fails loudly rather than
// silently flattening into the outer transaction (which would break the
// caller's atomicity expectations). It is a programming error, not a data
// conflict, so it is a dedicated sentinel rather than domain.ErrConflict.
var ErrNestedTx = errors.New("postgres: nested WithTx is not supported")

// txMarkerKey is the private context key under which WithTx stashes a marker so
// a re-entrant WithTx call can detect that it is already inside a transaction.
type txMarkerKey struct{}

// Store is the PostgreSQL unit-of-work root. It wraps a single *sql.DB whose
// pool is configured by Open, and hands out repositories that either
// auto-commit (Repos) or run inside one transaction (WithTx).
type Store struct {
	db *sql.DB
}

// Compile-time assertion that Store satisfies the repository.Store port.
var _ repository.Store = (*Store)(nil)

// NewStore wraps db as a Store. db must already be Open-configured; Store does
// not own db's lifecycle and never closes it.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// Repos returns repositories whose operations each auto-commit against the
// underlying *sql.DB. Owners, Handles, Devices, PublicKeys, KeySets, Audit,
// OwnerSalts, LinkedIdentities, RefreshCredentials, and DevicePairings are
// populated; the remaining fields stay nil and are filled by later slices.
func (s *Store) Repos() repository.Repos {
	return reposFor(s.db)
}

// AuditAppender returns the auto-commit audit sink, typed as the insert-only
// repository.AuditAppender so a caller that emits events cannot also read,
// rewrite, or delete them.
//
// This is a separate accessor rather than a reuse of the Repos.Audit field
// because Repos.Audit is typed repository.AuditRepository, which also declares
// the ADR-0024 maintenance operations (PurgeOlderThan, Pseudonymize). Emitting
// code must not be able to reach those, so it is handed the narrow interface
// here; maintenance jobs take Repos.Audit instead. The same concrete type backs
// both — what differs, and what is the actual control, is the interface the
// caller is given.
//
// Consequently an audit emit taken from this accessor auto-commits on its own
// and does not join a caller's WithTx transaction. That is acceptable for an
// append-only log — a committed audit row for a rolled-back change is a
// false positive an investigator can reconcile, whereas the reverse (a silent
// change with no record) is the failure mode that matters — but the
// transaction-bound path arrives with Repos.Audit.
func (s *Store) AuditAppender() repository.AuditAppender {
	return auditAppenderOnly{r: &auditRepo{e: s.db}}
}

// WithTx runs fn inside a single transaction with transaction-bound
// repositories. It begins a transaction at the server's default isolation
// level (READ COMMITTED), commits when fn returns nil, and rolls back when fn
// returns an error or panics; a panic is re-raised after the rollback. The ctx
// passed to fn carries a marker so a nested WithTx is detected and refused with
// ErrNestedTx, and it derives from the transaction's context so cancellation
// propagates into the transaction.
//
// Unlike the SQLite adapter, which serializes every transaction behind a single
// BEGIN IMMEDIATE write lock, Postgres runs transactions concurrently. Two
// concurrent writers racing on the same unique key therefore do not queue: the
// loser's INSERT fails with SQLSTATE 23505 and surfaces as domain.ErrConflict,
// which is the same outcome callers already handle from a non-racing duplicate.
func (s *Store) WithTx(ctx context.Context, fn func(ctx context.Context, r repository.Repos) error) error {
	if ctx.Value(txMarkerKey{}) != nil {
		return ErrNestedTx
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapError(err)
	}

	// A panic must roll back and then continue unwinding; recovering here keeps
	// the database consistent without swallowing the panic.
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()

	txCtx := context.WithValue(ctx, txMarkerKey{}, struct{}{})
	if err := fn(txCtx, reposFor(tx)); err != nil {
		_ = tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%s: commit transaction: %w", errPrefix, err)
	}
	return nil
}

// reposFor builds a repository.Repos backed by the given execer, which is
// either the *sql.DB (auto-commit) or an in-flight *sql.Tx. The repositories
// implemented so far — Owners, Handles, Devices, PublicKeys, KeySets, Audit,
// OwnerSalts, LinkedIdentities, RefreshCredentials, and DevicePairings — are
// populated; the rest are left nil for later slices. They all share that one
// execer, so a set handed out by WithTx runs every operation inside the same
// transaction.
func reposFor(e execer) repository.Repos {
	return repository.Repos{
		Owners:     &ownerRepo{e: e},
		Handles:    &handleRepo{e: e},
		Devices:    &deviceRepo{e: e},
		PublicKeys: &publicKeyRepo{e: e},
		KeySets:    &keySetRepo{e: e},
		Audit:      &auditRepo{e: e},
		OwnerSalts: &ownerSaltRepo{e: e},

		LinkedIdentities:   &linkedIdentityRepo{e: e},
		RefreshCredentials: &refreshCredRepo{e: e},
		DevicePairings:     &pairingRepo{e: e},
	}
}
