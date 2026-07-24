package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/repository"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/postgres"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
)

// datastore is the storage surface the composition root builds on: the
// repository.Store port (Repos + WithTx) plus the insert-only AuditAppender each
// adapter exposes. Both *sqlite.Store and *postgres.Store satisfy it, so every
// site that used to name the concrete *sqlite.Store -- the server assembly and
// the two bootstrap subcommands -- now depends on this interface and the driver
// choice lives in exactly one place (newStore).
type datastore interface {
	repository.Store

	// AuditAppender returns the auto-commit, insert-only audit sink. It is not
	// part of repository.Store on purpose (a writer of audit records must not be
	// able to read, purge, or rewrite them), but the composition root needs it to
	// build the recorders, so it is named here alongside the port.
	AuditAppender() repository.AuditAppender
}

// newStore selects the storage adapter for the configured driver and wraps the
// already-open handle in it. It is the single driver-keyed factory the server
// startup and both bootstrap subcommands share, so the store construction can
// never drift from the openDatabase/migrateDatabase driver switches.
//
// The default fails closed: an unknown driver is a startup error, never a silent
// fallback to one engine. config.Validate rejects an unknown driver first, so
// this default is defense in depth for a caller that reached here without it.
func newStore(cfg *config.Config, db *sql.DB) (datastore, error) {
	switch cfg.Database.Driver {
	case "sqlite":
		return sqlite.NewStore(db), nil
	case "postgres":
		return postgres.NewStore(db), nil
	default:
		return nil, fmt.Errorf("database driver %q is not supported", cfg.Database.Driver)
	}
}

// postgresDSN resolves the PostgreSQL connection string from its secret
// reference, mirroring accessKeyPepper's posture exactly: the DSN is a secret
// (it can embed a password) and lives only behind a secrets.Ref, never as a
// config literal. The permission posture follows the environment -- PermError in
// production, PermWarn elsewhere -- the same split accessKeyPepper makes.
//
// The returned value is a secrets.Redacted throughout, so a log line or an error
// that reached it prints a marker rather than the connection string. The caller
// reveals it only at the postgres.Open boundary and never binds it to a name a
// log could reach.
func postgresDSN(ctx context.Context, cfg *config.Config) (secrets.Redacted, error) {
	ref := cfg.Database.Postgres.DSNRef
	if ref.IsZero() {
		// config.Validate already requires this for the postgres driver; checked
		// here as well so this path does not depend on a caller having validated
		// first (bootstrap validates only the database section, the server the
		// whole config, and both reach openDatabase through here).
		return "", errors.New("database.postgres.dsn_ref is required when database.driver is postgres")
	}

	permMode := secrets.PermError
	if cfg.Server.Environment != "production" {
		permMode = secrets.PermWarn
	}
	resolver, err := secrets.NewResolver(secrets.Builtin(secrets.FileOptions{PermMode: permMode})...)
	if err != nil {
		return "", err
	}
	dsn, err := resolver.Resolve(ctx, ref)
	if err != nil {
		// Resolve names the field and the redacted reference, never the value, so
		// this error is safe to print on the way out.
		return "", fmt.Errorf("database.postgres.dsn_ref: %w", err)
	}
	return dsn, nil
}
