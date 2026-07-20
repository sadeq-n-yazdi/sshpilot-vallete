package postgres

import (
	"database/sql"
	"fmt"
	"time"

	// Registers the "pgx" database/sql driver. Using pgx through its stdlib
	// shim keeps the adapter on database/sql, so the execer abstraction and the
	// *sql.DB / *sql.Tx duality carry over from the SQLite adapter unchanged.
	_ "github.com/jackc/pgx/v5/stdlib"
)

// driverName is the database/sql driver registered by pgx/v5/stdlib.
const driverName = "pgx"

// Options configures how the database handle is opened.
type Options struct {
	// DSN is the PostgreSQL connection string, in either URL form
	// ("postgres://user:pass@host:5432/db?sslmode=require") or keyword/value
	// form ("host=... user=..."). It is passed to the driver verbatim.
	DSN string

	// MaxOpenConns caps the pool size. Zero selects defaultMaxOpenConns.
	MaxOpenConns int
}

// defaultMaxOpenConns bounds the pool by default. Unlike SQLite, Postgres
// serves concurrent writers, but every pooled connection consumes a server-side
// backend process, so the pool is capped to keep server resource use
// predictable rather than left unbounded (database/sql's default).
const defaultMaxOpenConns = 16

// connMaxIdleTime retires connections that have been idle this long. Bounding
// idle lifetime keeps the adapter from pinning server backends across quiet
// periods and lets a connection re-resolve DNS after a failover.
const connMaxIdleTime = 5 * time.Minute

// connMaxLifetime bounds the total age of a pooled connection so a long-lived
// process eventually rotates onto new backends after a server restart or a
// rolling upgrade behind a proxy.
const connMaxLifetime = 30 * time.Minute

// Open returns a database/sql handle backed by pgx in stdlib mode.
//
// sql.Open does not contact the server, so a bad host or bad credentials
// surface on first use rather than here; only a malformed DSN fails eagerly.
// The caller owns the returned handle and is responsible for closing it.
func Open(opts Options) (*sql.DB, error) {
	if opts.DSN == "" {
		return nil, fmt.Errorf("%s: open database: empty DSN", errPrefix)
	}

	db, err := sql.Open(driverName, opts.DSN)
	if err != nil {
		// The DSN can embed a password, so the driver error is deliberately not
		// wrapped here: a parse failure quotes the offending connection string.
		return nil, fmt.Errorf("%s: open database: invalid DSN", errPrefix)
	}

	maxOpen := opts.MaxOpenConns
	if maxOpen <= 0 {
		maxOpen = defaultMaxOpenConns
	}
	db.SetMaxOpenConns(maxOpen)
	// Keeping half the pool warm avoids a connect round trip (TLS handshake plus
	// backend fork) on every burst without holding the full pool open.
	db.SetMaxIdleConns(maxOpen / 2)
	db.SetConnMaxIdleTime(connMaxIdleTime)
	db.SetConnMaxLifetime(connMaxLifetime)

	return db, nil
}
