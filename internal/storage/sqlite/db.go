package sqlite

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	// Registers the "sqlite" database/sql driver. The driver's error type is
	// imported by name only in errors.go, which keeps engine-specific error
	// inspection isolated to a single file.
	_ "modernc.org/sqlite"
)

// driverName is the database/sql driver registered by modernc.org/sqlite.
const driverName = "sqlite"

// busyTimeout is the SQLite busy_timeout applied to every connection. A writer
// that finds the database locked retries internally for this long before
// returning SQLITE_BUSY, which smooths over brief contention between the pool's
// connections without blocking indefinitely.
const busyTimeout = 5 * time.Second

// Options configures how the database handle is opened.
type Options struct {
	// Path is the SQLite database file path. The sentinel values ":memory:"
	// and "" (also treated as in-memory) select a private in-memory database;
	// see Open for the connection-pool implications.
	Path string
}

// Open returns a database/sql handle backed by modernc.org/sqlite.
//
// The DSN enables, on every connection:
//
//   - foreign_keys(ON): foreign-key enforcement is a per-connection setting, so
//     it is carried in the DSN (the driver reapplies DSN pragmas to each new
//     connection) rather than issued once after opening, which would only
//     affect a single pooled connection.
//   - journal_mode(WAL): write-ahead logging, so readers do not block the
//     single writer. This is a database-file-level setting.
//   - busy_timeout: bounded internal retry on a locked database.
//   - _txlock=immediate: every transaction the driver begins is a BEGIN
//     IMMEDIATE, which acquires the write lock up front so concurrent writers
//     serialize deterministically instead of failing late with SQLITE_BUSY.
//
// In-memory databases live for exactly as long as their connection. To keep a
// single shared in-memory database alive, an in-memory Path pins the pool to a
// single connection that is never retired: MaxOpenConns(1) serializes access,
// while MaxIdleConns(1) and zero connection lifetimes stop database/sql from
// closing the idle connection and silently discarding the in-memory data.
func Open(opts Options) (*sql.DB, error) {
	memory := opts.Path == "" || opts.Path == ":memory:"

	db, err := sql.Open(driverName, dsn(opts.Path))
	if err != nil {
		return nil, fmt.Errorf("sqlite: open database: %w", err)
	}

	if memory {
		// A shared in-memory database exists only while its one connection is
		// open, so the pool must hold exactly one connection forever.
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		db.SetConnMaxLifetime(0)
		db.SetConnMaxIdleTime(0)
	} else {
		// _txlock=immediate serializes writers, so a small pool of readers plus
		// the writer is enough; cap it to keep file-descriptor and lock
		// pressure predictable.
		db.SetMaxOpenConns(8)
		db.SetMaxIdleConns(4)
		db.SetConnMaxIdleTime(5 * time.Minute)
	}

	return db, nil
}

// dsn builds the modernc.org/sqlite data source name for path. modernc uses
// URI-style "?_pragma=name(value)" parameters and a "_txlock" parameter, which
// differ from the mattn/go-sqlite3 "_foreign_keys=ON" style; the pragma names
// are the same as the SQL PRAGMA statements they run.
func dsn(path string) string {
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(ON)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyTimeout.Milliseconds()))
	q.Set("_txlock", "immediate")

	if path == "" || path == ":memory:" {
		// The "file::memory:" form is required so the query parameters are
		// honored; a bare ":memory:" would be read as the whole DSN and the
		// pragmas dropped.
		return "file::memory:?" + q.Encode()
	}

	// A plain filesystem path is used as-is (not percent-encoded) so paths
	// containing characters such as spaces round-trip unchanged; only the
	// query string is encoded.
	var b strings.Builder
	b.WriteString(path)
	b.WriteByte('?')
	b.WriteString(q.Encode())
	return b.String()
}
