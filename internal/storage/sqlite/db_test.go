package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

// openMemory returns a working in-memory database for a test and registers its
// cleanup.
func openMemory(t *testing.T) *sql.DB {
	t.Helper()
	db, err := Open(Options{})
	if err != nil {
		t.Fatalf("Open in-memory: %v", err)
	}
	t.Cleanup(func() {
		if cerr := db.Close(); cerr != nil {
			t.Errorf("close db: %v", cerr)
		}
	})
	return db
}

func TestOpenInMemoryPragmas(t *testing.T) {
	t.Parallel()
	db := openMemory(t)
	ctx := context.Background()

	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}

	var fk int
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil {
		t.Fatalf("query foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Errorf("foreign_keys = %d, want 1", fk)
	}

	var journal string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	// In-memory databases report "memory"; a real WAL file reports "wal".
	if journal != "memory" && journal != "wal" {
		t.Errorf("journal_mode = %q, want memory or wal", journal)
	}

	var busy int
	if err := db.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busy); err != nil {
		t.Fatalf("query busy_timeout: %v", err)
	}
	if busy != int(busyTimeout.Milliseconds()) {
		t.Errorf("busy_timeout = %d, want %d", busy, busyTimeout.Milliseconds())
	}
}

func TestOpenFilePragmas(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "vallet.db")
	db, err := Open(Options{Path: path})
	if err != nil {
		t.Fatalf("Open file: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	var journal string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
		t.Fatalf("query journal_mode: %v", err)
	}
	if journal != "wal" {
		t.Errorf("journal_mode = %q, want wal", journal)
	}

	var fk int
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil {
		t.Fatalf("query foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Errorf("foreign_keys = %d, want 1", fk)
	}
}

// TestOpenPathWithReservedChars guards the DSN against fail-open truncation: a
// path containing '?' or '#' (both structural in a DSN) must still open the
// database at the literal path with foreign_keys enforced, not silently drop
// the pragmas at the reserved byte.
func TestOpenPathWithReservedChars(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "weird?name#x.db")
	db, err := Open(Options{Path: path})
	if err != nil {
		t.Fatalf("Open reserved-char path: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	var fk int
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil {
		t.Fatalf("query foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Errorf("foreign_keys = %d, want 1", fk)
	}
	if _, err := db.ExecContext(ctx, "CREATE TABLE t (id INTEGER)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("expected database file at literal path %q: %v", path, err)
	}
}

// TestOpenInMemoryPersistsAcrossQueries guards against database/sql retiring the
// single in-memory connection, which would silently reset the database.
func TestOpenInMemoryPersistsAcrossQueries(t *testing.T) {
	t.Parallel()
	db := openMemory(t)
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, "CREATE TABLE t (id INTEGER PRIMARY KEY)"); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO t (id) VALUES (1)"); err != nil {
		t.Fatalf("insert: %v", err)
	}

	var n int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM t").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("row count = %d, want 1 (in-memory connection was likely retired)", n)
	}
}
