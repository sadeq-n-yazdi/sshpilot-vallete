package migrate

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// This file provides an in-memory implementation of the migrate ports for
// tests: no driver, no build tags. It models a transactional key/value store
// for the ledger table plus a set of "existing" tables for catalog
// preconditions, and supports failure injection.

// ledgerRow holds a ledger row exactly as columns of text, mirroring what a
// real driver would return.
type ledgerRow struct {
	id, name, checksum, appliedAt, engine string
}

// execEntry records one Exec call for placeholder/argument assertions,
// regardless of whether the enclosing transaction later commits.
type execEntry struct {
	query string
	args  []any
}

// fakeDB is an in-memory DB. It is used from a single goroutine per test.
type fakeDB struct {
	engine Engine

	rows   map[string]ledgerRow
	tables map[string]bool

	execLog   []execEntry
	beginErr  error
	commitErr error
	rowsErr   error
	// execErr, if set, is consulted on every Exec (db- and tx-level). A
	// non-nil return fails that Exec and the statement is not applied.
	execErr func(query string, args []any) error
	// queryErr, if set, is consulted on every Query. A non-nil return fails
	// the query.
	queryErr func(query string) error
}

func newFakeDB(engine Engine) *fakeDB {
	return &fakeDB{
		engine: engine,
		rows:   map[string]ledgerRow{},
		tables: map[string]bool{},
	}
}

// seedLedger inserts a ledger row directly, bypassing SQL, for verify
// scenarios.
func (db *fakeDB) seedLedger(r ledgerRow) { db.rows[r.id] = r }

// seedTable marks a table as existing for catalog preconditions.
func (db *fakeDB) seedTable(name string) { db.tables[name] = true }

// appliedIDs returns the ledger IDs currently stored, sorted.
func (db *fakeDB) appliedIDs() []string {
	ids := make([]string, 0, len(db.rows))
	for id := range db.rows {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func str(v any) string {
	s, ok := v.(string)
	if !ok {
		panic(fmt.Sprintf("fake: expected string arg, got %T", v))
	}
	return s
}

// applyExec mutates rows/tables according to the statement. Unrecognized
// statements are accepted as no-ops.
func applyExec(rows map[string]ledgerRow, tables map[string]bool, query string, args []any) {
	q := strings.TrimSpace(query)
	upper := strings.ToUpper(q)
	switch {
	case strings.HasPrefix(upper, "INSERT INTO SCHEMA_MIGRATIONS"):
		rows[str(args[0])] = ledgerRow{str(args[0]), str(args[1]), str(args[2]), str(args[3]), str(args[4])}
	case strings.HasPrefix(upper, "DELETE FROM SCHEMA_MIGRATIONS"):
		delete(rows, str(args[0]))
	case strings.Contains(upper, "SCHEMA_MIGRATIONS"):
		// CREATE TABLE IF NOT EXISTS schema_migrations: no-op.
	case strings.HasPrefix(upper, "CREATE TABLE"):
		if name := tableName(q, upper, "CREATE TABLE"); name != "" {
			tables[name] = true
		}
	case strings.HasPrefix(upper, "DROP TABLE"):
		if name := tableName(q, upper, "DROP TABLE"); name != "" {
			delete(tables, name)
		}
	}
}

// tableName extracts the target table name from a CREATE/DROP TABLE statement,
// skipping IF [NOT] EXISTS and stopping at "(" or whitespace.
func tableName(q, upper, verb string) string {
	rest := strings.TrimSpace(q[len(verb):])
	restUpper := strings.ToUpper(rest)
	for _, kw := range []string{"IF NOT EXISTS ", "IF EXISTS "} {
		if strings.HasPrefix(restUpper, kw) {
			rest = strings.TrimSpace(rest[len(kw):])
			break
		}
	}
	rest = strings.TrimLeft(rest, " \t")
	if i := strings.IndexAny(rest, " \t("); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// runCatalogQuery answers a precondition catalog query. It recognizes the
// SQLite and Postgres catalog forms and returns a single integer column: 1 if
// the named table exists, else 0.
func (db *fakeDB) runCatalogQuery(tables map[string]bool, query string, args []any) (Rows, bool) {
	upper := strings.ToUpper(query)
	if !strings.Contains(upper, "SQLITE_MASTER") && !strings.Contains(upper, "TO_REGCLASS") {
		return nil, false
	}
	if len(args) != 1 {
		return &fakeRows{err: errors.New("catalog query must take exactly one argument")}, true
	}
	present := 0
	if tables[str(args[0])] {
		present = 1
	}
	return &fakeRows{data: [][]any{{present}}}, true
}

// runLedgerQuery answers the ledger select, returning rows sorted by ID.
func runLedgerQuery(rows map[string]ledgerRow) Rows {
	ids := make([]string, 0, len(rows))
	for id := range rows {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	data := make([][]any, 0, len(ids))
	for _, id := range ids {
		r := rows[id]
		data = append(data, []any{r.id, r.name, r.checksum, r.appliedAt, r.engine})
	}
	return &fakeRows{data: data}
}

// query resolves a read against the given working set.
func (db *fakeDB) query(rows map[string]ledgerRow, tables map[string]bool, q string, args []any) (Rows, error) {
	if db.queryErr != nil {
		if err := db.queryErr(q); err != nil {
			return nil, err
		}
	}
	if r, ok := db.runCatalogQuery(tables, q, args); ok {
		return r, nil
	}
	if strings.Contains(strings.ToUpper(q), "FROM SCHEMA_MIGRATIONS") {
		if db.rowsErr != nil {
			return &fakeRows{err: db.rowsErr}, nil
		}
		return runLedgerQuery(rows), nil
	}
	return &fakeRows{}, nil
}

// exec runs a statement against the given working set, honoring injection.
func (db *fakeDB) exec(rows map[string]ledgerRow, tables map[string]bool, q string, args []any) error {
	db.execLog = append(db.execLog, execEntry{query: q, args: args})
	if db.execErr != nil {
		if err := db.execErr(q, args); err != nil {
			return err
		}
	}
	applyExec(rows, tables, q, args)
	return nil
}

// --- DB-level (autocommit) operations ---

func (db *fakeDB) Exec(_ context.Context, query string, args ...any) error {
	return db.exec(db.rows, db.tables, query, args)
}

func (db *fakeDB) Query(_ context.Context, query string, args ...any) (Rows, error) {
	return db.query(db.rows, db.tables, query, args)
}

func (db *fakeDB) Begin(_ context.Context) (Tx, error) {
	if db.beginErr != nil {
		return nil, db.beginErr
	}
	return &fakeTx{
		db:     db,
		rows:   cloneRows(db.rows),
		tables: cloneTables(db.tables),
	}, nil
}

// --- Transaction ---

type fakeTx struct {
	db        *fakeDB
	rows      map[string]ledgerRow
	tables    map[string]bool
	committed bool
	done      bool
}

func (tx *fakeTx) Exec(_ context.Context, query string, args ...any) error {
	return tx.db.exec(tx.rows, tx.tables, query, args)
}

func (tx *fakeTx) Query(_ context.Context, query string, args ...any) (Rows, error) {
	return tx.db.query(tx.rows, tx.tables, query, args)
}

func (tx *fakeTx) Commit() error {
	if tx.db.commitErr != nil {
		// Commit failed: changes are not made durable.
		tx.done = true
		return tx.db.commitErr
	}
	tx.db.rows = tx.rows
	tx.db.tables = tx.tables
	tx.committed = true
	tx.done = true
	return nil
}

func (tx *fakeTx) Rollback() error {
	// A Rollback after a successful Commit is a no-op, so callers may defer it.
	if tx.committed {
		return nil
	}
	tx.done = true
	return nil
}

func cloneRows(in map[string]ledgerRow) map[string]ledgerRow {
	out := make(map[string]ledgerRow, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneTables(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// --- Rows ---

type fakeRows struct {
	data   [][]any
	idx    int
	closed bool
	err    error
}

func (r *fakeRows) Next() bool {
	if r.err != nil || r.idx >= len(r.data) {
		return false
	}
	r.idx++
	return true
}

func (r *fakeRows) Scan(dest ...any) error {
	if r.idx == 0 || r.idx > len(r.data) {
		return errors.New("fake: Scan called out of range")
	}
	row := r.data[r.idx-1]
	if len(dest) != len(row) {
		return fmt.Errorf("fake: Scan expected %d columns, got %d", len(row), len(dest))
	}
	for i, d := range dest {
		switch p := d.(type) {
		case *string:
			s, ok := row[i].(string)
			if !ok {
				return fmt.Errorf("fake: column %d is not a string", i)
			}
			*p = s
		case *int:
			n, ok := row[i].(int)
			if !ok {
				return fmt.Errorf("fake: column %d is not an int", i)
			}
			*p = n
		default:
			return fmt.Errorf("fake: unsupported Scan destination %T", d)
		}
	}
	return nil
}

func (r *fakeRows) Err() error   { return r.err }
func (r *fakeRows) Close() error { r.closed = true; return nil }
