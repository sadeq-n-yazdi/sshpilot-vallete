package migrate

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

func TestPreconditionQueriesAreParameterized(t *testing.T) {
	// The table name must never be interpolated into the SQL; it travels as a
	// bind argument. Verify the query text carries a placeholder and no literal
	// name, for both engines.
	for _, engine := range []Engine{EngineSQLite, EnginePostgres} {
		q := tableExistsQuery(engine)
		if strings.Contains(q, "widgets") {
			t.Errorf("%s query interpolates a name: %q", engine, q)
		}
		if engine == EnginePostgres && !strings.Contains(q, "$1") {
			t.Errorf("postgres catalog query missing $1: %q", q)
		}
		if engine == EngineSQLite && !strings.Contains(q, "?") {
			t.Errorf("sqlite catalog query missing ?: %q", q)
		}
	}
}

func TestTableExistsAndAbsent(t *testing.T) {
	ctx := context.Background()
	for _, engine := range []Engine{EngineSQLite, EnginePostgres} {
		t.Run(string(engine), func(t *testing.T) {
			db := newFakeDB(engine)
			db.seedTable("widgets")

			if err := TableExists("widgets").Check(ctx, db, engine); err != nil {
				t.Errorf("TableExists(widgets) should pass: %v", err)
			}
			if err := TableExists("missing").Check(ctx, db, engine); !errors.Is(err, domain.ErrConflict) {
				t.Errorf("TableExists(missing) should fail with conflict: %v", err)
			}
			if err := TableAbsent("widgets").Check(ctx, db, engine); !errors.Is(err, domain.ErrConflict) {
				t.Errorf("TableAbsent(widgets) should fail with conflict: %v", err)
			}
			if err := TableAbsent("missing").Check(ctx, db, engine); err != nil {
				t.Errorf("TableAbsent(missing) should pass: %v", err)
			}
		})
	}
}

func TestPreconditionDescriptions(t *testing.T) {
	if got := TableExists("t").Description; got == "" {
		t.Error("TableExists description must be non-empty")
	}
	if got := TableAbsent("t").Description; got == "" {
		t.Error("TableAbsent description must be non-empty")
	}
}

func TestTablePresentQueryError(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB(EngineSQLite)
	sentinel := errors.New("catalog unavailable")
	db.queryErr = func(string) error { return sentinel }
	if _, err := tablePresent(ctx, db, EngineSQLite, "widgets"); !errors.Is(err, sentinel) {
		t.Fatalf("expected propagated query error, got %v", err)
	}
}

// TestPreconditionIntegratesWithUp proves a precondition runs inside the
// migration transaction and can block application.
func TestPreconditionIntegratesWithUp(t *testing.T) {
	ctx := context.Background()
	m := mig("0001", "widgets")
	m.Preconditions = []Precondition{TableAbsent("widgets")}
	db := newFakeDB(EngineSQLite)
	db.seedTable("widgets") // precondition should fail
	r := mustRunner(t, db, EngineSQLite, mustRegistry(t, m))
	if _, err := r.Up(ctx); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("expected ErrPreconditionFailed, got %v", err)
	}
	if ids := db.appliedIDs(); len(ids) != 0 {
		t.Errorf("ledger must be empty after precondition block: %v", ids)
	}
}
