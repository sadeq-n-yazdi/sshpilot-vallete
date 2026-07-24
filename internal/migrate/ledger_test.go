package migrate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

func TestLedgerRoundTrip(t *testing.T) {
	for _, engine := range []Engine{EngineSQLite, EnginePostgres} {
		t.Run(string(engine), func(t *testing.T) {
			ctx := context.Background()
			db := newFakeDB(engine)
			if err := ensureLedgerTable(ctx, db); err != nil {
				t.Fatalf("ensure: %v", err)
			}

			applied := time.Date(2026, 7, 19, 12, 30, 0, 0, time.UTC)
			l1 := Ledger{ID: "0001", Name: "one", Checksum: "c1", AppliedAt: applied, Engine: engine}
			l2 := Ledger{ID: "0002", Name: "two", Checksum: "c2", AppliedAt: applied.Add(time.Minute), Engine: engine}
			// Insert out of order to prove loadLedger sorts.
			if err := insertLedger(ctx, db, l2); err != nil {
				t.Fatalf("insert l2: %v", err)
			}
			if err := insertLedger(ctx, db, l1); err != nil {
				t.Fatalf("insert l1: %v", err)
			}

			got, err := loadLedger(ctx, db)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if len(got) != 2 || got[0].ID != "0001" || got[1].ID != "0002" {
				t.Fatalf("load returned %+v, want 0001 then 0002", got)
			}
			if !got[0].AppliedAt.Equal(applied) {
				t.Errorf("applied_at round-trip = %v, want %v", got[0].AppliedAt, applied)
			}
			if got[0].Engine != engine {
				t.Errorf("engine = %q, want %q", got[0].Engine, engine)
			}

			if err := deleteLedger(ctx, db, engine, "0001"); err != nil {
				t.Fatalf("delete: %v", err)
			}
			if ids := db.appliedIDs(); len(ids) != 1 || ids[0] != "0002" {
				t.Fatalf("after delete ids = %v, want [0002]", ids)
			}
		})
	}
}

func TestLedgerSQLPlaceholdersPerEngine(t *testing.T) {
	if !strings.Contains(insertLedgerSQL(EnginePostgres), "$1") {
		t.Error("postgres insert must use $N placeholders")
	}
	if !strings.Contains(insertLedgerSQL(EngineSQLite), "?") {
		t.Error("sqlite insert must use ? placeholders")
	}
	if !strings.Contains(deleteLedgerSQL(EnginePostgres), "$1") {
		t.Error("postgres delete must use $N placeholders")
	}
	if !strings.Contains(deleteLedgerSQL(EngineSQLite), "?") {
		t.Error("sqlite delete must use ? placeholders")
	}
}

func TestInsertLedgerUsesEngineSQL(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB(EnginePostgres)
	l := Ledger{ID: "0001", Name: "one", Checksum: "c1", AppliedAt: time.Now(), Engine: EnginePostgres}
	if err := insertLedger(ctx, db, l); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range db.execLog {
		if strings.Contains(e.query, "INSERT INTO schema_migrations") {
			found = true
			if !strings.Contains(e.query, "$1") {
				t.Errorf("insert used non-postgres placeholders: %q", e.query)
			}
		}
	}
	if !found {
		t.Fatal("insert statement not recorded")
	}
}

func TestLoadLedgerInvalidTimestamp(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB(EngineSQLite)
	db.seedLedger(ledgerRow{id: "0001", name: "one", checksum: "c1", appliedAt: "not-a-timestamp", engine: "sqlite"})
	_, err := loadLedger(ctx, db)
	if err == nil {
		t.Fatal("expected error for invalid timestamp")
	}
	if !errors.Is(err, domain.ErrConflict) {
		t.Errorf("error %v does not wrap domain.ErrConflict", err)
	}
	if strings.Contains(err.Error(), "not-a-timestamp") {
		t.Errorf("error leaks the bad timestamp value: %q", err)
	}
}

func TestLoadLedgerQueryError(t *testing.T) {
	ctx := context.Background()
	db := newFakeDB(EngineSQLite)
	sentinel := errors.New("connection reset")
	db.queryErr = func(string) error { return sentinel }
	if _, err := loadLedger(ctx, db); !errors.Is(err, sentinel) {
		t.Fatalf("expected propagated query error, got %v", err)
	}
}
