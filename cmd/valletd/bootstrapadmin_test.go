package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/audit"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/listadmin"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
	httpserver "github.com/sadeq-n-yazdi/sshpilot-vallete/internal/transport/http"
)

// bootstrapAdminKey is the admin signing key these tests provision the command
// with. A constant is correct: what is under test is that the SAME key verifies
// the minted token, not the secrecy of this value. It is 36 bytes.
const bootstrapAdminKey = "0123456789abcdef0123456789abcdef0123"

// runBootstrapAdminAt drives the real subcommand against the SQLite file at
// dbPath, with the admin signing key configured, and returns its stdout.
func runBootstrapAdminAt(t *testing.T, dbPath string, args ...string) (string, error) {
	t.Helper()
	t.Setenv("VALLET_SERVER_ENVIRONMENT", "development")
	t.Setenv("VALLET_DATABASE_SQLITE_PATH", dbPath)
	t.Setenv("VALLET_AUTH_ADMIN_TOKEN_SIGNING_KEY_REF", "env:VALLET_TEST_BOOTSTRAP_ADMIN_KEY")
	t.Setenv("VALLET_TEST_BOOTSTRAP_ADMIN_KEY", bootstrapAdminKey)
	var stdout, stderr bytes.Buffer
	err := runBootstrapAdmin(args, &stdout, &stderr)
	return stdout.String(), err
}

// fieldFrom returns the value of a "key=value" line printed by the command.
func fieldFrom(t *testing.T, out, key string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return v
		}
	}
	t.Fatalf("output %q has no %s= line", out, key)
	return ""
}

func TestBootstrapAdminCreatesAndPrintsToken(t *testing.T) {
	out, err := runBootstrapAdminAt(t, filepath.Join(t.TempDir(), "vallet.db"), "-label", "ops")
	if err != nil {
		t.Fatalf("bootstrap-admin -label ops = %v, want success", err)
	}
	if !strings.Contains(out, "label=ops\n") {
		t.Errorf("output %q does not report label=ops", out)
	}
	if id := fieldFrom(t, out, "administrator_id"); id == "" {
		t.Error("no administrator_id printed")
	}
	if tok := fieldFrom(t, out, "admin_token"); !strings.HasPrefix(tok, "sadm_") {
		t.Errorf("admin_token %q lacks the sadm_ prefix", tok)
	}
}

func TestBootstrapAdminRequiresLabel(t *testing.T) {
	out, err := runBootstrapAdminAt(t, filepath.Join(t.TempDir(), "vallet.db"))
	if err == nil {
		t.Fatal("bootstrap-admin with no -label succeeded, want refusal")
	}
	if out != "" {
		t.Errorf("refused bootstrap printed %q, want nothing", out)
	}
}

func TestBootstrapAdminRefusesNonPositiveTTL(t *testing.T) {
	for _, ttl := range []string{"0s", "-1h"} {
		out, err := runBootstrapAdminAt(t, filepath.Join(t.TempDir(), "vallet.db"), "-label", "ops", "-ttl", ttl)
		if err == nil {
			t.Errorf("bootstrap-admin -ttl %s succeeded, want refusal", ttl)
		}
		if out != "" {
			t.Errorf("-ttl %s: refused bootstrap printed %q, want nothing", ttl, out)
		}
	}
}

// TestBootstrapAdminRequiresSigningKey proves the command refuses to mint a
// token when no admin signing key is configured -- unlike bootstrap-owner, it
// genuinely needs the key, and an empty result is a hard error naming the field.
func TestBootstrapAdminRequiresSigningKey(t *testing.T) {
	t.Setenv("VALLET_SERVER_ENVIRONMENT", "development")
	t.Setenv("VALLET_DATABASE_SQLITE_PATH", filepath.Join(t.TempDir(), "vallet.db"))
	// No admin signing key reference set.
	var stdout, stderr bytes.Buffer
	err := runBootstrapAdmin([]string{"-label", "ops"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("bootstrap-admin with no signing key succeeded, want refusal")
	}
	if !strings.Contains(err.Error(), "auth.admin_token_signing_key_ref") {
		t.Errorf("error does not name the config field an operator must set: %v", err)
	}
	if stdout.String() != "" {
		t.Errorf("refused bootstrap printed %q, want nothing", stdout.String())
	}
}

// TestBootstrapAdminTokenAuthenticates is the end-to-end proof that provisioning
// and authentication close: the token bootstrap-admin printed, fed to the SAME
// verifier the server mounts, resolves to the created administrator, and
// listadmin -- the real authority check -- authorizes an edit on it.
//
// This is the whole point of the command. A token that provisioned an admin row
// but could not then authenticate would be a dead credential; asserting the
// round trip is what proves the two halves of ADR-0031 fit together.
func TestBootstrapAdminTokenAuthenticates(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "vallet.db")
	out, err := runBootstrapAdminAt(t, dbPath, "-label", "ops")
	if err != nil {
		t.Fatalf("bootstrap-admin: %v", err)
	}
	wantID := domain.AdministratorID(fieldFrom(t, out, "administrator_id"))
	token := fieldFrom(t, out, "admin_token")

	// The verifier the server would mount, built from the SAME signing key.
	signer, err := auth.NewAdminTokenSigner([]byte(bootstrapAdminKey))
	if err != nil {
		t.Fatalf("NewAdminTokenSigner: %v", err)
	}
	id := httpserver.NewSignedAdminIdentifier(signer, time.Now)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/reserved/allowlist", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	gotID := id.AdministratorID(req)
	if gotID != wantID {
		t.Fatalf("identifier resolved %q, want the created administrator %q", gotID, wantID)
	}

	// The real authority check: listadmin must authorize an edit attributed to
	// the resolved id, which means Admins.Get found the row and it is Active.
	ctx := context.Background()
	db, err := sqlite.Open(sqlite.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := sqlite.NewStore(db)

	cfg := config.Default()
	policy, err := newNamePolicy(ctx, &cfg, store.Repos().ListOverrides)
	if err != nil {
		t.Fatalf("newNamePolicy: %v", err)
	}
	emitter, err := audit.NewEmitter(store.AuditAppender())
	if err != nil {
		t.Fatalf("audit emitter: %v", err)
	}
	svc, err := listadmin.New(listadmin.Params{
		Admins:    store.Repos().Admins,
		Overrides: store.Repos().ListOverrides,
		Emitter:   emitter,
		Matcher:   policy.Matcher,
	})
	if err != nil {
		t.Fatalf("listadmin.New: %v", err)
	}
	if err := svc.AddAllowlistEntry(ctx, gotID, "widget"); err != nil {
		t.Fatalf("listadmin refused the provisioned administrator: %v", err)
	}
}
