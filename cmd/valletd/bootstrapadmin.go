package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/auth"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/domain"
)

// bootstrapAdminCmd is the subcommand name that seeds a first administrator and
// mints its token.
const bootstrapAdminCmd = "bootstrap-admin"

// defaultAdminTokenTTL bounds a freshly minted administrator token's life. It is
// thirty days: long enough that re-minting is not a daily chore, short enough
// that a leaked token stops working without operator action. It is the
// note-forward tradeoff of ADR-0031 -- there is NO per-token revocation in v1,
// so disabling the administrator row is the only way to revoke early, and a
// bounded TTL is what caps the exposure of a token that leaks before then.
const defaultAdminTokenTTL = 720 * time.Hour

// runBootstrapAdmin seeds a first administrator and mints, once, a bearer token
// for it.
//
// Unlike bootstrap-owner it DOES need the administrator signing key: the whole
// point of the command is to hand back a token, and a token cannot be signed
// without the key. It runs migrations first so a brand-new deployment is a
// single command; the runner is idempotent, so doing this on an already-migrated
// database is a no-op.
func runBootstrapAdmin(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet(bootstrapAdminCmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to the configuration file (env and defaults are used when empty)")
	label := fs.String("label", "", "operator-visible label for the administrator (required)")
	ttl := fs.Duration("ttl", defaultAdminTokenTTL, "administrator token lifetime; must be > 0. "+
		"There is NO per-token revocation: disabling the administrator row revokes all its tokens, "+
		"and this TTL bounds a leaked token's exposure until then.")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *label == "" {
		return errors.New("bootstrap-admin: -label is required")
	}
	if *ttl <= 0 {
		return errors.New("bootstrap-admin: -ttl must be greater than zero")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	// Only the database section is validated here, as bootstrap-owner does: this
	// command opens the datastore and exits, binding no listener. The signing key
	// is resolved separately below, because this command genuinely needs it and a
	// full Validate would additionally demand a TLS mode it never reads.
	if err := cfg.ValidateDatabase(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	ctx := context.Background()

	// Resolve the signing key BEFORE touching the database, so a missing key fails
	// fast without seeding a row that would then be unusable. adminTokenSigningKey
	// returns "" for an unset reference in development, which is a valid state for
	// the SERVER (admin API disabled) but not here: this command cannot mint a
	// token without a key, so an empty result is a hard error that names the field.
	keyBytes, err := adminTokenSigningKey(ctx, cfg)
	if err != nil {
		return err
	}
	if keyBytes == "" {
		return errors.New("bootstrap-admin: auth.admin_token_signing_key_ref must be set to mint an administrator token")
	}
	signer, err := auth.NewAdminTokenSigner([]byte(keyBytes.Reveal()))
	if err != nil {
		// keyBytes is a secrets.Redacted and the signer never echoes key bytes, so
		// this reports only the length rule and the field to set.
		return fmt.Errorf("bootstrap-admin: admin token signer (auth.admin_token_signing_key_ref): %w", err)
	}

	db, err := openDatabase(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	if err := migrateDatabase(ctx, cfg, db); err != nil {
		return err
	}
	store, err := newStore(cfg, db)
	if err != nil {
		return err
	}

	// The service supplies a fully-populated, already-minted entity; the
	// repository persists exactly what it is given (CLAUDE.md). The id is random
	// like every other entity id (crypto/rand.Text, the same source bootstrap's
	// newID uses), and the timestamps are this command's own clock.
	now := time.Now().UTC()
	admin := &domain.Administrator{
		ID:        domain.AdministratorID(rand.Text()),
		Label:     *label,
		Status:    domain.AdminStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := store.Repos().Admins.Create(ctx, admin); err != nil {
		return fmt.Errorf("bootstrap-admin: create administrator: %w", err)
	}

	token, err := signer.Issue(admin.ID, auth.NewAdminTokenID(), now, now.Add(*ttl))
	if err != nil {
		return fmt.Errorf("bootstrap-admin: mint administrator token: %w", err)
	}

	// The token is printed exactly once, the way an access key is: it cannot be
	// recovered later, only re-minted. Only public facts accompany it -- the id
	// and the label the operator chose -- and nothing else secret is printed. The
	// token's Reveal is called only here, at the single point it is handed over.
	_, _ = fmt.Fprintf(stdout, "administrator_id=%s\nlabel=%s\nadmin_token=%s\n", admin.ID, admin.Label, token.Reveal())
	return nil
}
