package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/migrate"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/nameguard"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/schema"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/service/bootstrap"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/storage/sqlite"
)

// bootstrapOwnerCmd is the subcommand name that seeds a first owner.
const bootstrapOwnerCmd = "bootstrap-owner"

// maxKeyFileBytes bounds a key file read. keys.Parse rejects anything over its
// own line limit anyway, but the file is read before parsing, so the read
// itself is bounded rather than trusting an operator-supplied path to be small.
const maxKeyFileBytes = 1 << 16

// runBootstrapOwner seeds an owner, its handle, and its default key set, and
// optionally a first public key.
//
// It runs migrations first so that a brand-new deployment is a single command
// rather than a two-step dance an operator can get half-right. The migration
// runner is idempotent, so doing this on an already-migrated database is a
// no-op.
func runBootstrapOwner(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet(bootstrapOwnerCmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to the configuration file (env and defaults are used when empty)")
	handle := fs.String("handle", "", "the public handle to claim (required)")
	// The default is EMPTY, not bootstrap.DefaultSetName. An explicitly
	// supplied set name is a user-chosen identifier and is blocklist-checked;
	// the system's own fallback name is not. Defaulting the flag to the literal
	// would have made every bootstrap submit "default" as a user choice -- and
	// "default" is itself a curated routing term, so the command would refuse
	// to run at all.
	setName := fs.String("set", "", "name of the default key set (empty uses "+bootstrap.DefaultSetName+")")
	deviceName := fs.String("device", bootstrap.DefaultDeviceName, "label for the device holding the seeded key")
	keyFile := fs.String("key-file", "", `path to a file holding one SSH public key line, or "-" for stdin`)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *handle == "" {
		return errors.New("bootstrap-owner: -handle is required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	// Only the database section is validated: this command opens the datastore
	// and exits, binding no listener and issuing no token, so demanding a TLS
	// mode and a signing key here would be a gate on settings it never reads.
	if err := cfg.ValidateDatabase(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	keyLine, err := readKeyFile(*keyFile)
	if err != nil {
		return err
	}

	db, err := openDatabase(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if err := applyMigrations(ctx, sqlite.NewMigrateDB(db), migrate.EngineSQLite); err != nil {
		return err
	}

	// Build the guard BEFORE opening the seed. If the curated lists cannot be
	// compiled the command must stop rather than seed an unchecked handle: the
	// handle claimed here is global and permanent, so proceeding without
	// enforcement is the one outcome no later fix undoes.
	guard, err := nameguard.Default()
	if err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}

	res, err := bootstrap.Seed(ctx, sqlite.NewStore(db), bootstrap.Params{
		Handle:     *handle,
		SetName:    *setName,
		DeviceName: *deviceName,
		KeyLine:    keyLine,
		Now:        time.Now().UTC(),
		Guard:      guard,
	})
	if err != nil {
		return err
	}

	// Only public facts are printed. The owner ID is an opaque capability-ish
	// identifier, so it goes to stdout for the operator who just created it,
	// but no key material is echoed — the fingerprint of a public key is the
	// safe way to confirm which key was stored.
	_, _ = fmt.Fprintf(stdout, "owner_id=%s\nhandle=%s\nset=%s\n", res.OwnerID, *handle, res.SetName)
	if res.Fingerprint != "" {
		_, _ = fmt.Fprintf(stdout, "key_fingerprint=%s\n", res.Fingerprint)
	}
	return nil
}

// readKeyFile reads the optional key line. "-" reads stdin so a key can be
// piped in without ever being written to disk, and an empty path means no key.
func readKeyFile(path string) ([]byte, error) {
	switch path {
	case "":
		return nil, nil
	case "-":
		return readLimited(os.Stdin)
	default:
		f, err := os.Open(path) //nolint:gosec // the path is an operator-supplied argument to a local admin command.
		if err != nil {
			return nil, fmt.Errorf("open key file: %w", err)
		}
		defer func() { _ = f.Close() }()
		return readLimited(f)
	}
}

// readLimited reads at most maxKeyFileBytes and fails if there is more, rather
// than silently truncating: a truncated key would either fail to parse or, far
// worse, parse as something the operator did not intend to publish.
func readLimited(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxKeyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	if len(b) > maxKeyFileBytes {
		return nil, fmt.Errorf("key input exceeds %d bytes", maxKeyFileBytes)
	}
	return b, nil
}

// applyMigrations brings the database schema up to date using the dialect for
// engine. It is the single runner-wiring site shared by the bootstrap
// subcommand and normal server startup, so the two can never drift in how the
// schema is brought up.
func applyMigrations(ctx context.Context, db migrate.DB, engine migrate.Engine) error {
	reg, err := schema.Registry()
	if err != nil {
		return fmt.Errorf("build migration registry: %w", err)
	}
	runner, err := migrate.NewRunner(db, engine, reg)
	if err != nil {
		return fmt.Errorf("build migration runner: %w", err)
	}
	if _, err := runner.Up(ctx); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}
