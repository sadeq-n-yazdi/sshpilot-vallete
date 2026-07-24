package main

import (
	"context"
	"fmt"
	"time"

	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/config"
	"github.com/sadeq-n-yazdi/sshpilot-vallete/internal/secrets"
)

// accessKeyPepperField is the config field name under which the resolved access
// key pepper is keyed. It matches the string config.RequiredSecretRefs reports,
// and exists as a constant so a rename there is a compile-time concern in
// exactly one place rather than a silently absent secret here.
const accessKeyPepperField = "auth.access_key_pepper_ref"

// secretResolveTimeout bounds the whole startup resolution. A secret provider
// that hangs -- a file on a mount that stopped answering -- must not leave the
// process wedged before it has bound a listener, where no health check can see
// it and an orchestrator has nothing to restart.
const secretResolveTimeout = 30 * time.Second

// resolveSecrets resolves every secret reference this configuration requires
// and returns them keyed by config field.
//
// # Resolved once, at startup, not at the point of use
//
// internal/transport/http builds its own resolver per reference, on the stated
// grounds that it was the only production consumer and threading one down from
// main would add a parameter nothing else needed. That is now false -- this is
// the second consumer -- and the note there anticipated exactly this. Resolving
// here means a deployment whose secret provider is misconfigured fails before
// the listener binds, rather than at the first request or the first sweep pass,
// and it means no long-lived key material is re-read from disk on a schedule.
//
// # The permission posture is derived from the environment
//
// PermError in production, PermWarn elsewhere: a world-readable secret file on
// a production host must be treated as already copied, while a contributor's
// checkout should not be blocked by its own permissions. This is the same split
// the TLS resolver makes, and it lives at the config layer because the secrets
// package deliberately never imports config.
//
// # A missing entry is the empty value, and that is safe
//
// The returned map holds only the fields this configuration required. A caller
// indexing a field its feature did not enable gets the zero Redacted, which
// every consumer refuses: accesskey.New rejects a pepper below its minimum
// length rather than hashing under a short key. So the failure mode of asking
// for a secret nobody configured is a refusal to construct, not a service
// running on an empty key.
func resolveSecrets(cfg *config.Config) (map[string]secrets.Redacted, error) {
	permMode := secrets.PermError
	if cfg.Server.Environment != "production" {
		permMode = secrets.PermWarn
	}

	resolver, err := secrets.NewResolver(secrets.Builtin(secrets.FileOptions{PermMode: permMode})...)
	if err != nil {
		return nil, fmt.Errorf("secret resolver: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), secretResolveTimeout)
	defer cancel()

	list, err := cfg.ResolveRequiredSecrets(ctx, resolver)
	if err != nil {
		// Returned unwrapped in content: ResolveRequiredSecrets names the field
		// and the redacted reference and never the value, which is what makes
		// this error safe to print to stderr on the way out.
		return nil, err
	}

	out := make(map[string]secrets.Redacted, len(list))
	for _, s := range list {
		out[s.Field] = s.Value
	}
	return out, nil
}
