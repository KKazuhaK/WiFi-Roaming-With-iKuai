package main

// runtime.go
// Builds and swaps the runtime state derived from database-backed settings.
//
// The invariant this file exists to hold: a request sees one consistent world.
// Configuration and the clients built from it are swapped together behind a
// single atomic pointer, so there is no window in which a handler reads the new
// Entra tenant and the old OIDC client — which would authenticate against the
// wrong directory and, worse, do it silently.

import (
	"context"
	"fmt"
	"log"
	"time"
)

// reloadRuntime rebuilds the runtime state from the current settings and
// installs it.
//
// Failure semantics are the important part. Before settings moved into the
// database, a bad OIDC configuration was caught by log.Fatalf at startup, which
// was correct: the only fix was editing .env and restarting anyway. Now the fix
// lives in an admin console this same process serves, so exiting would strand
// the operator. Instead:
//
//   - The state is always installed, even when incomplete. A portal with no
//     OIDC client still serves /admin, which is where the repair happens.
//   - An error is returned for the caller to log or show. At startup that is a
//     warning; from a settings save it is what tells the admin their change did
//     not take.
//   - The previous state is never left in place on a partial failure. Keeping
//     the old OIDC client alongside the new tenant ID is the one outcome that
//     produces a confusing, silent mismatch rather than an obvious error.
func (a *App) reloadRuntime(ctx context.Context) error {
	values, err := a.settings.LoadAll()
	if err != nil {
		// Nothing can be trusted if the settings table cannot be read — most
		// likely a rotated encryption key. Leave whatever is currently
		// installed alone; a running portal with stale-but-working credentials
		// beats one that just dropped them.
		return fmt.Errorf("load settings: %w", err)
	}

	var cfg Config
	applyBootstrap(&cfg, a.boot)
	applyRuntimeSettings(&cfg, values)

	problems := validateRuntimeConfig(&cfg)
	logConfigProblems(problems, "check")

	next := &runtimeState{cfg: cfg}

	// OIDC discovery is a network call to the identity provider, so it is
	// bounded and its failure is tolerated: an unreachable Entra at the moment
	// of a settings save must not leave the portal without a config.
	if cfg.TenantID != "" && cfg.ClientID != "" && cfg.ClientSecret != "" {
		dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		client, oerr := newOIDCClient(dctx, cfg)
		cancel()
		if oerr != nil {
			err = fmt.Errorf("OIDC init failed (sign-in will not work until this is fixed): %w", oerr)
			log.Printf("runtime: %v", err)
		} else {
			next.oidc = client
		}
	} else if err == nil {
		err = fmt.Errorf("Entra SSO is not configured")
	}

	if cfg.IsDuoEnabled() {
		next.duo = newDuoClient(cfg)
		next.duoUniversal = newDuoUniversalClient(cfg)
		log.Printf("Duo: enabled (Auth API + Universal Prompt), host=%s, allowed_domains=%v",
			cfg.DuoAPIHost, cfg.AllowedEmailDomains)
	} else {
		log.Printf("Duo: disabled")
	}

	if cfg.IsAdminEnabled() {
		log.Printf("admin console: enabled, admin=%v", cfg.AdminEmails)
	} else {
		log.Printf("admin console: disabled (no admin emails or group IDs configured)")
	}

	a.rtPtr.Store(next)

	for _, p := range problems {
		if p.Fatal && err == nil {
			err = fmt.Errorf("%s", p)
		}
	}
	return err
}

// oidcReady reports whether sign-in can currently work. Handlers use it to
// return a clear "not configured" error instead of dereferencing a nil client.
func (a *App) oidcReady() bool {
	rt := a.rt()
	return rt != nil && rt.oidc != nil
}
