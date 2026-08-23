package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/chronos/chronos-go/internal/adapter/openbao"
	"github.com/chronos/chronos-go/internal/platform/config"
)

// resolveSecrets fills the config's secret fields from OpenBao when custody is
// configured, and is a no-op when it is not.
//
// # Why the failure is fatal
//
// Every other optional dependency in this binary degrades: no Stripe key means
// no billing service, and the process still serves everything else. Custody is
// different, and the difference is the whole reason it exists. Naming
// OPENBAO_STRIPE_PATH is a statement that the environment is NOT to be trusted
// for these values — so falling back to it on failure would use exactly the
// source the operator just said not to, and would do it silently, at the moment
// something is wrong.
//
// Starting without them would be no better. The Stripe key's absence is not
// visible until a customer tries to pay, and the webhook secret's absence is not
// visible until Stripe posts an event nobody can verify — which is to say, at
// the two moments least amenable to discovery.
//
// So this returns an error and `run` stops. A deployment that cannot read its
// own secrets has not started; it has failed, and should say so.
func resolveSecrets(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	if cfg.OpenBao.StripePath == "" {
		// Not configured. Local development keeps its .env, which is what .env is
		// for. Logged at INFO rather than passed over in silence, because "are
		// the production secrets actually coming from custody" is a question
		// somebody asks during an incident and should be able to answer from the
		// startup log.
		log.Info("secret custody is not configured; secrets come from the environment",
			"env", cfg.Env)
		return nil
	}

	client, err := openbao.Dial(cfg.OpenBao.Address, cfg.OpenBao.Token.Expose())
	if err != nil {
		return fmt.Errorf("secret custody: %w", err)
	}
	secrets, err := openbao.NewSecrets(client, cfg.OpenBao.KVMount)
	if err != nil {
		return fmt.Errorf("secret custody: %w", err)
	}
	if err := cfg.ResolveSecrets(ctx, secrets); err != nil {
		return err
	}

	// The PATH, never a value or any part of one. A log line that carried even a
	// prefix of an API key would put it in the one place secrets end up being
	// read by people who were not meant to see them.
	log.Info("secrets loaded from custody",
		"mount", cfg.OpenBao.KVMount, "path", cfg.OpenBao.StripePath)
	return nil
}
