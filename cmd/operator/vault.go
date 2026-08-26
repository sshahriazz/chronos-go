package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/chronos/chronos-go/internal/adapter/openbao"
	"github.com/chronos/chronos-go/internal/adapter/piivault"
	"github.com/chronos/chronos-go/internal/operator/app"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// vaultReader is the operator plane's only path to a person's data.
//
// # It is deliberately narrower than the vault it wraps
//
// piivault.Vault can Put, Forget, Erase and read a whole Profile. This exposes
// Resolve, for one subject and a named field list, and nothing else. The
// narrowing is the point: operator.md §4 permits READING on justified access
// and says nothing about writing, and an adapter that could write would make
// "the operator plane cannot erase somebody" a fact about the call sites rather
// than about the type.
//
// The database grant says the same thing a second time — chronos_operator holds
// SELECT on the vault tables and nothing else (migration 00038) — which is what
// makes this hold even if somebody widens the interface.
type vaultReader struct {
	vault *piivault.Vault
	log   *slog.Logger
}

var _ app.VaultReader = (*vaultReader)(nil)

func newVault(tx db.SystemTX, cfg *config.Config, log *slog.Logger) (*vaultReader, error) {
	client, err := openbao.Dial(cfg.OpenBao.Address, cfg.OpenBao.Token.Expose())
	if err != nil {
		// FATAL, like everything else in this binary's startup. An operator
		// plane that came up without the vault would serve the directory and
		// fail every personal-data read — which reads as "this customer's
		// details are missing" rather than as a misconfiguration, and that is
		// the diagnosis that costs a day.
		return nil, fmt.Errorf("reaching the key store: %w", err)
	}

	ring := openbao.NewKeyRing(client, cfg.OpenBao.KEKName)

	// No key cache, for the reason cmd/api gives and one more.
	//
	// cmd/api resolves at most one subject per request, so a cache buys nothing
	// and widens the window in which an erased subject's key is still usable
	// (ADR-041). Here the argument is stronger: an operator resolves a subject
	// on an explicit, justified, audited access, and caching the key would mean
	// a SECOND read of the same subject could be served without touching the
	// key store at all — which is fine for correctness and wrong for a plane
	// whose whole design is that every access leaves a trace.
	v := piivault.New(tx, ring)

	return &vaultReader{vault: v, log: log}, nil
}

// Resolve returns the requested fields, omitting the ones the vault does not
// hold.
//
// # An absent field is ABSENT, not empty
//
// The two are different answers and only one of them is honest. A field the
// vault has never held and a field holding an empty string would be
// indistinguishable if both came back as "", and the operator reading the
// result would have no way to tell "we do not have their phone number" from "we
// have it and it is blank".
//
// An ERASED subject resolves to nothing at all, and that is the correct answer
// rather than an error: their key is destroyed, so there is no data to return,
// and the audit entry for the attempt is already written.
func (v *vaultReader) Resolve(ctx context.Context, subjectID string, fields []string) (map[string]string, error) {
	id := pii.SubjectID(subjectID)

	out := make(map[string]string, len(fields))
	for _, name := range fields {
		field := pii.Field(name)
		if !field.Valid() {
			// Refused rather than skipped. A field name the vault does not know
			// is a caller mistake, and silently dropping it would return a
			// partial answer that looks complete — so an operator would
			// conclude we hold nothing under a name they had simply mistyped.
			return nil, fmt.Errorf("operator: %q is not a vault field: %w", name, pii.ErrInvalidField)
		}

		value, err := v.vault.Get(ctx, id, field)
		switch {
		case errors.Is(err, pii.ErrNoValue), errors.Is(err, pii.ErrNoSubject):
			continue
		case errors.Is(err, pii.ErrErased):
			// An erased subject resolves to nothing at all, and the loop stops:
			// every remaining field would give the same answer, and the vault
			// round trips would be work done to learn what is already known.
			return map[string]string{}, nil
		case err != nil:
			return nil, fmt.Errorf("operator: resolving %q: %w", name, err)
		}
		out[name] = value
	}
	return out, nil
}
