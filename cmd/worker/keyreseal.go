package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/argon2id"
	identitypg "github.com/chronos/chronos-go/internal/modules/identity/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/totpseal"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/config"
)

// resealAdapter presents the identity use case as the durable-work port.
//
// Two counter structs rather than one shared type, for the reason sweepAdapter
// and retentionAdapter exist: the alternative is internal/adapter/temporal
// importing an identity use case, and an adapter that knows a module is an
// adapter that will eventually make a decision for it. Here the decision it must
// never make is which rows are safe to leave behind on a retired key. The
// conversion is mechanical and total.
type resealAdapter struct{ reseal *app.KeyReseal }

var _ temporaladapter.CredentialResealer = resealAdapter{}

func (r resealAdapter) Kinds() []string { return r.reseal.Kinds() }

func (r resealAdapter) ResealOnce(
	ctx context.Context, kind, after string, limit int,
) (temporaladapter.ResealBatch, error) {
	res, err := r.reseal.ResealOnce(ctx, kind, after, limit)
	return temporaladapter.ResealBatch{
		Version:    res.Version,
		Scanned:    res.Scanned,
		Resealed:   res.Resealed,
		Skipped:    res.Skipped,
		Unopenable: res.Unopenable,
		Failed:     res.Failed,
		Cursor:     res.Cursor,
		More:       res.More,
		Remaining:  res.Remaining,
		Counted:    res.Counted,
	}, err
}

// newCredentialReseal builds the re-sealing job, or reports why it could not be.
//
// # Why this binary loads key material at all
//
// Nothing else in cmd/worker holds a pepper or a TOTP sealing key: a reactor
// sends notifications and a projector writes rows, and neither opens a
// credential. This job is the exception by necessity — re-sealing is an AEAD open
// under one key followed by an AEAD seal under another, so the process doing it
// must hold both. That is a deliberate widening of this binary's blast radius and
// it is worth naming: the worker now holds the same two secrets cmd/api holds.
// The alternative is worse in every direction. Doing it in cmd/api would put a
// bulk rewrite of the credential table on the request path's process; doing it
// with a transit round trip per row is impossible, because the KeyRing port has
// no way to carry additional data and the AAD binding is what stops a verifier
// being replayed onto another account.
//
// # Why the CURRENT key alone is not enough
//
// The keys are read from configuration, which today names exactly one version per
// key set (IDENTITY_PASSWORD_PEPPER_KEY / _VERSION, IDENTITY_TOTP_SEAL_KEY /
// _KEY_VERSION). A re-sealing pass needs the OLD key too — it cannot open what
// the old key sealed otherwise — so with only the current version loaded, every
// row at an older version is reported as UNOPENABLE rather than re-sealed. That
// is the correct and loudest possible behaviour: the job refuses to touch a value
// it cannot open, says so per row and per pass, and the count of rows on the old
// key does not fall. It is NOT silent, and it must never be mistaken for the job
// being broken — see the note in the report this returns to the operator.
//
// Completing a rotation therefore requires the previous key to be loaded
// alongside the current one. PepperKeys.Rotate and totpseal.Keys.Rotate already
// support holding several versions at once; what is missing is a configuration
// key that carries the previous versions into this process. That gap is outside
// this file's reach and is reported rather than worked around, because the
// workaround — opening a row under whatever key happens to be loaded — is exactly
// the mistake that destroys credentials.
func newCredentialReseal(
	d *dependencies, cfg *config.Config, log *slog.Logger,
) (*app.KeyReseal, error) {
	if d.pool == nil {
		return nil, errors.New("no read model: the re-sealing work list and its done check " +
			"are queries against the credential table, so neither can run")
	}
	if !cfg.Identity.Configured() {
		return nil, errors.New("identity key material is not configured: set " +
			"IDENTITY_PASSWORD_PEPPER_KEY and IDENTITY_TOTP_SEAL_KEY, or nothing can be " +
			"opened and nothing can be re-sealed")
	}

	// Decoded here rather than held on the config, so the key bytes exist in
	// exactly one scope — the same discipline cmd/api applies in buildIdentity.
	// EVERY version, and for this binary that is the entire point: re-sealing
	// means opening a value under the key it was sealed with and writing it back
	// under the current one. Holding only the current key makes every outstanding
	// row Unopenable — which the job reports loudly and correctly, and which means
	// the rotation it exists to complete can never complete.
	pepperKeys, err := cfg.Identity.PasswordPepperKeySet()
	if err != nil {
		return nil, err
	}
	pepper, err := argon2id.NewPepperKeys(pepperKeys, cfg.Identity.PasswordPepperVersion)
	if err != nil {
		return nil, fmt.Errorf("password pepper: %w", err)
	}
	// DefaultParams, and they are never used. Reseal preserves each verifier's
	// OWN salt and cost parameters — it has no plaintext to re-derive a digest
	// from, so it cannot change them — and the hasher's params only govern Hash.
	// Passing the defaults keeps the constructor's validation honest without
	// implying this binary is in the business of hashing passwords.
	hasher, err := argon2id.New(pepper, argon2id.DefaultParams)
	if err != nil {
		return nil, fmt.Errorf("password hasher: %w", err)
	}
	passwords, err := argon2id.NewPasswordResealer(hasher)
	if err != nil {
		return nil, err
	}

	sealKeySet, err := cfg.Identity.TotpSealKeySet()
	if err != nil {
		return nil, err
	}
	sealKeys, err := totpseal.NewKeys(sealKeySet, cfg.Identity.TotpSealKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("totp sealing keys: %w", err)
	}
	sealer, err := totpseal.New(sealKeys)
	if err != nil {
		return nil, fmt.Errorf("totp sealer: %w", err)
	}
	secrets, err := totpseal.NewTOTPResealer(sealer)
	if err != nil {
		return nil, err
	}

	store, err := identitypg.NewResealStore(pgadapter.New(d.pool))
	if err != nil {
		return nil, err
	}

	// BOTH resealers, always. A job wired with one of them reports a clean pass
	// over the kind it cannot see, which is precisely the failure this area has
	// already had once: the work list hardcoded `kind = 'password'`, reported
	// zero rows outstanding, and every TOTP secret in the system still depended
	// on the key an operator was being told was safe to destroy.
	return app.NewKeyReseal(store, log, passwords, secrets)
}

// scheduleReseal makes credential re-sealing recur.
//
// Separate from scheduleSweep and scheduleRetention rather than folded into
// either, because the three failures are different and the log lines have to say
// different things. A missing sweep reaches a user who cannot register; a missing
// retention job reaches nobody until a table is enormous; a missing re-sealing
// job reaches an OPERATOR, through a count that never falls, and the two
// conclusions available from that number are "keep the leaked key forever" and
// "destroy it anyway".
func (d *dependencies) scheduleReseal(log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), scheduleTimeout)
	defer cancel()

	created, err := temporaladapter.EnsureResealSchedule(ctx, d.temporal,
		temporaladapter.ResealCredentialKeysInput{}, temporaladapter.DefaultResealInterval)
	switch {
	case err != nil:
		log.Error("credential re-sealing is NOT scheduled; a key rotation can never be "+
			"completed, every old pepper and TOTP sealing key must be kept alive "+
			"indefinitely, and any account that has not signed in since a rotation stays "+
			"pinned to the old key",
			"schedule", temporaladapter.ResealCredentialKeysScheduleID, "error", err)
	case created:
		log.Info("credential re-sealing scheduled",
			"schedule", temporaladapter.ResealCredentialKeysScheduleID,
			"every", temporaladapter.DefaultResealInterval)
	default:
		log.Info("credential re-sealing already scheduled",
			"schedule", temporaladapter.ResealCredentialKeysScheduleID)
	}
}
