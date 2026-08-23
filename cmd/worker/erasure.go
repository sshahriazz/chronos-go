package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/chronos/chronos-go/internal/adapter/piivault"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	complianceapp "github.com/chronos/chronos-go/internal/modules/compliance/app"
	compliancereactor "github.com/chronos/chronos-go/internal/modules/compliance/reactor"
	identitypg "github.com/chronos/chronos-go/internal/modules/identity/adapter/postgres"
	identityapp "github.com/chronos/chronos-go/internal/modules/identity/app"
	identitydomain "github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// newAccountErasure builds identity's half of an erasure.
//
// Sessions, the address reservation, the username tombstone, and the account's
// own terminal event. It knows nothing about keys or grace periods.
func newAccountErasure(d *dependencies) (*identityapp.Erasure, error) {
	if d.store == nil {
		return nil, errors.New("no event store: an erasure is recorded as events")
	}
	if d.pool == nil {
		return nil, errors.New("no read model: an erasure names a pseudonym and user " +
			"streams are named after account ids, so there is no stream to erase")
	}

	reads, err := identitypg.NewReadModel(pgadapter.New(d.pool))
	if err != nil {
		return nil, fmt.Errorf("account directory: %w", err)
	}
	users := eventsourcing.NewRepository[*identitydomain.User](
		d.store, d.codec, nil, identityapp.UserCategory, identitydomain.New)
	emails := eventsourcing.NewRepository[*identitydomain.EmailReservation](
		d.store, d.codec, nil,
		identityapp.ReservationCategory, identitydomain.NewReservation)
	usernames := eventsourcing.NewRepository[*identitydomain.UsernameReservation](
		d.store, d.codec, nil,
		identityapp.UsernameCategory, identitydomain.NewUsernameReservation)

	return identityapp.NewErasure(identityapp.ErasureDeps{
		Directory: reads,
		Users:     users, Emails: emails, Usernames: usernames,
		Now: clock.System{}.Now,
	})
}

// newErasure builds compliance's orchestration.
//
// # What its absence costs
//
// A person asks to be forgotten, we record the request and mail them a date, and
// nothing ever happens. No error is raised anywhere, because from this system's
// side nothing happened — and the obligation has a statutory clock.
func newErasure(d *dependencies, log *slog.Logger) (*complianceapp.Erasure, error) {
	if d.piiVault == nil {
		return nil, errors.New("no PII vault: destroying the subject key IS the erasure, " +
			"and without it every other step is bookkeeping over data that is still readable")
	}
	if d.accountErasure == nil {
		return nil, errors.New("identity's erasure half was not constructed")
	}
	if d.notify == nil {
		return nil, errors.New("no notification dispatcher: the erasure confirmation is the " +
			"one message that cannot be sent afterwards")
	}

	confirmation, err := complianceapp.NewMailConfirmation(d.notify)
	if err != nil {
		return nil, fmt.Errorf("erasure confirmation: %w", err)
	}
	log.Info("erasure orchestration constructed")

	return complianceapp.NewErasure(complianceapp.ErasureDeps{
		Vault:    vaultEraser{vault: d.piiVault},
		Accounts: accountEraser{accounts: d.accountErasure},
		Confirm:  confirmation,
		Now:      clock.System{}.Now,
	})
}

// vaultEraser narrows the vault to the one method compliance may call.
//
// The vault can read every field of every subject. The code that performs an
// irreversible destruction should hold exactly the capability it needs and no
// more — the same reason identity's Erasure takes a SessionRevoker rather than
// the whole authentication use case.
type vaultEraser struct{ vault *piivault.Vault }

func (e vaultEraser) Erase(ctx context.Context, subjectID string) error {
	return e.vault.Erase(ctx, pii.SubjectID(subjectID))
}

// accountEraser narrows identity's use case to compliance's port, discarding
// the counts: what the orchestration needs to know is whether it worked.
type accountEraser struct{ accounts *identityapp.Erasure }

func (e accountEraser) Erase(ctx context.Context, subjectID string) error {
	_, err := e.accounts.Erase(ctx, subjectID)
	return err
}

// newErasureReactor builds the reactor that starts the grace-period clock.
func newErasureReactor(d *dependencies) (*compliancereactor.Erasure, error) {
	if d.temporal == nil {
		return nil, errors.New("no Temporal client: the grace period is a durable timer, " +
			"and there is nowhere to run it")
	}
	return compliancereactor.NewErasure(
		d.temporal, temporaladapter.ErasureWorkflow, d.codec)
}
