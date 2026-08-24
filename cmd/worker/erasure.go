package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/piivault"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	complianceapp "github.com/chronos/chronos-go/internal/modules/compliance/app"
	compliancereactor "github.com/chronos/chronos-go/internal/modules/compliance/reactor"
	identitypg "github.com/chronos/chronos-go/internal/modules/identity/adapter/postgres"
	identityapp "github.com/chronos/chronos-go/internal/modules/identity/app"
	identitydomain "github.com/chronos/chronos-go/internal/modules/identity/domain"
	profiledomain "github.com/chronos/chronos-go/internal/modules/profile/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/pii"
	"github.com/chronos/chronos-go/internal/platform/workflow"
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

	// The passkey store, which erasure must reach EXPLICITLY.
	//
	// It is the one erasure target with no key to destroy: a WebAuthn public key
	// is verification material, so the vault never held it and shredding a
	// subject key leaves it untouched. Migration 00033 also removed the foreign
	// key that would have cascaded, because `user_view` is a projection and a
	// rebuild truncating it would have taken every passkey in the installation.
	//
	// So nothing else deletes these rows. Without this the credential id and
	// public key of somebody who asked to be forgotten stay in the database
	// forever — and the store's Erase was implemented, tested, and called by
	// NOTHING until this line.
	passkeys, err := identitypg.NewPasskeys(pgadapter.New(d.pool))
	if err != nil {
		return nil, fmt.Errorf("passkey store: %w", err)
	}

	return identityapp.NewErasure(identityapp.ErasureDeps{
		Directory: reads,
		Users:     users, Emails: emails, Usernames: usernames,
		Passkeys: passkeys,
		Now:      clock.System{}.Now,
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

	if d.blobs == nil {
		return nil, errors.New("no object store: an avatar is a photograph of a person " +
			"living outside the vault, so destroying the subject key does nothing to it " +
			"and an erasure without this leaves it servable")
	}

	confirmation, err := complianceapp.NewMailConfirmation(d.notify)
	if err != nil {
		return nil, fmt.Errorf("erasure confirmation: %w", err)
	}
	objects, err := complianceapp.NewObjects(complianceapp.ObjectsDeps{
		Store: d.blobs, Prefixes: subjectObjectPrefixes,
	})
	if err != nil {
		return nil, fmt.Errorf("object erasure: %w", err)
	}
	log.Info("erasure orchestration constructed",
		"object_prefixes", len(subjectObjectPrefixes("probe")))

	return complianceapp.NewErasure(complianceapp.ErasureDeps{
		Vault:    vaultEraser{vault: d.piiVault},
		Accounts: accountEraser{accounts: d.accountErasure},
		Objects:  objects,
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

// subjectObjectPrefixes is compliance.md §4 step 4's subject graph, for objects.
//
// # This list is the extension point, and forgetting it is the failure mode
//
// Every module that stores an OBJECT keyed under something derived from a
// subject belongs here. Vault fields do not: one key destruction makes all of
// them unreadable at once, which is the whole design of ADR-002. Objects are
// outside that, and nothing about destroying a key reaches them.
//
// It lives in the composition root rather than in compliance because compliance
// may not import another module's internals (CONVENTIONS §2) — and
// `profile.AvatarPrefix` is exactly the kind of internal detail that should not
// cross a module boundary. Assembling the list is what a composition root is
// for.
//
// A module added to this system that stores objects and is NOT added here erases
// incompletely, and the symptom is nothing at all: the erasure reports success.
// The compliance use case refuses an empty list for that reason, and the wiring
// test asserts profile's prefix is present — both of which are cheaper than
// discovering it from a subject access request.
func subjectObjectPrefixes(subjectID string) []string {
	return []string{
		// profile: avatars. The prefix is a digest of the pseudonym, so this
		// enumerates one person's objects rather than scanning a bucket — and it
		// covers superseded avatars and abandoned uploads, which no projection
		// names and ADR-056 left unreclaimed.
		profiledomain.AvatarPrefix(subjectID),
	}
}

// newErasureSweep builds the backstop for requests the reactor never picked up.
//
// The client is passed IN rather than read from d.temporal: this runs while the
// worker is being built, which happens BEFORE startTemporal publishes the client
// — and reading the field here would find nil and disable the backstop on every
// boot, silently.
func newErasureSweep(
	d *dependencies, client *temporaladapter.Client, log *slog.Logger,
) (*complianceapp.Sweep, error) {
	if d.pool == nil {
		return nil, errors.New("no read model: the work list is user_view's deletion " +
			"deadlines, so nothing can find a request whose clock never started")
	}
	if client == nil {
		return nil, errors.New("no Temporal client: the backstop restarts CLOCKS, and " +
			"there is nowhere to run one")
	}

	reads, err := identitypg.NewReadModel(pgadapter.New(d.pool))
	if err != nil {
		return nil, fmt.Errorf("overdue deletions: %w", err)
	}
	return complianceapp.NewSweep(complianceapp.SweepDeps{
		Requests: overdueAdapter{reads: reads},
		Starter:  erasureStarter{starter: client},
		Log:      log,
	})
}

// overdueAdapter narrows identity's read model to compliance's port.
//
// It converts between two structurally identical row types, which is the cost of
// the import contract: compliance may not read identity's tables and identity
// may not know compliance's vocabulary, so the shape is declared twice and
// matched here — in one place, where a mismatch is a compile error.
type overdueAdapter struct{ reads *identitypg.ReadModel }

func (a overdueAdapter) ListOverdue(
	ctx context.Context, before time.Time, limit int,
) ([]complianceapp.OverdueRequest, error) {
	rows, err := a.reads.ListOverdueDeletions(ctx, before, limit)
	if err != nil {
		return nil, err
	}
	out := make([]complianceapp.OverdueRequest, 0, len(rows))
	for _, r := range rows {
		out = append(out, complianceapp.OverdueRequest{
			SubjectID: r.SubjectID, ScheduledFor: r.ScheduledFor,
		})
	}
	return out, nil
}

// erasureStarter starts the SAME workflow the reactor starts.
//
// The same id, so a sweep for a request that already has a clock finds it
// running rather than starting a second. That is what keeps the backstop from
// being a second path to an irreversible action: it can only ever cause what the
// ordinary path causes.
type erasureStarter struct{ starter *temporaladapter.Client }

func (s erasureStarter) StartErasure(ctx context.Context, subjectID string) error {
	_, err := s.starter.Start(ctx, workflow.Start{
		ID:    "erasure:" + subjectID,
		Name:  temporaladapter.ErasureWorkflow,
		Input: compliancereactor.ErasureArgs{SubjectID: subjectID},
	})
	if errors.Is(err, workflow.ErrAlreadyStarted) {
		// The ordinary case on a healthy system: every overdue request already
		// has a clock, and this is the sweep confirming it.
		return nil
	}
	return err
}

// sweepAdapterForErasure narrows the use case to the activity's port.
type sweepAdapterForErasure struct{ sweep *complianceapp.Sweep }

func (a sweepAdapterForErasure) SweepOnce(
	ctx context.Context, now time.Time, limit int,
) (temporaladapter.ErasureSweepPass, error) {
	res, err := a.sweep.SweepOnce(ctx, now, limit)
	if err != nil {
		return temporaladapter.ErasureSweepPass{}, err
	}
	return temporaladapter.ErasureSweepPass{
		Scanned: res.Scanned, Started: res.Started, Failed: res.Failed, More: res.More,
	}, nil
}
