//go:build integration

package identityit_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/openbao"
	"github.com/chronos/chronos-go/internal/adapter/piivault"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/argon2id"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// registerThroughTheKernel creates an account that the server can actually LOAD.
//
// It creates NO CREDENTIAL, exactly as the public Register no longer does
// (IDENTITY-REVIEW C8). The password arrives later, over HTTP, in the
// VerifyEmail call — which is the point of the change and is now covered by the
// real handler rather than reproduced here.
//
// # Why this exists
//
// `Register` over HTTP works, and the account it creates is unusable: identity's
// command handlers build their event metadata by hand and never set
// SchemaVersion, so every event is stored at v0 while the registry declares v1,
// and the aggregate can never be rehydrated. See
// TestIdentityEventsCarryTheirSchemaVersion for the evidence. That defect stops
// the end-to-end scenario at step 2, and stopping there would leave steps 3
// through 7 — the second factor, the session, the bearer token, the interceptor
// and the revocation — completely unexercised. Those are the parts of the slice
// nothing else in the repository has ever run.
//
// So this builds the same account through the SAME domain aggregates and the
// SAME adapters, but saves it with `eventsourcing.Repository.Save`, which is the
// kernel's own append path and fills SchemaVersion from the registry — exactly
// what the handler's hand-rolled metadata omits. Everything else is production
// code: the normalizer, the blind index, the PII vault against real OpenBao, and
// both aggregates' own invariants.
//
// # What it deliberately does NOT reproduce
//
// The atomic two-stream append. `Register` claims the reservation and creates
// the account in one multi-append; this saves the two aggregates separately,
// which is precisely the ordering the design rejects (IDENTITY-SLICE-1,
// "Settled: the registration ordering"). It is acceptable here only because
// nothing about the steps that follow depends on the atomicity, and because the
// atomic path is exercised for real by
// TestConcurrentRegistrationsForOneAddress. Reserve is saved FIRST, matching
// the production order, so a failure leaves a lapsing lease rather than an
// account with no claim.
//
// It should be deleted the moment the schema-version defect is fixed: the
// scenario can then use the public Register call for its setup, and this file
// becomes a second, divergent way to make an account.
func (hh *harness) registerThroughTheKernel(
	t *testing.T, email string,
) accountRow {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	normalized, err := domain.NormalizeEmail(email)
	if err != nil {
		t.Fatalf("normalizing %q: %v", email, err)
	}
	index, err := hh.index.Of(normalized)
	if err != nil {
		t.Fatalf("blind index: %v", err)
	}

	now := time.Now().UTC()
	userID := ids.New[ids.User](now, rand.Reader)
	subjectID := ids.New[ids.Subject](now, rand.Reader).String()

	// No verifier, and no credential row. This fixture reproduces what the public
	// Register now does, and Register creates no credential at all
	// (IDENTITY-REVIEW C8). The password is chosen by whoever follows the
	// verification link, and the scenario supplies it over HTTP through the real
	// VerifyEmail handler — which is the part of the flow worth exercising, and
	// the part a hand-built credential used to hide.
	if err := hh.vault.PutAll(ctx, pii.SubjectID(subjectID),
		map[pii.Field]string{pii.FieldEmail: normalized}); err != nil {
		t.Fatalf("storing the address in the vault: %v", err)
	}

	key := "fixture_" + hex.EncodeToString([]byte(subjectID))

	reservation := eventsourcing.NewAggregate(domain.NewReservation)
	if err := reservation.Reserve(index, subjectID, now.Add(24*time.Hour), now); err != nil {
		t.Fatalf("reserving the address: %v", err)
	}
	if _, err := hh.reservationRepo.Save(ctx, string(index), reservation,
		key+":res", eventsourcing.Metadata{
			OccurredAt: now, SubjectIDs: []string{subjectID}, ActorID: subjectID,
		}); err != nil {
		t.Fatalf("saving the reservation: %v", err)
	}

	user := eventsourcing.NewAggregate(domain.New)
	if err := user.Register(userID, subjectID, index, now); err != nil {
		t.Fatalf("registering: %v", err)
	}
	if _, err := hh.userRepo.Save(ctx, userID.String(), user,
		key+":usr", eventsourcing.Metadata{
			OccurredAt: now, SubjectIDs: []string{subjectID}, ActorID: subjectID,
		}); err != nil {
		t.Fatalf("saving the account: %v", err)
	}

	// The account only becomes usable to the API once the projector has written
	// it, exactly as a real registration does.
	row := hh.awaitAccount(t, string(index))
	if row.subjectID != subjectID || row.userID != userID.String() {
		t.Fatalf("the projected row names %s/%s, want %s/%s",
			row.subjectID, row.userID, subjectID, userID)
	}
	t.Logf("fixture account: subject=%s user=%s state=%s", row.subjectID, row.userID, row.state)
	return row
}

// buildKernelFixtures constructs the adapters registerThroughTheKernel needs.
// Called once from the harness, so a missing dependency fails at startup rather
// than in the middle of a scenario.
func (hh *harness) buildKernelFixtures(
	pepperKeyHex, baoAddr, baoToken, kekName string,
	upcasters *eventsourcing.UpcasterRegistry,
) error {
	pepperBytes, err := hex.DecodeString(pepperKeyHex)
	if err != nil {
		return err
	}
	pepper, err := argon2id.NewPepperKeys(map[int][]byte{1: pepperBytes}, 1)
	if err != nil {
		return err
	}
	hasher, err := argon2id.New(pepper, argon2id.DefaultParams)
	if err != nil {
		return err
	}
	hh.hasher = hasher

	bao, err := openbao.Dial(baoAddr, baoToken)
	if err != nil {
		return err
	}
	hh.vault = piivault.New(hh.pg, openbao.NewKeyRing(bao, kekName))

	hh.userRepo = eventsourcing.NewRepository[*domain.User](
		hh.store, hh.codec, upcasters, app.UserCategory, domain.New)
	hh.reservationRepo = eventsourcing.NewRepository[*domain.EmailReservation](
		hh.store, hh.codec, upcasters, app.ReservationCategory, domain.NewReservation)
	// The public handle's reservation. Held for ONE thing no RPC can do: writing
	// a tombstone. Erasure is `compliance`'s work and that module does not exist,
	// so TestATombstonedHandleIsNeverReissued drives the aggregate's own
	// transition through the kernel's append path — the same way an erasure will
	// when there is something to perform it.
	hh.usernameRepo = eventsourcing.NewRepository[*domain.UsernameReservation](
		hh.store, hh.codec, upcasters, app.UsernameCategory, domain.NewUsernameReservation)
	return nil
}
