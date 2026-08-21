//go:build integration

package identityit_test

import (
	"context"
	"strings"
	"testing"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/internal/modules/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// TestIdentityEventsCarryTheirSchemaVersion is the test that found why nothing
// past registration works.
//
// # The rule
//
// ADR-029 evolves events by upcasting on read: every stored event records the
// schema version it was written at, and `UpcasterRegistry.Apply` walks the chain
// from that version up to the current one. `RegisterSchemas` declares every
// identity event at version 1. An event stored at version 0 is therefore a
// version the registry believes is OLDER than current, and loading it demands a
// v0 → v1 upcaster that does not exist and never should — the shape never
// changed.
//
// # Why nothing else notices
//
// The kernel fills the field for you on the single-stream path:
// `Repository.Save` sets `SchemaVersion` from the registry when the caller left
// it zero. Identity does not use that path for its command appends — a
// registration writes two streams atomically, so it goes through
// `MultiAppender` with metadata it builds itself — and the three metadata
// builders in `app/` set OccurredAt, SubjectIDs, ActorID and the causation
// chain, and never SchemaVersion.
//
// The read model stays perfectly healthy while this is broken, which is what
// makes it so hard to see: the projection path does not upcast at all, so
// `user_view` fills in correctly and every dashboard is green. Only the
// AGGREGATE path upcasts, and that is the path every command takes.
//
// This test reads the stored metadata straight out of KurrentDB and then tries
// the load the handlers try, so a failure names the cause rather than the
// symptom.
func TestIdentityEventsCarryTheirSchemaVersion(t *testing.T) {
	ctx := context.Background()
	email := h.freshEmail("schema")

	if _, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: email,
	})); err != nil {
		t.Fatalf("Register: %v\n%s", err, h.serverLogs())
	}
	index := h.emailIndex(t, email)
	account := h.awaitAccount(t, index)

	upcasters := eventsourcing.NewUpcasterRegistry()
	identity.RegisterSchemas(upcasters)

	for _, s := range []struct{ label, category, key string }{
		{"account", "user", account.userID},
		{"reservation", "reservation_email", index},
	} {
		id, err := eventsourcing.NewStreamID(eventsourcing.Category(s.category), s.key)
		if err != nil {
			t.Fatalf("stream id: %v", err)
		}
		events, err := h.store.ReadStream(ctx, id, 0)
		if err != nil {
			t.Fatalf("reading %s: %v", id, err)
		}
		if len(events) == 0 {
			t.Fatalf("%s stream is empty", s.label)
		}
		for _, e := range events {
			// Decoded with the SERVER's own codec, so the field this reads is
			// exactly the field the repository reads when it decides what to
			// upcast — not a hand-written struct that could disagree about a tag.
			meta, err := h.codec.UnmarshalMetadata(e.Metadata)
			if err != nil {
				t.Fatalf("metadata of %s: %v", e.Type, err)
			}
			want, ok := upcasters.CurrentVersion(e.Type)
			if !ok {
				t.Errorf("%s is not registered in the schema registry", e.Type)
				continue
			}
			if meta.SchemaVersion != want {
				t.Errorf("BUG: %s on the %s stream was stored at schema_version %d, but the "+
					"registry declares v%d. Loading it demands a v%d -> v%d upcaster that does "+
					"not exist, so the aggregate can never be rehydrated.",
					e.Type, s.label, meta.SchemaVersion, want, meta.SchemaVersion, want)
			} else {
				t.Logf("%s stored at schema_version %d (current)", e.Type, meta.SchemaVersion)
			}
		}
	}

	// The consequence, stated as a load rather than as an inference. This is the
	// exact call every identity command makes as its first step, built from the
	// same constructors cmd/api builds it from.
	users := eventsourcing.NewRepository[*domain.User](
		h.store, h.codec, upcasters, app.UserCategory, domain.New)
	if _, err := users.Load(ctx, account.userID); err != nil {
		t.Errorf("BUG: the account this system just wrote cannot be loaded back: %v\n"+
			"Every command that begins by loading a User — VerifyEmail, Authenticate, "+
			"CreateSession, EnrollTotp, ConfirmTotp, RevokeSession — fails here, and fails "+
			"with an unwrapped error, so the caller gets an undifferentiated INTERNAL and "+
			"the server logs nothing at all.", err)
	}

	reservations := eventsourcing.NewRepository[*domain.EmailReservation](
		h.store, h.codec, upcasters, app.ReservationCategory, domain.NewReservation)
	if _, err := reservations.Load(ctx, index); err != nil {
		t.Errorf("BUG: the reservation this system just wrote cannot be loaded back: %v", err)
	}
}

// TestAnInternalErrorReachesTheLog is the observability half of the same
// finding, and it is worth its own name because it is what turned a
// five-minute diagnosis into an hour.
//
// `VerifyEmail` fails with `fmt.Errorf("loading the account for a verification:
// %w", err)`. That error never passed through `errs`, so
// `server/connect.Error` maps it — correctly, per its own doc — to a bare
// INTERNAL with no message and no reason detail. Nothing anywhere logs the
// wrapped cause. The operator's total evidence for a completely broken identity
// slice is the string "internal error" on the wire and silence in the log.
//
// The test asserts what a running server should be able to tell an operator: if
// an RPC answers INTERNAL, SOMETHING must be written to the log about it.
func TestAnInternalErrorReachesTheLog(t *testing.T) {
	ctx := context.Background()
	email := h.freshEmail("logging")

	if _, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: email,
	})); err != nil {
		t.Fatalf("Register: %v\n%s", err, h.serverLogs())
	}
	account := h.awaitAccount(t, h.emailIndex(t, email))
	plaintext := h.mintVerificationToken(t, account.subjectID)

	mark := len(h.serverLogs())
	_, err := h.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
		Token:    plaintext,
		Password: "correct-horse-battery-staple-54",
		Username: h.freshUsername("schema"),
	}))
	if err == nil {
		t.Skip("VerifyEmail succeeded, so there is no internal error to look for; the " +
			"schema-version defect has been fixed and this test can be deleted")
	}
	tail := h.serverLogs()[mark:]
	t.Logf("wire error: %v", err)
	t.Logf("server log written during the failing call:\n%s", strings.TrimSpace(tail))

	if !strings.Contains(tail, "ERROR") {
		t.Errorf("BUG: an RPC answered %v and the server logged nothing. The wrapped cause "+
			"is discarded by server/connect.Error (which is correct — it never passed "+
			"through errs) and logged by nobody, so a total identity outage is "+
			"indistinguishable from a healthy server plus a confused client.", err)
	}
}
