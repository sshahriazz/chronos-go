//go:build integration

package identityit_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	identityprojection "github.com/chronos/chronos-go/internal/modules/identity/projection"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/kurrent-io/KurrentDB-Client-Go/kurrentdb"
)

// ---------------------------------------------------------------------------
// THE property: uniqueness under contention, asserted against the LOG
// ---------------------------------------------------------------------------

// TestConcurrentUsernameClaimsForOneHandle is the property the username
// reservation stream exists for (ADR-051), driven with real goroutines against
// the real server.
//
// Uniqueness of a public handle is not a UNIQUE constraint. It is an optimistic
// append to a stream named by the handle itself, with NoStream as the
// precondition — so eight verifications racing for one handle contend inside
// KurrentDB, seven get a revision conflict, and each loser's ENTIRE verification
// is discarded because the append that claims the handle is the same atomic
// multi-append that proves the address and sets the first password.
//
// # Why this cannot be shown below the integration level
//
// A unit test with a fake appender proves the handler's branch is written. It
// cannot prove that KurrentDB actually refuses the second append, and that is
// where the guarantee lives. It is driven concurrently for the same reason:
// serialized calls take the "already claimed" branch, which is a different code
// path from the one that loses the append race.
//
// # Why the assertion is against $all and not against user_view
//
// Because a projection is the one place that cannot answer this question
// honestly. `user_view.username` carries a partial UNIQUE index (migration
// 00016), so a second account for one handle would not appear as a second row —
// the INSERT would be refused, the identity projector would stop, and
// `SELECT count(*)` would keep returning 1. That is exactly how
// TestConcurrentRegistrationsForOneAddress passed while the log held two
// registrations for one address (ADR-054). The log cannot filter: every claim
// that got as far as an append is in it, whatever any projector later did.
func TestConcurrentUsernameClaimsForOneHandle(t *testing.T) {
	const racers = 8
	ctx := context.Background()

	handle := h.freshUsername("race")

	// Eight DIFFERENT accounts, each with its own address and its own live
	// verification token. They must be different accounts: eight calls with one
	// token would contend on the token store's single-use DELETE instead, which
	// is a real property but a different one.
	type racer struct {
		token   string
		subject string
	}
	contenders := make([]racer, racers)
	for i := range contenders {
		email := h.freshEmail("uraceres")
		account := h.registerThroughTheKernel(t, email)
		contenders[i] = racer{
			token:   h.mintVerificationToken(t, account.subjectID),
			subject: account.subjectID,
		}
	}

	// The position the log is at before anything races. Every assertion that
	// matters is made against the events committed after it.
	from := h.logTail(t)

	start := make(chan struct{})
	var wg sync.WaitGroup
	errsByRacer := make([]error, racers)
	for i := range racers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := h.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
				Token:    contenders[i].token,
				Password: "correct-horse-battery-staple-77",
				Username: handle,
			}))
			errsByRacer[i] = err
		}(i)
	}
	close(start)
	wg.Wait()

	// Unlike registration, the outcomes here are DELIBERATELY distinguishable.
	// A handle is published by design and its availability is served by a public
	// RPC, so telling the loser "that username is not available" discloses
	// nothing an attacker could not read from CheckUsernameAvailability — and it
	// is the only message that lets a real person pick another handle.
	var won, refused int
	for i, err := range errsByRacer {
		switch {
		case err == nil:
			won++
		case connectrpc.CodeOf(err) == connectrpc.CodeAlreadyExists:
			refused++
		default:
			t.Errorf("racer %d failed with an unexpected error: %v (code %v)",
				i, err, connectrpc.CodeOf(err))
		}
	}
	t.Logf("racers=%d won=%d refused=%d handle=%s", racers, won, refused, handle)
	if won != 1 || refused != racers-1 {
		t.Errorf("%d racers won and %d were refused, want exactly 1 and %d",
			won, refused, racers-1)
	}

	// THE assertion, and it is made against the LOG.
	claims := h.usernameClaimsFor(t, handle, from)
	if len(claims) != 1 {
		t.Errorf("%d concurrent verifications put %d UsernameReserved events in the log "+
			"for one handle, want exactly 1: %v. The append that claims the handle and "+
			"the append that proves the address are the same atomic multi-append, so a "+
			"second claim here means the reservation stream admitted two winners "+
			"(ADR-044, ADR-051).", racers, len(claims), claims)
	}

	// The handle's own stream, read back from KurrentDB rather than from any
	// projection. The projection is derived; the stream is the truth.
	stream, err := eventsourcing.NewStreamID(app.UsernameCategory, handle)
	if err != nil {
		t.Fatalf("stream id: %v", err)
	}
	events, err := h.store.ReadStream(ctx, stream, 0)
	if err != nil {
		t.Fatalf("reading the handle's stream: %v", err)
	}
	types := make([]string, 0, len(events))
	for _, e := range events {
		types = append(types, e.Type)
	}
	if len(events) != 1 || types[0] != (&contract.UsernameReserved{}).EventType() {
		t.Errorf("the handle's stream holds %v, want exactly one claim", types)
	}

	// The losers left NOTHING behind — not a verification, not a password. That
	// is what makes the append atomic rather than merely ordered: a loser whose
	// EmailVerified had already committed would be a verified account with a
	// handle it does not hold.
	//
	// Asserted from the LOG for the reason above, and per subject so a single
	// loser is named rather than hidden in an aggregate count.
	verified := h.subjectsVerifiedSince(t, from)
	if len(verified) != 1 {
		t.Errorf("%d accounts were verified by the race, want 1: %v. A loser that "+
			"recorded EmailVerified has proven its address and holds no handle, which "+
			"is the state the atomic append exists to make unrepresentable",
			len(verified), verified)
	}
	if len(claims) == 1 && len(verified) == 1 && claims[0] != verified[0] {
		t.Errorf("the handle was claimed by %s and the verification belongs to %s; "+
			"one atomic append cannot produce two different subjects",
			claims[0], verified[0])
	}

	// And the projection agrees, once it catches up. Checked SECOND and
	// separately, because it answers a different question: not "did uniqueness
	// hold" but "did the projector survive what uniqueness produced".
	if len(claims) == 1 {
		h.awaitUsernameRow(t, handle, claims[0])
	}
	var rows int
	h.systemQuery(t, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx,
			`SELECT count(*) FROM user_view WHERE username = $1`, handle).Scan(&rows)
	})
	if rows != 1 {
		t.Errorf("%d user_view rows hold the handle, want exactly 1", rows)
	}
}

// ---------------------------------------------------------------------------
// The availability check, over HTTP
// ---------------------------------------------------------------------------

// TestUsernameAvailabilityOverHTTP exercises the public check through the real
// server, unauthenticated, and pins the one behaviour that is deliberately NOT
// like its neighbours: it answers the question.
//
// Every other public RPC in this service is shaped so its two outcomes are
// indistinguishable, because an address is secret. A handle is not — publication
// is its entire purpose — so this endpoint is an enumeration oracle on purpose,
// and a future "hardening" that made it uniform would leave an API that answers
// nothing while the same fact stayed readable from every mention and every
// profile URL.
func TestUsernameAvailabilityOverHTTP(t *testing.T) {
	ctx := context.Background()
	handle := h.freshUsername("avail")

	// No bearer token, no idempotency key. It is public and it is a READ.
	free, err := h.client.CheckUsernameAvailability(ctx,
		connectrpc.NewRequest(&identityv1.CheckUsernameAvailabilityRequest{
			Username: strings.ToUpper(handle),
		}))
	if err != nil {
		t.Fatalf("CheckUsernameAvailability: %v\n%s", err, h.serverLogs())
	}
	if !free.Msg.GetAvailable() {
		t.Fatalf("a freshly minted handle %q reports itself taken", handle)
	}
	// The CANONICAL form comes back, not what was typed. A client that echoed the
	// input would show somebody a handle in a casing they will never hold.
	if got := free.Msg.GetUsername(); got != handle {
		t.Errorf("the check returned %q for input %q, want the lower-cased canonical "+
			"form %q", got, strings.ToUpper(handle), handle)
	}

	// Claim it through the real flow, then ask again.
	account := h.registerThroughTheKernel(t, h.freshEmail("avail"))
	if _, err := h.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
		Token:    h.mintVerificationToken(t, account.subjectID),
		Password: "correct-horse-battery-staple-78",
		Username: handle,
	})); err != nil {
		t.Fatalf("VerifyEmail: %v\n%s", err, h.serverLogs())
	}

	// Answered from the STREAM, not from a projection, so it is correct the
	// instant the append returns. No polling here, deliberately: a retry loop
	// would hide exactly the staleness this design exists to avoid.
	taken, err := h.client.CheckUsernameAvailability(ctx,
		connectrpc.NewRequest(&identityv1.CheckUsernameAvailabilityRequest{
			Username: handle,
		}))
	if err != nil {
		t.Fatalf("CheckUsernameAvailability: %v\n%s", err, h.serverLogs())
	}
	if taken.Msg.GetAvailable() {
		t.Errorf("%q reports itself available immediately after being claimed. The check "+
			"reads the reservation STREAM; an answer that lags means it has been "+
			"rewired to a projection, and a check that reports a taken handle free "+
			"sends people to a verification link they will lose.", handle)
	}

	// A reserved name is refused as malformed rather than reported unavailable,
	// and it says so: the list is a property of the system, not of any account.
	_, err = h.client.CheckUsernameAvailability(ctx,
		connectrpc.NewRequest(&identityv1.CheckUsernameAvailabilityRequest{
			Username: "admin",
		}))
	if err == nil {
		t.Error("the reserved handle @admin was reported as an ordinary answer; a handle " +
			"that reads as the operator is a phishing primitive that needs no technical " +
			"compromise at all")
	} else {
		t.Logf("reserved handle refused: %v", err)
	}

	// And the shape rules are enforced at the WIRE, before the handler runs.
	for _, bad := range []string{"ab", "ada-lovelace", "1ada", "_ada"} {
		if _, err := h.client.CheckUsernameAvailability(ctx,
			connectrpc.NewRequest(&identityv1.CheckUsernameAvailabilityRequest{
				Username: bad,
			})); err == nil {
			t.Errorf("the malformed handle %q was accepted; the check and the claim must "+
				"agree on shape, or a handle this reports available is refused by "+
				"VerifyEmail after the link has been spent", bad)
		}
	}
}

// ---------------------------------------------------------------------------
// The tombstone
// ---------------------------------------------------------------------------

// TestATombstonedHandleIsNeverReissued is the erasure half of ADR-051, driven
// end to end: a handle is claimed, tombstoned, deleted from the projection by
// the real projector, and then refused to everybody forever.
//
// # Why the tombstone is written through the aggregate rather than through an RPC
//
// Because there is no RPC. Erasure is `compliance`'s work and that module does
// not exist — `identity.UserDeletionRequested` is emitted and nothing consumes
// it (app.Lifecycle.RequestDeletion). What DOES exist, and is what this test
// drives, is the mechanism: the aggregate's Tombstone transition, the event, the
// projector handler that clears `user_view.username`, and the refusal every
// future claim inherits. The producer is the missing half, and it is missing
// deliberately rather than forgotten.
//
// # Why the refusal matters more than the deletion
//
// Deleting the column is the obvious part and the easy part. The tombstone is
// the part that is easy to leave out and impossible to add later: if @alice
// could be reissued, every old mention, link and cached reference would silently
// re-point at a stranger — so an erasure request, a privacy action taken to
// protect someone, would create an impersonation vector aimed at that same
// person.
func TestATombstonedHandleIsNeverReissued(t *testing.T) {
	ctx := context.Background()
	handle := h.freshUsername("tomb")

	// A real account claims it through the real RPC.
	erasedEmail := h.freshEmail("tomb")
	account := h.registerThroughTheKernel(t, erasedEmail)
	if _, err := h.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
		Token:    h.mintVerificationToken(t, account.subjectID),
		Password: "correct-horse-battery-staple-79",
		Username: handle,
	})); err != nil {
		t.Fatalf("VerifyEmail: %v\n%s", err, h.serverLogs())
	}
	h.awaitUsernameRow(t, handle, account.subjectID)

	// Erasure: the handle is burned on its own stream.
	reservation, err := h.usernameRepo.Load(ctx, handle)
	if err != nil {
		t.Fatalf("loading the handle's reservation: %v", err)
	}
	if err := reservation.Tombstone(time.Now().UTC()); err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	if _, err := h.usernameRepo.Save(ctx, handle, reservation,
		"tombstone_"+handle, eventsourcing.Metadata{
			OccurredAt: time.Now().UTC(),
			// NO SubjectIDs and NO ActorID. A tombstone outlives an erasure, so
			// anything here naming the erased account would be a permanent record
			// linking a person to their own erasure request (ADR-051).
		}); err != nil {
		t.Fatalf("saving the tombstone: %v", err)
	}

	// The projector DELETES the handle from the read model. This is the one place
	// in identity where erasure is a deletion rather than the destruction of a
	// key, and it is a deletion precisely because the value was published:
	// crypto-shredding does nothing to cleartext.
	h.awaitUsernameCleared(t, handle)

	// Nobody may claim it again — not a stranger, and not the erased account's
	// own successor either.
	stranger := h.registerThroughTheKernel(t, h.freshEmail("tombstranger"))
	strangerToken := h.mintVerificationToken(t, stranger.subjectID)
	_, err = h.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
		Token:    strangerToken,
		Password: "correct-horse-battery-staple-80",
		Username: handle,
	}))
	if err == nil {
		t.Fatalf("a tombstoned handle was reissued to a new account. Every old mention "+
			"and link to @%s now points at a stranger, which is an impersonation vector "+
			"created by the erasure that was supposed to protect the previous holder "+
			"(ADR-051)", handle)
	}
	if code := connectrpc.CodeOf(err); code != connectrpc.CodeAlreadyExists {
		t.Errorf("the refusal came back as %v, want AlreadyExists: %v", code, err)
	}

	// The refusal happened BEFORE the token was spent, so the stranger keeps
	// their link and can finish signing up with a different handle. That is the
	// whole reason the availability check runs ahead of Consume.
	if _, err := h.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
		Token:    strangerToken,
		Password: "correct-horse-battery-staple-80",
		Username: h.freshUsername("tombrecover"),
	})); err != nil {
		t.Errorf("the stranger's verification link was burned by a refused handle: %v. "+
			"A person who picks a taken handle did nothing wrong and must not lose "+
			"their only route into the account.\n%s", err, h.serverLogs())
	}

	// And the public check agrees, with NO extra detail. "This handle was
	// tombstoned" would mean "the account that held it was erased", which is a
	// fact about a person — so it is merged into the same answer a merely-taken
	// handle gets.
	answer, err := h.client.CheckUsernameAvailability(ctx,
		connectrpc.NewRequest(&identityv1.CheckUsernameAvailabilityRequest{Username: handle}))
	if err != nil {
		t.Fatalf("CheckUsernameAvailability: %v", err)
	}
	if answer.Msg.GetAvailable() {
		t.Errorf("the availability check reports the tombstoned handle %q as free", handle)
	}
	if answer.Msg.GetUsername() != handle {
		t.Errorf("the check returned %q, want %q", answer.Msg.GetUsername(), handle)
	}

	// The tombstone event itself carries no personal data. Read back from the
	// log, because that is where it will still be in ten years.
	stream, err := eventsourcing.NewStreamID(app.UsernameCategory, handle)
	if err != nil {
		t.Fatalf("stream id: %v", err)
	}
	stored, err := h.store.ReadStream(ctx, stream, 0)
	if err != nil {
		t.Fatalf("reading the handle's stream: %v", err)
	}
	var sawTombstone bool
	for _, e := range stored {
		if e.Type != (&contract.UsernameTombstoned{}).EventType() {
			continue
		}
		sawTombstone = true
		if strings.Contains(string(e.Payload), account.subjectID) {
			t.Errorf("the tombstone payload names the erased subject: %s. It is retained "+
				"after an erasure request, and that is only lawful because it retains "+
				"no personal data (ADR-051)", e.Payload)
		}
		if strings.Contains(string(e.Metadata), account.subjectID) {
			t.Errorf("the tombstone METADATA names the erased subject: %s", e.Metadata)
		}
	}
	if !sawTombstone {
		t.Error("no UsernameTombstoned event reached the handle's stream")
	}

	// AND A REBUILD MUST NOT BRING IT BACK — done LAST, deliberately.
	//
	// This block used to sit above, before the claim assertions, and it stopped
	// the projectors and restarted them from a `defer`. A defer fires at function
	// EXIT, so everything between the rebuild and the end of the test ran with no
	// projector: the stranger's registration below never got a user_view row and
	// the test timed out after 30s waiting for one. Rebuilding last means the
	// defer is the correct tool again.
	//
	// This is the assertion that is easy to leave out and expensive to discover
	// missing. Every projection in this system must be reconstructable by
	// replaying from position zero, and the replay sees UsernameAssigned BEFORE
	// UsernameTombstoned — so a projector whose assign statement guarded on
	// `username IS NULL`, or whose tombstone handler was keyed by a subject the
	// event does not carry, would restore an erased person's handle every time
	// the read model was rebuilt. The erasure would be undone by routine
	// maintenance, silently, and nothing in the log would say so.
	h.cancelProjectors()
	<-h.projectorsDone
	// From a defer, not from the happy path: every later test in this package
	// needs a running projector, so a t.Fatal inside the rebuild must not take
	// the rest of the package down with it. The error is fatal rather than
	// dropped — a restart that came up as a standby leaves every later test
	// asserting against a projection this process does not advance
	// (harness.awaitLeases).
	defer func() {
		if err := h.startProjectors(); err != nil {
			t.Fatalf("the projectors could not be restarted after the rebuild: %v", err)
		}
	}()
	h.rebuild(t, identityprojection.NewUser(h.codec), h.emailIndex(t, erasedEmail))

	var afterRebuild int
	h.systemQuery(t, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx,
			`SELECT count(*) FROM user_view WHERE username = $1`, handle).Scan(&afterRebuild)
	})
	if afterRebuild != 0 {
		t.Errorf("a rebuild from position zero restored the erased handle %q to %d row(s). "+
			"The replay applies UsernameAssigned and then UsernameTombstoned in commit "+
			"order and must land on cleared; anything else means a routine rebuild undoes "+
			"an erasure (ADR-051).", handle, afterRebuild)
	}
}

// ---------------------------------------------------------------------------
// Not a login identifier
// ---------------------------------------------------------------------------

// TestAUsernameCannotBeUsedToSignIn is ADR-051's fourth decision, asserted over
// the real RPCs rather than only against the command structs.
//
// A public handle is half of a credential pair that is published on purpose.
// Accepting one at Authenticate or CreateSession would hand an attacker an
// enumerable, harvestable target list — every visible @handle becomes a login to
// spray — and would turn the per-authenticator lockout ceiling into a
// denial-of-service tool aimed at anyone whose handle can be read.
//
// The account under test is fully usable with its ADDRESS, and that half is
// asserted too: a test that only showed the handle failing would also pass if
// the whole login were broken.
func TestAUsernameCannotBeUsedToSignIn(t *testing.T) {
	ctx := context.Background()
	const password = "correct-horse-battery-staple-81"

	email := h.freshEmail("nologin")
	handle := h.freshUsername("nologin")
	account := h.registerThroughTheKernel(t, email)
	if _, err := h.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
		Token: h.mintVerificationToken(t, account.subjectID), Password: password,
		Username: handle,
	})); err != nil {
		t.Fatalf("VerifyEmail: %v\n%s", err, h.serverLogs())
	}
	h.awaitVerified(t, h.emailIndex(t, email))

	// The control: the ADDRESS works. Without this the test below would pass on a
	// server where nothing can sign in at all.
	if _, err := h.client.Authenticate(ctx, write(&identityv1.AuthenticateRequest{
		Identifier: email, Password: password, DeviceId: "dev_nologin_" + h.suffix,
	})); err != nil {
		t.Fatalf("the account cannot authenticate with its address, so this test proves "+
			"nothing: %v\n%s", err, h.serverLogs())
	}

	// The property: the HANDLE does not.
	for _, rpc := range []struct {
		name string
		call func() error
	}{
		{"Authenticate", func() error {
			_, err := h.client.Authenticate(ctx, write(&identityv1.AuthenticateRequest{
				Identifier: handle, Password: password, DeviceId: "dev_nologin2_" + h.suffix,
			}))
			return err
		}},
		{"CreateSession", func() error {
			_, err := h.client.CreateSession(ctx, write(&identityv1.CreateSessionRequest{
				Identifier: handle, Password: password, DeviceId: "dev_nologin3_" + h.suffix,
			}))
			return err
		}},
	} {
		if err := rpc.call(); err == nil {
			t.Errorf("%s accepted the public handle %q as an identifier. Every visible "+
				"@handle is then a login to spray, and the account-lockout ceiling "+
				"becomes a denial of service aimed at anyone whose handle can be read "+
				"(ADR-051).", rpc.name, handle)
		} else {
			t.Logf("%s refused the handle: code=%v", rpc.name, connectrpc.CodeOf(err))
		}
	}
}

// ---------------------------------------------------------------------------
// The account screen
// ---------------------------------------------------------------------------

// TestGetUserReturnsTheHandleAndNoAddress pins the ONE place personal data
// deliberately leaves identity's read model.
//
// GetUserResponse returns a pseudonym for everything else, and the vault resolves
// it. The handle is the exception ADR-051 records: it is published by design, so
// the vault cannot protect it and there is nothing for a pseudonym to stand in
// for. What must still be true is that the exception is exactly one field wide —
// the address must not have followed it out.
func TestGetUserReturnsTheHandleAndNoAddress(t *testing.T) {
	ctx := context.Background()
	const password = "correct-horse-battery-staple-82"

	email := h.freshEmail("screen")
	handle := h.freshUsername("screen")
	account := h.registerThroughTheKernel(t, email)
	if _, err := h.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
		Token: h.mintVerificationToken(t, account.subjectID), Password: password,
		Username: handle,
	})); err != nil {
		t.Fatalf("VerifyEmail: %v\n%s", err, h.serverLogs())
	}
	h.awaitUsernameRow(t, handle, account.subjectID)

	bearer, _ := h.bootstrapFirstFactor(t, email, password)
	resp, err := h.client.GetUser(ctx, read(&identityv1.GetUserRequest{}, bearer))
	if err != nil {
		t.Fatalf("GetUser: %v\n%s", err, h.serverLogs())
	}
	if got := resp.Msg.GetUsername(); got != handle {
		t.Errorf("GetUser returned handle %q, want %q", got, handle)
	}
	// The address did NOT follow it out. Asserted on the rendered message, over
	// the wire, because that is where a leak would actually be observable.
	if body := resp.Msg.String(); strings.Contains(body, email) {
		t.Errorf("the account screen returned the address: %s", body)
	}
}

// ---------------------------------------------------------------------------
// Harness support
// ---------------------------------------------------------------------------

// usernameClaimsFor returns the subject of every account the LOG says claimed
// this handle, in commit order.
//
// $all rather than the handle's own stream, and rather than a $et- link stream.
// The handle's stream would answer "what does the winner's stream hold", which
// is a weaker question: it cannot see a claim that landed on a DIFFERENT stream
// because a normalization bug produced two spellings of one handle. $et- is
// produced by a system projection that can lag, and this reads immediately after
// the write.
func (hh *harness) usernameClaimsFor(
	t *testing.T, username string, from kurrentdb.AllPosition,
) []string {
	t.Helper()
	var subjects []string
	hh.eachEventSince(t, from, func(eventType string, decoded any) {
		e, ok := decoded.(*contract.UsernameReserved)
		if ok && e.Username == username {
			subjects = append(subjects, e.SubjectID)
		}
	})
	return subjects
}

// subjectsVerifiedSince returns every subject the LOG says proved its address
// after a position.
func (hh *harness) subjectsVerifiedSince(
	t *testing.T, from kurrentdb.AllPosition,
) []string {
	t.Helper()
	var subjects []string
	hh.eachEventSince(t, from, func(eventType string, decoded any) {
		if e, ok := decoded.(*contract.EmailVerified); ok {
			subjects = append(subjects, e.SubjectID)
		}
	})
	return subjects
}

// eachEventSince decodes every identity event committed after a position.
//
// One reader for both helpers above, so "which events did this test cause" has
// one definition. Events this build cannot decode are skipped rather than
// fatal: $all carries the server's own index entries and other modules' events,
// and a test that stopped on them would be asserting about the log's contents
// rather than about its own work.
func (hh *harness) eachEventSince(
	t *testing.T, from kurrentdb.AllPosition, visit func(eventType string, decoded any),
) {
	t.Helper()
	rs, err := hh.kurrent.ReadAll(context.Background(), kurrentdb.ReadAllOptions{
		Direction: kurrentdb.Forwards, From: from,
	}, ^uint64(0))
	if err != nil {
		t.Fatalf("reading $all: %v", err)
	}
	defer rs.Close()

	for {
		ev, err := rs.Recv()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatalf("reading $all: %v", err)
		}
		if ev.Event == nil || !strings.HasPrefix(ev.Event.EventType, "identity.") {
			continue
		}
		decoded, err := hh.codec.Unmarshal(ev.Event.EventType, ev.Event.Data)
		if err != nil {
			continue
		}
		visit(ev.Event.EventType, decoded)
	}
}

// awaitUsernameRow waits for the projector to write the handle onto the account.
func (hh *harness) awaitUsernameRow(t *testing.T, username, subjectID string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var got string
	for time.Now().Before(deadline) {
		hh.systemQuery(t, func(ctx context.Context, q db.Querier) error {
			// COALESCE so a NULL is "" rather than a scan error, which is the state
			// this loop is waiting to leave.
			return q.QueryRow(ctx,
				`SELECT coalesce(username, '') FROM user_view WHERE subject_id = $1`,
				subjectID).Scan(&got)
		})
		if got == username {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("user_view.username for %s is %q after 30s, want %q\n%s",
		subjectID, got, username, hh.serverLogs())
}

// awaitUsernameCleared waits for the tombstone to remove the handle from the
// projection.
//
// It asks whether ANY row holds the handle, rather than asking about the erased
// subject's row: the tombstone event carries no subject, so the statement it
// drives is keyed by the handle, and asserting on the subject would be asserting
// about a link the design deliberately does not have.
func (hh *harness) awaitUsernameCleared(t *testing.T, username string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var rows int
	for time.Now().Before(deadline) {
		hh.systemQuery(t, func(ctx context.Context, q db.Querier) error {
			return q.QueryRow(ctx,
				`SELECT count(*) FROM user_view WHERE username = $1`, username).Scan(&rows)
		})
		if rows == 0 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%d user_view row(s) still hold the handle %q 30s after the tombstone. "+
		"Erasure of a handle is a DELETION and not the destruction of a key, because "+
		"the value was published — crypto-shredding does nothing to cleartext.\n%s",
		rows, username, hh.serverLogs())
}

// The domain constructor the repository rebuilds into must be the one the
// composition root uses. A second constructor here would rebuild a different
// aggregate from the same stream.
var _ = domain.NewUsernameReservation
