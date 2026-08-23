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
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/kurrent-io/KurrentDB-Client-Go/kurrentdb"
)

// ---------------------------------------------------------------------------
// Reading the account's own stream
// ---------------------------------------------------------------------------

// accountEvent is one decoded event with the log position it was committed at.
//
// The POSITION is what makes atomicity observable: a multi-stream append is one
// transaction, so everything it wrote shares a commit position, and two separate
// appends cannot.
type accountEvent struct {
	typ    string
	commit uint64
	event  eventsourcing.Event
}

// streamEvents reads one stream forwards and decodes it with the production
// codec.
func (hh *harness) streamEvents(t *testing.T, stream string) []accountEvent {
	t.Helper()
	rs, err := hh.kurrent.ReadStream(context.Background(), stream,
		kurrentdb.ReadStreamOptions{Direction: kurrentdb.Forwards, From: kurrentdb.Start{}},
		^uint64(0))
	if err != nil {
		t.Fatalf("reading %s: %v", stream, err)
	}
	defer rs.Close()

	var out []accountEvent
	for {
		ev, err := rs.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var kerr *kurrentdb.Error
			if errors.As(err, &kerr) && kerr.Code() == kurrentdb.ErrorCodeResourceNotFound {
				return nil
			}
			t.Fatalf("reading %s: %v", stream, err)
		}
		if ev.Event == nil {
			continue
		}
		decoded, decErr := hh.codec.Unmarshal(ev.Event.EventType, ev.Event.Data)
		if decErr != nil {
			t.Fatalf("decoding %s on %s: %v", ev.Event.EventType, stream, decErr)
		}
		out = append(out, accountEvent{
			typ:    ev.Event.EventType,
			commit: ev.Event.Position.Commit,
			event:  decoded,
		})
	}
	return out
}

// accountStream reads the account's own stream.
func (hh *harness) accountStream(t *testing.T, userID string) []accountEvent {
	t.Helper()
	return hh.streamEvents(t, string(eventsourcing.MustStreamID(app.UserCategory, userID)))
}

// lifecycleTypes reduces a stream to the account-lifecycle events, in order.
func lifecycleTypes(events []accountEvent) []string {
	var out []string
	for _, e := range events {
		switch e.event.(type) {
		case *contract.UserRegistered, *contract.UserActivated, *contract.UserDeactivated,
			*contract.UserReactivated, *contract.UserSuspended,
			*contract.UserDeletionRequested:
			out = append(out, e.typ)
		}
	}
	return out
}

func countType[T eventsourcing.Event](events []accountEvent) int {
	var n int
	for _, e := range events {
		if _, ok := e.event.(T); ok {
			n++
		}
	}
	return n
}

// signedIn is one live session established over the real login path.
type signedIn struct {
	bearer    string
	sessionID string
}

// signIn completes an ordinary two-factor login over HTTP.
func (hh *harness) signIn(t *testing.T, email, password, secret string) signedIn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	res, err := hh.client.CreateSession(ctx, write(&identityv1.CreateSessionRequest{
		Identifier: email,
		Password:   password,
		Code:       hh.freshCode(t, secret),
		DeviceId:   "dev_life_" + hh.suffix,
	}))
	if err != nil {
		t.Fatalf("CreateSession: %v\n%s", err, hh.serverLogs())
	}
	if got := res.Msg.GetAssuranceLevel(); got.String() != "ASSURANCE_LEVEL_2" {
		t.Fatalf("the session is %v, want AAL2", got)
	}
	hh.awaitSessionProjected(t, res.Msg.GetSessionId())
	return signedIn{bearer: res.Msg.GetToken(), sessionID: res.Msg.GetSessionId()}
}

// awaitSessionProjected blocks until the session the API just minted is
// RESOLVABLE, and measures how long that took.
//
// # The window it measures is real
//
// A session has two halves written by two different things. CreateSession
// appends SessionCreated and then writes `session_token` itself — the digest and
// the idle deadline are not in the log (IDENTITY-SLICE-1) — while the other half,
// `session_view`, is written by the identity_session PROJECTOR. Migration 00010
// split them exactly so a session resolves only when BOTH exist, and
// GetSessionByToken joins them. So between CreateSession returning and the
// projector applying the event, the bearer token the caller is holding
// authenticates NOTHING and every request with it is
// `unauthenticated: authentication failed`.
//
// # What it is NOT: it is not the cause of the reactivation flake
//
// This was added while investigating TestADeactivatedAccountCanGetBackIn, whose
// failure is exactly that message on a token CreateSession had just returned,
// and the window above was the obvious suspect. It was measured rather than
// assumed, and the measurement REFUTED it: across 14 sign-ins — one whole suite
// alone and one run concurrent with six other integration packages against the
// same Postgres — the projection was resolvable in 1ms, worst case 2ms. That is
// not a window a test loses two runs in five to.
//
// So the flake's cause is still OPEN and is recorded as such in
// IDENTITY-SLICE-1. What this function is worth keeping for is what it does
// after eliminating that hypothesis: it costs ~1ms, it removes one whole class
// of cause from every later investigation, and if the window ever does grow it
// says so with a number instead of failing somewhere else with
// "authentication failed".
func (hh *harness) awaitSessionProjected(t *testing.T, sessionID string) {
	t.Helper()
	started := time.Now()
	deadline := started.Add(30 * time.Second)
	for {
		var n int
		hh.systemQuery(t, func(ctx context.Context, q db.Querier) error {
			return q.QueryRow(ctx,
				`SELECT count(*) FROM session_view WHERE session_id = $1`, sessionID).Scan(&n)
		})
		if n > 0 {
			// 250ms is two orders of magnitude above every measurement taken so
			// far, so a line here means the window has changed character and the
			// paragraph above needs re-measuring rather than re-reading.
			if waited := time.Since(started); waited > 250*time.Millisecond {
				t.Logf("the session projection took %s to make session %s resolvable",
					waited.Round(time.Millisecond), sessionID)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("session %s was minted 30s ago and session_view still has no row for "+
				"it; its bearer token authenticates nothing", sessionID)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// lifecycleAccount builds an ACTIVE account and signs it in once.
//
// Everything after the fixture step goes over HTTP through the production
// handlers, which is the whole point of this package.
type lifecycleAccount struct {
	email     string
	password  string
	secret    string
	index     string
	subjectID string
	userID    string
}

func (hh *harness) lifecycleAccount(t *testing.T, tag string) lifecycleAccount {
	t.Helper()
	email := hh.freshEmail(tag)
	const password = "correct-horse-battery-staple-51"

	row := hh.registerThroughTheKernel(t, email)
	index := hh.emailIndex(t, email)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := hh.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
		Token:    hh.mintVerificationToken(t, row.subjectID),
		Password: password,
		Username: hh.freshUsername("life"),
	})); err != nil {
		t.Fatalf("VerifyEmail: %v\n%s", err, hh.serverLogs())
	}
	_, secret := hh.bootstrapFirstFactor(t, email, password)
	hh.awaitState(t, index, "active")

	return lifecycleAccount{
		email: email, password: password, secret: secret,
		index: index, subjectID: row.subjectID, userID: row.userID,
	}
}

// ---------------------------------------------------------------------------
// The property this whole vertical turns on
// ---------------------------------------------------------------------------

// A deactivated account can actually get back in.
//
// # Why this test exists at all
//
// identity.md §1 says deactivation is reversible by the holder. Before this
// change, `CanAuthenticate` refused a deactivated account and every authenticated
// RPC needed a session — so "reversible" named no code, and nothing anywhere in
// the repository would have said so. That is the shape of the enrolment deadlock
// this codebase already hit once: a gate whose precondition its own subject
// cannot satisfy.
//
// So the assertion is not "Deactivate returns 200". It is: switch the account
// off through the real RPC, watch the bearer token stop working, sign in again
// with the same credentials, and get a WORKING session for an ACTIVE account.
// Every step is over HTTP against cmd/api, through the production interceptor
// chain and the production projectors.
func TestADeactivatedAccountCanGetBackIn(t *testing.T) {
	// Parallel: this package is bounded by TOTP step boundaries, not by CPU, and a
	// sequential run of the lifecycle tests pushed it past the ten minute go test
	// timeout. Each test drives its OWN account and freshCode is keyed per secret,
	// so nothing here waits on anything another test is doing.
	t.Parallel()

	ctx := context.Background()
	acct := h.lifecycleAccount(t, "reactivate")
	first := h.signIn(t, acct.email, acct.password, acct.secret)

	// The session works before the deactivation, so the refusal below is
	// attributable to the deactivation rather than to a token that never worked.
	if _, err := h.client.GetUser(ctx, read(&identityv1.GetUserRequest{}, first.bearer)); err != nil {
		t.Fatalf("GetUser before the deactivation: %v\n%s", err, h.serverLogs())
	}

	// --- switch it off -----------------------------------------------------
	deact, err := h.client.DeactivateAccount(ctx,
		writeAuth(&identityv1.DeactivateAccountRequest{}, first.bearer))
	if err != nil {
		t.Fatalf("DeactivateAccount: %v\n%s", err, h.serverLogs())
	}
	if !deact.Msg.GetChanged() {
		t.Error("the deactivation reported no change on an active account")
	}
	if deact.Msg.GetSessionsRevoked() < 1 {
		t.Errorf("the deactivation revoked %d sessions; the caller's own session must be "+
			"among them, or the account is off everywhere except where it was switched off",
			deact.Msg.GetSessionsRevoked())
	}
	t.Logf("deactivated: changed=%v revoked=%d scanned=%d", deact.Msg.GetChanged(),
		deact.Msg.GetSessionsRevoked(), deact.Msg.GetSessionsScanned())

	// WAIT FOR THE REVOCATION TO PROJECT before asserting the token is dead.
	//
	// The revocation is an APPEND; `GetSessionByToken` reads `revoked_at` from
	// `session_view`, which is a PROJECTION. So there is a window in which
	// DeactivateAccount has returned and the bearer still authenticates — and
	// asserting immediately races it. Under load the projector is far enough
	// behind to land inside that window, and the failure reads as "deactivation
	// does not revoke sessions" when the revocation is recorded and simply not
	// applied yet.
	//
	// This is the same shape as the password-reset flake fixed earlier in this
	// suite: a projection-derived auth decision asserted immediately after the
	// append that changes it. It is a strong candidate for the intermittent
	// failure this test has been parked on — parked because it did not reproduce,
	// which is exactly what a narrow timing window does.
	h.awaitLiveSessions(t, acct.subjectID, func(n int) bool { return n == 0 },
		"none, because the deactivation revoked them")

	// The bearer that made the call is dead. This is the assertion that would
	// still pass if the revocation had been skipped ONLY IF the authenticator
	// checked account state — it does not (GetSessionByToken joins user_view for
	// the enrolment column alone), so this is a real check of the revocation.
	if _, err := h.client.GetUser(ctx, read(&identityv1.GetUserRequest{}, first.bearer)); err == nil {
		t.Fatal("the session that switched the account off still works; nothing in the " +
			"request pipeline reads an account's state, so that session has full API access")
	} else if code := connectrpc.CodeOf(err); code != connectrpc.CodeUnauthenticated {
		t.Errorf("the revoked session was refused with %v, want unauthenticated", code)
	}
	h.awaitState(t, acct.index, "deactivated")

	// --- and back in -------------------------------------------------------
	//
	// The SAME credentials, presented in full. Nothing is relaxed: the account
	// still owes its second factor, and only a completed ceremony reactivates.
	second := h.signIn(t, acct.email, acct.password, acct.secret)
	if second.bearer == first.bearer {
		t.Fatal("the second login returned the first login's token")
	}
	if _, err := h.client.GetUser(ctx, read(&identityv1.GetUserRequest{}, second.bearer)); err != nil {
		t.Fatalf("GetUser after signing back in: %v\n%s\n"+
			"the account is deactivated with no route back into it", err, h.serverLogs())
	}
	state := h.awaitState(t, acct.index, "active")
	t.Logf("after signing back in the account is %q", state)

	// And the LOG says so, in the right order. The projection is derived; the log
	// is the fact.
	events := h.accountStream(t, acct.userID)
	got := lifecycleTypes(events)
	want := []string{
		(&contract.UserRegistered{}).EventType(),
		(&contract.UserActivated{}).EventType(),
		(&contract.UserDeactivated{}).EventType(),
		(&contract.UserReactivated{}).EventType(),
	}
	if len(got) != len(want) {
		t.Fatalf("the account stream holds %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("the account stream holds %v, want %v", got, want)
		}
	}

	// --- and the notification path ----------------------------------------
	//
	// cmd/worker's catalogue has entries for both of these — Security class, to
	// the subject, with `ByAnotherParty` derived from the event's ActorID — and
	// neither has ever fired, for exactly one reason: nothing emitted the events.
	// That is what this change fixes, so the last thing to check is that what now
	// reaches the log is the shape the catalogue reads:
	//
	//   - the production codec decodes it (an event the codec cannot decode is
	//     skipped by the reactor with no error, no metric and no log line),
	//   - its type carries the "identity." prefix the reactor's filter selects on,
	//   - and both fields the catalogue's Data function reads are populated.
	//
	// The last hop, reactor to Mailpit, is exercised by
	// TestIdentitySecurityAlertsReachMailpit in cmd/worker, which this change may
	// not edit; the accompanying report names the two rows it needs.
	for _, e := range events {
		if !strings.HasPrefix(e.typ, "identity.") {
			t.Errorf("%s does not carry the identity. prefix the notification reactor's "+
				"subscription filter selects on", e.typ)
		}
		var subject, actor string
		switch ev := e.event.(type) {
		case *contract.UserDeactivated:
			subject, actor = ev.SubjectID, ev.ActorID
		case *contract.UserReactivated:
			subject, actor = ev.SubjectID, ev.ActorID
		default:
			continue
		}
		if subject != acct.subjectID {
			t.Errorf("%s names subject %q, want %q — the audience resolver has nobody to "+
				"mail otherwise", e.typ, subject, acct.subjectID)
		}
		if actor != acct.subjectID {
			t.Errorf("%s names actor %q, want the holder's own pseudonym %q; the catalogue "+
				"renders ByAnotherParty from exactly this comparison",
				e.typ, actor, acct.subjectID)
		}
	}
}

// A password alone does not bring a deactivated account back.
//
// The carve-out admits the ceremony; it does not shorten it. Without this, a
// stolen password would undo the very step a worried owner took — and the owner
// took it precisely because they were worried about that password.
func TestAPasswordAloneDoesNotReactivate(t *testing.T) {
	// Parallel: this package is bounded by TOTP step boundaries, not by CPU, and a
	// sequential run of the lifecycle tests pushed it past the ten minute go test
	// timeout. Each test drives its OWN account and freshCode is keyed per secret,
	// so nothing here waits on anything another test is doing.
	t.Parallel()

	ctx := context.Background()
	acct := h.lifecycleAccount(t, "reactivate-1fa")
	session := h.signIn(t, acct.email, acct.password, acct.secret)

	if _, err := h.client.DeactivateAccount(ctx,
		writeAuth(&identityv1.DeactivateAccountRequest{}, session.bearer)); err != nil {
		t.Fatalf("DeactivateAccount: %v\n%s", err, h.serverLogs())
	}
	h.awaitState(t, acct.index, "deactivated")

	// CreateSession with no code. The app layer answers an incomplete ceremony
	// with the same undifferentiated refusal it gives a wrong password (ADR-036),
	// so what is asserted is the REFUSAL and the account's state afterwards.
	_, err := h.client.CreateSession(ctx, write(&identityv1.CreateSessionRequest{
		Identifier: acct.email, Password: acct.password,
		DeviceId: "dev_1fa_" + h.suffix,
	}))
	if err == nil {
		t.Fatal("a password-only login minted a session for a deactivated account")
	}
	t.Logf("password-only login on a deactivated account refused: %v", connectrpc.CodeOf(err))

	if state := h.awaitState(t, acct.index, "deactivated"); state != "deactivated" {
		t.Fatalf("the account is %q after a password-only attempt, want deactivated", state)
	}
	if n := countType[*contract.UserReactivated](h.accountStream(t, acct.userID)); n != 0 {
		t.Fatalf("a password-only attempt appended %d reactivations", n)
	}
}

// ---------------------------------------------------------------------------
// Atomicity and contention
// ---------------------------------------------------------------------------

// A deactivation leaves NO live session, and the account event leads the append.
//
// # Why this is not the "one atomic append" assertion
//
// That claim is provable where the appender can be observed —
// TestDeactivationAndItsRevocationsAreOneAtomicAppend in the app package asserts
// exactly one AppendToMany call, and a mutation that splits the write into two
// fails it. It is NOT soundly provable from the log: the obvious probes both
// fail against a correct implementation. A shared commit position is not a
// property of atomicity — KurrentDB's MultiStreamAppend returns one position for
// the transaction while the events carry their own, measured here at 695823
// beside 696384 and 697023 from one write. And contiguity in `$all` is real but
// not deterministic, because `go test ./...` runs other integration packages
// against the same log and their writes can legitimately land in the gap.
//
// So this asserts the CONSEQUENCE, which is deterministic and is the thing that
// actually matters: after the call, no session on the account resolves, every one
// that was live is revoked under the deactivation's own reason, and the account
// event leads the events this write added — the order the entry list is built in.
func TestADeactivationLeavesNoLiveSession(t *testing.T) {
	ctx := context.Background()
	acct := h.lifecycleAccount(t, "sweep")

	// Two live sessions, so the write spans three streams rather than two: the one
	// signed in here plus the bootstrap session the first enrolment minted, which
	// is an ordinary revocable session.
	session := h.signIn(t, acct.email, acct.password, acct.secret)
	// AWAITED. session_view is a projection, so a login that has returned its
	// bearer is not yet a row — and reading once here failed intermittently under
	// a full-package run, reporting "the account holds 1 live session" about an
	// account that held two.
	h.awaitLiveSessions(t, acct.subjectID,
		func(n int) bool { return n >= 2 },
		"at least 2 — this test would otherwise prove nothing about a fan-out")

	from := h.logTail(t)
	res, err := h.client.DeactivateAccount(ctx,
		writeAuth(&identityv1.DeactivateAccountRequest{}, session.bearer))
	if err != nil {
		t.Fatalf("DeactivateAccount: %v\n%s", err, h.serverLogs())
	}
	if res.Msg.GetSessionsRevoked() < 2 {
		t.Fatalf("revoked %d sessions, want at least 2", res.Msg.GetSessionsRevoked())
	}

	// The observable consequence. Nothing in the request pipeline reads an
	// account's state, so a session that survives here has full API access to an
	// account its holder has been told is off.
	h.awaitState(t, acct.index, "deactivated")
	// Awaited, not read once. user_view and session_view are written by two
	// projectors with two checkpoints, so "the account says deactivated" is no
	// evidence at all that the session projector has caught up — and this
	// assertion failed exactly that way, intermittently, once the package grew
	// enough other events to widen the window.
	h.awaitLiveSessions(t, acct.subjectID, func(n int) bool { return n == 0 }, "none")

	// And the account event LEADS what this write added, which is the order the
	// entry list is built in: the decision before its consequences.
	mine := h.eventsSince(t, from, acct.subjectID)
	if len(mine) == 0 {
		t.Fatal("the deactivation added nothing this account can be seen in")
	}
	if got := mine[0].typ; got != (&contract.UserDeactivated{}).EventType() {
		t.Errorf("the first event this write added is %s, want UserDeactivated: %v",
			got, typesOf(mine))
	}
	var revocations int
	for _, e := range mine[1:] {
		r, ok := e.event.(*contract.SessionRevoked)
		if !ok {
			t.Errorf("the write added %s beside the deactivation: %v", e.typ, typesOf(mine))
			continue
		}
		revocations++
		if r.Reason != app.RevokeReasonDeactivated {
			t.Errorf("session %s was revoked for %q, want %q — a person reading their own "+
				"security history is told which of the three things that void sessions "+
				"happened", r.SessionID, r.Reason, app.RevokeReasonDeactivated)
		}
	}
	if revocations != int(res.Msg.GetSessionsRevoked()) {
		t.Errorf("the log holds %d revocations and the call reported %d",
			revocations, res.Msg.GetSessionsRevoked())
	}
	t.Logf("$all gained %v for this account", typesOf(mine))
}

// eventsSince reads the events $all gained after a marker FOR ONE SUBJECT.
//
// Scoped to the subject because `go test ./...` runs several integration
// packages against the same log: an unfiltered read would pick up whatever
// another package happened to write while this one was calling.
//
// $all rather than a link stream: $all is the log itself and is consistent the
// moment the append returns, while a $et- stream is produced by a system
// projection that can lag.
func (hh *harness) eventsSince(
	t *testing.T, from kurrentdb.AllPosition, subjectID string,
) []accountEvent {
	t.Helper()
	rs, err := hh.kurrent.ReadAll(context.Background(), kurrentdb.ReadAllOptions{
		Direction: kurrentdb.Forwards, From: from,
	}, ^uint64(0))
	if err != nil {
		t.Fatalf("reading $all: %v", err)
	}
	defer rs.Close()

	var out []accountEvent
	for {
		ev, err := rs.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reading $all: %v", err)
		}
		// System events are the server's own index entries, not writes anybody made.
		if ev.Event == nil || strings.HasPrefix(ev.Event.EventType, "$") {
			continue
		}
		decoded, decErr := hh.codec.Unmarshal(ev.Event.EventType, ev.Event.Data)
		if decErr != nil {
			// Another package's event type this codec does not register. Not this
			// test's concern and not a failure.
			continue
		}
		if subjectOf(decoded) != subjectID {
			continue
		}
		out = append(out, accountEvent{
			typ:    ev.Event.EventType,
			commit: ev.Event.Position.Commit,
			event:  decoded,
		})
	}
	return out
}

// subjectOf reports the pseudonym an identity event names, for the few types
// this file filters on.
func subjectOf(e eventsourcing.Event) string {
	switch v := e.(type) {
	case *contract.UserDeactivated:
		return v.SubjectID
	case *contract.UserReactivated:
		return v.SubjectID
	case *contract.UserDeletionRequested:
		return v.SubjectID
	case *contract.SessionRevoked:
		return v.SubjectID
	case *contract.SessionCreated:
		return v.SubjectID
	}
	return ""
}

func typesOf(events []accountEvent) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, strings.TrimPrefix(e.typ, "identity."))
	}
	return out
}

// Concurrent deactivations produce exactly ONE UserDeactivated.
//
// Each call carries its own idempotency key, so the gate cannot collapse them
// before KurrentDB sees them — the contention is real and is resolved by the
// expected-revision precondition on the account stream, which is the only thing
// standing between four simultaneous clicks and four deactivations in a permanent
// log.
func TestConcurrentDeactivationsAppendExactlyOne(t *testing.T) {
	// Parallel: this package is bounded by TOTP step boundaries, not by CPU, and a
	// sequential run of the lifecycle tests pushed it past the ten minute go test
	// timeout. Each test drives its OWN account and freshCode is keyed per secret,
	// so nothing here waits on anything another test is doing.
	t.Parallel()

	ctx := context.Background()
	acct := h.lifecycleAccount(t, "concurrent-deact")

	// ONE session issuing four concurrent calls, rather than four sessions. The
	// contention under test is on the ACCOUNT STREAM, which is keyed by the
	// account and not by the caller — and a second login costs a real TOTP step
	// boundary, which is thirty seconds of wall clock per racer for no extra
	// coverage.
	const racers = 4
	session := h.signIn(t, acct.email, acct.password, acct.secret)

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		changed int
		errs    []error
	)
	start := make(chan struct{})
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			res, err := h.client.DeactivateAccount(ctx,
				writeAuth(&identityv1.DeactivateAccountRequest{}, session.bearer))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			if res.Msg.GetChanged() {
				changed++
			}
		}()
	}
	close(start)
	wg.Wait()

	for _, err := range errs {
		// A loser may be refused: its whole append is rolled back, and a
		// deactivation that lost the race is a CONFLICT the caller retries. A
		// revoked session's call is UNAUTHENTICATED, which is also expected — the
		// winner revoked it.
		code := connectrpc.CodeOf(err)
		if code != connectrpc.CodeAborted && code != connectrpc.CodeUnauthenticated &&
			code != connectrpc.CodeFailedPrecondition && code != connectrpc.CodeAlreadyExists {
			t.Errorf("a racing deactivation failed with %v (%v), which is neither a lost "+
				"precondition nor a revoked session", code, err)
		}
	}
	if changed > 1 {
		t.Errorf("%d of %d calls reported that THEY switched the account off; at most one "+
			"may", changed, racers)
	}

	events := h.accountStream(t, acct.userID)
	if n := countType[*contract.UserDeactivated](events); n != 1 {
		t.Fatalf("the account stream holds %d UserDeactivated events, want exactly 1 — the "+
			"expected-revision precondition on the account stream is what makes that true",
			n)
	}
	h.awaitState(t, acct.index, "deactivated")
	t.Logf("%d concurrent deactivations, %d reported the change, 1 event in the log",
		racers, changed)
}

// A deactivation racing a login leaves the log coherent.
//
// The two touch the same account stream — the deactivation always, the login only
// when it reactivates — so the outcomes are constrained rather than arbitrary.
// Whatever the interleaving, the account's lifecycle events must READ as a valid
// history and the projection must agree with the last one.
func TestADeactivationRacingALoginDoesNotTear(t *testing.T) {
	// Parallel: this package is bounded by TOTP step boundaries, not by CPU, and a
	// sequential run of the lifecycle tests pushed it past the ten minute go test
	// timeout. Each test drives its OWN account and freshCode is keyed per secret,
	// so nothing here waits on anything another test is doing.
	t.Parallel()

	ctx := context.Background()
	acct := h.lifecycleAccount(t, "race-login")
	session := h.signIn(t, acct.email, acct.password, acct.secret)

	// The login's code is drawn BEFORE the race so the goroutine does not spend
	// seconds waiting for a TOTP step boundary while the deactivation runs alone.
	code := h.freshCode(t, acct.secret)

	var wg sync.WaitGroup
	wg.Add(2)
	start := make(chan struct{})
	go func() {
		defer wg.Done()
		<-start
		_, err := h.client.DeactivateAccount(ctx,
			writeAuth(&identityv1.DeactivateAccountRequest{}, session.bearer))
		t.Logf("racing deactivation: err=%v", err)
	}()
	go func() {
		defer wg.Done()
		<-start
		_, err := h.client.CreateSession(ctx, write(&identityv1.CreateSessionRequest{
			Identifier: acct.email, Password: acct.password, Code: code,
			DeviceId: "dev_race_" + h.suffix,
		}))
		t.Logf("racing login: err=%v", err)
	}()
	close(start)
	wg.Wait()

	// Whatever happened, the stream must be a valid history: the state machine
	// never records two deactivations in a row, and never a reactivation that does
	// not follow one.
	events := h.accountStream(t, acct.userID)
	state := "active"
	for _, e := range events {
		switch e.event.(type) {
		case *contract.UserDeactivated:
			if state == "deactivated" {
				t.Fatalf("the account stream deactivates an already-deactivated account: %v",
					lifecycleTypes(events))
			}
			state = "deactivated"
		case *contract.UserReactivated:
			if state != "deactivated" {
				t.Fatalf("the account stream reactivates an account that is not deactivated: %v",
					lifecycleTypes(events))
			}
			state = "active"
		}
	}
	t.Logf("after the race the log says %q: %v", state, lifecycleTypes(events))

	// And the projection agrees with the log. A disagreement here is the tear:
	// the row and the stream describing different accounts.
	if got := h.awaitState(t, acct.index, state); got != state {
		t.Fatalf("user_view says %q and the log says %q", got, state)
	}

	// # The residual window, measured rather than assumed
	//
	// If the deactivation won, a login whose ceremony had already passed the
	// account load can still mint a session AFTER the revocation's work list was
	// taken. Closing that exactly would need a cross-stream precondition on a
	// stream the login writes no event to, and the append API refuses an entry
	// with no events — so the window is real and bounded rather than absent.
	//
	// It is not a privilege gap under this design: that session grants nothing the
	// same credentials could not obtain by signing in a second later, which would
	// reactivate the account and say so by mail. It IS an incoherence, and the
	// recoveries are the next DeactivateAccount (which sweeps on the idempotent
	// path for exactly this reason), RevokeAllSessions, and the session's own idle
	// deadline.
	//
	// Logged, never asserted: a live session here is legal and so is none, and a
	// test that demanded one answer would be flaky in whichever direction the
	// scheduler happened to fall.
	if state == "deactivated" {
		t.Logf("residual window: %d live session(s) survived the deactivation that raced "+
			"this login", h.liveSessionCount(t, acct.subjectID))
	}
}

// ---------------------------------------------------------------------------
// The deletion request
// ---------------------------------------------------------------------------

// A deletion request is appended, projected, idempotent, and signs nobody out.
//
// It also stops there, and the test says so: nothing consumes the event, because
// the compliance domain does not exist. See the report accompanying this change.
func TestRequestAccountDeletion(t *testing.T) {
	// Parallel: this package is bounded by TOTP step boundaries, not by CPU, and a
	// sequential run of the lifecycle tests pushed it past the ten minute go test
	// timeout. Each test drives its OWN account and freshCode is keyed per secret,
	// so nothing here waits on anything another test is doing.
	t.Parallel()

	ctx := context.Background()
	acct := h.lifecycleAccount(t, "deletion")
	session := h.signIn(t, acct.email, acct.password, acct.secret)

	// The typed confirmation is enforced by protovalidate, as an interceptor,
	// before the handler runs. Asserted over the real server because the schema
	// rule is the only thing carrying it — there is no check in Go to fall back on.
	for _, bad := range []string{"", "delete", "DELETE ", "yes"} {
		_, err := h.client.RequestAccountDeletion(ctx,
			writeAuth(&identityv1.RequestAccountDeletionRequest{Confirmation: bad},
				session.bearer))
		if err == nil {
			t.Errorf("the confirmation %q was accepted; only the exact literal may be", bad)
			continue
		}
		if code := connectrpc.CodeOf(err); code != connectrpc.CodeInvalidArgument {
			t.Errorf("the confirmation %q was refused with %v, want invalid_argument", bad, code)
		}
	}

	res, err := h.client.RequestAccountDeletion(ctx,
		writeAuth(&identityv1.RequestAccountDeletionRequest{Confirmation: "DELETE"},
			session.bearer))
	if err != nil {
		t.Fatalf("RequestAccountDeletion: %v\n%s", err, h.serverLogs())
	}
	if !res.Msg.GetChanged() {
		t.Error("the first deletion request reported no change")
	}
	due := res.Msg.GetScheduledFor().AsTime()
	if until := time.Until(due); until < 29*24*time.Hour {
		t.Errorf("erasure falls due in %s; the grace period is meant to be the 30-day "+
			"statutory clock", until)
	}
	t.Logf("deletion requested, due %s", due.Format(time.RFC3339))

	// The session SURVIVES. Every other destructive call in this module voids
	// sessions; this one must not, because the grace period exists so the person
	// can change their mind and an account that still works must not sign them out.
	if _, err := h.client.GetUser(ctx, read(&identityv1.GetUserRequest{}, session.bearer)); err != nil {
		t.Fatalf("the session was revoked by a deletion REQUEST: %v", err)
	}

	// The projector wrote it, so a rebuild will reproduce it.
	requested, scheduled := h.awaitDeletionRequest(t, acct.subjectID)
	if !scheduled.Equal(due.UTC()) {
		t.Errorf("user_view holds the deadline %s and the response said %s", scheduled, due)
	}
	t.Logf("projected: requested_at=%s scheduled_for=%s", requested, scheduled)

	// And it reaches the account screen, as timestamps rather than as a state:
	// the account still works, and every other endpoint keeps serving it.
	got, err := h.client.GetUser(ctx, read(&identityv1.GetUserRequest{}, session.bearer))
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.Msg.GetDeletionScheduledFor() == nil {
		t.Error("GetUser does not report the outstanding deletion request")
	}
	if got.Msg.GetState() != identityv1.AccountState_ACCOUNT_STATE_ACTIVE {
		t.Errorf("the account reads as %v after a deletion REQUEST; nothing has erased it, "+
			"and every other endpoint will keep serving it", got.Msg.GetState())
	}

	// A second request keeps the FIRST deadline. Otherwise anyone holding the
	// session pushes erasure out forever, and the date already mailed is wrong.
	again, err := h.client.RequestAccountDeletion(ctx,
		writeAuth(&identityv1.RequestAccountDeletionRequest{Confirmation: "DELETE"},
			session.bearer))
	if err != nil {
		t.Fatalf("the second RequestAccountDeletion: %v", err)
	}
	if again.Msg.GetChanged() {
		t.Error("a repeated deletion request reported a change")
	}
	if !again.Msg.GetScheduledFor().AsTime().Equal(due) {
		t.Errorf("the deadline moved from %s to %s", due, again.Msg.GetScheduledFor().AsTime())
	}
	if n := countType[*contract.UserDeletionRequested](h.accountStream(t, acct.userID)); n != 1 {
		t.Fatalf("the account stream holds %d deletion requests, want exactly 1", n)
	}
}

// awaitDeletionRequest waits for the projector to record the request.
func (hh *harness) awaitDeletionRequest(t *testing.T, subjectID string) (time.Time, time.Time) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		var requested, scheduled *time.Time
		hh.systemQuery(t, func(ctx context.Context, q db.Querier) error {
			return q.QueryRow(ctx,
				`SELECT deletion_requested_at, deletion_scheduled_for
				 FROM user_view WHERE subject_id = $1`, subjectID).
				Scan(&requested, &scheduled)
		})
		if requested != nil && scheduled != nil {
			return requested.UTC(), scheduled.UTC()
		}
		if time.Now().After(deadline) {
			t.Fatalf("user_view still holds no deletion request for %s after 30s; the "+
				"projector never applied UserDeletionRequested\n%s", subjectID, hh.serverLogs())
		}
		time.Sleep(200 * time.Millisecond)
	}
}
