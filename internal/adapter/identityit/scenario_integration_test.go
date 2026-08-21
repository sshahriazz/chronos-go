//go:build integration

package identityit_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/token"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/server/interceptor"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TestIdentitySliceEndToEnd drives one account from "does not exist" to
// "authenticated, then revoked", entirely over HTTP against the real server.
//
// The value is not in any single assertion — every one of them is covered by a
// unit test somewhere — it is in the SEQUENCE. Each step consumes something the
// previous step produced through a different subsystem: the projector's row,
// the vault's ciphertext, the credential table's verifier, the sealed TOTP
// secret, the session_token digest, the interceptor's resolution of that
// digest. A break at any seam is invisible to every test that owns one side of
// it.
func TestIdentitySliceEndToEnd(t *testing.T) {
	ctx := context.Background()
	email := h.freshEmail("e2e")
	const password = "correct-horse-battery-staple-47"

	// --- 1. Register -------------------------------------------------------
	//
	// The response is deliberately empty (see RegisterResponse): success and
	// "already taken" are indistinguishable on the wire, which is the whole
	// point of the flow. So the only honest way to learn what happened is to
	// look at what the server WROTE — and even that cannot be looked up by
	// address, because no column holds one. The lookup key is the blind index,
	// computed here with the same key the server was started with.
	//
	// The public call is made, and it succeeds — but the account it creates
	// cannot be loaded by any later command, because its events are stored at
	// schema version 0 (TestIdentityEventsCarryTheirSchemaVersion). So the
	// account this scenario CONTINUES with is built by
	// registerThroughTheKernel, which is the same domain code saved through the
	// kernel's own append path. Both calls are made deliberately: the public one
	// so this test still covers the real handler, the fixture one so steps 3
	// through 7 are reachable at all.
	if _, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: email,
	})); err != nil {
		t.Fatalf("Register: %v\n%s", err, h.serverLogs())
	}
	public := h.awaitAccount(t, h.emailIndex(t, email))
	if public.state != "pending" {
		t.Errorf("a freshly registered account is %q, want pending", public.state)
	}
	t.Logf("public Register: subject=%s user=%s state=%s",
		public.subjectID, public.userID, public.state)

	usable := h.freshEmail("e2e-usable")
	index := h.emailIndex(t, usable)
	account := h.registerThroughTheKernel(t, usable)
	if account.state != "pending" {
		t.Errorf("a freshly registered account is %q, want pending", account.state)
	}
	email = usable

	// --- 2. VerifyEmail ----------------------------------------------------
	//
	// See mintVerificationToken: nothing in production mints one, so the test
	// does it through the production minter and the production TokenStore port.
	plaintext := h.mintVerificationToken(t, account.subjectID)

	// The public handle is claimed HERE, in the same request as the proof and the
	// first password (ADR-051). It is mandatory: a request without one is refused
	// by protovalidate before this handler runs.
	username := h.freshUsername("scenario")
	verified, err := h.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
		Token:    plaintext,
		Password: password,
		Username: username,
	}))
	if err != nil {
		t.Fatalf("VerifyEmail: %v\n%s", err, h.serverLogs())
	}
	if got := verified.Msg.GetSubjectId(); got != account.subjectID {
		t.Errorf("VerifyEmail returned subject %q, want %q", got, account.subjectID)
	}
	if !verified.Msg.GetChanged() {
		t.Error("VerifyEmail reported no change on a first verification")
	}
	t.Logf("verified: subject=%s user=%s changed=%v",
		verified.Msg.GetSubjectId(), verified.Msg.GetUserId(), verified.Msg.GetChanged())

	// The same token a second time is refused. Single-use is the property that
	// makes an intercepted link worthless after it has been followed once, and
	// it lives in one SQL statement (DELETE ... RETURNING) rather than in Go.
	if _, err := h.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
		Token: plaintext, Password: password, Username: h.freshUsername("replay"),
	})); err == nil {
		t.Error("a spent verification token was accepted a second time")
	} else {
		t.Logf("replayed verification token refused: %v", err)
	}

	// --- 3. EnrollTotp / ConfirmTotp ---------------------------------------
	//
	// A verified account with no factor mints one AAL1 session and uses it to
	// enrol. That the session cannot enrol a SECOND factor once this one is
	// confirmed is asserted by TestFirstFactorBootstrapClosesBehindItself.
	//
	// # This test, and only this test, waits out its step boundaries
	//
	// Every other test in the package pushes the server's clock forward instead
	// (ADR-054), which is what took the suite from four minutes to one. This one
	// keeps the wall clock, and it was chosen rather than a new test written for
	// the purpose because it is the package's END-TO-END proof: one account
	// driven from "does not exist" to "authenticated, then revoked" through the
	// deployed interceptor chain. If any test in this repository has to be true
	// of the server AS DEPLOYED — where no control exists and thirty seconds is
	// thirty seconds — it is this one.
	//
	// The property it keeps alive is narrow and would otherwise be asserted
	// nowhere: real elapsed seconds roll a TOTP step over on the real server.
	// Convert this last caller and the whole suite would still pass on a build
	// where TOTP verification had quietly stopped following the wall clock.
	//
	// It costs one real boundary — the second of the two codes below — because
	// the replay guard forces the two onto different steps.
	_, secret := h.bootstrapFirstFactorWith(t, email, password, (*harness).freshCodeByWaiting)

	activated := h.awaitState(t, index, "active")
	t.Logf("after TOTP confirmation the account is %q", activated)

	// --- 4. Authenticate, password only ------------------------------------
	//
	// The assertion that matters is the SHAPE of the success: the password was
	// accepted, no session came back, and the account was told which kinds of
	// second factor it can complete with. AuthenticateResponse has no token
	// field at all, so "returns no proof" is carried by the schema; what a test
	// can still check is that nothing was minted as a side effect, which is why
	// the session count is read before and after.
	before := h.liveSessionCount(t, account.subjectID)
	first, err := h.client.Authenticate(ctx, write(&identityv1.AuthenticateRequest{
		Identifier: email,
		Password:   password,
	}))
	if err != nil {
		t.Fatalf("Authenticate (password only): %v\n%s", err, h.serverLogs())
	}
	if !first.Msg.GetSecondFactorRequired() {
		t.Error("a password-only authentication did not report that a second factor is required")
	}
	if !hasKind(first.Msg.GetOffered(), identityv1.MethodKind_METHOD_KIND_TOTP) {
		t.Errorf("offered kinds are %v, want TOTP among them", first.Msg.GetOffered())
	}
	if after := h.liveSessionCount(t, account.subjectID); after != before {
		t.Errorf("a password-only authentication created %d session(s)", after-before)
	}
	t.Logf("password-only: second_factor_required=%v offered=%v sessions=%d",
		first.Msg.GetSecondFactorRequired(), first.Msg.GetOffered(), before)

	// A wrong password is refused, and refused with the SAME undifferentiated
	// error a wrong second factor gets (ADR-036). Asserted as a code rather
	// than as a message, because the message is deliberately uninformative.
	if _, err := h.client.Authenticate(ctx, write(&identityv1.AuthenticateRequest{
		Identifier: email,
		Password:   password + "-wrong",
	})); err == nil {
		t.Error("a wrong password authenticated")
	} else {
		t.Logf("wrong password refused: code=%v", connectrpc.CodeOf(err))
	}

	// --- 5. Authenticate with both factors, then CreateSession -------------
	//
	// Two DIFFERENT time steps, because the replay guard is keyed on
	// (credential, step) and is the one control here that fails closed. Reusing
	// one code would be refused — correctly — and the test would read as a bug
	// in authentication.
	full, err := h.client.Authenticate(ctx, write(&identityv1.AuthenticateRequest{
		Identifier: email,
		Password:   password,
		Code:       h.freshCodeByWaiting(t, secret),
		DeviceId:   "dev_" + h.suffix,
	}))
	if err != nil {
		t.Fatalf("Authenticate (both factors): %v\n%s", err, h.serverLogs())
	}
	if full.Msg.GetSecondFactorRequired() {
		t.Error("a complete authentication still reported that a second factor is required")
	}

	created, err := h.client.CreateSession(ctx, write(&identityv1.CreateSessionRequest{
		Identifier: email,
		Password:   password,
		Code:       h.freshCodeByWaiting(t, secret),
		DeviceId:   "dev_" + h.suffix,
	}))
	if err != nil {
		t.Fatalf("CreateSession: %v\n%s", err, h.serverLogs())
	}
	bearer := created.Msg.GetToken()
	switch {
	case bearer == "":
		t.Fatal("CreateSession returned an empty bearer token")
	case created.Msg.GetSubjectId() != account.subjectID:
		t.Errorf("CreateSession is for subject %q, want %q",
			created.Msg.GetSubjectId(), account.subjectID)
	case created.Msg.GetAssuranceLevel() < optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2:
		t.Errorf("a session was minted at %v, below AAL2", created.Msg.GetAssuranceLevel())
	}
	t.Logf("session: id=%s aal=%v idle=%s absolute=%s rotation=%v",
		created.Msg.GetSessionId(), created.Msg.GetAssuranceLevel(),
		created.Msg.GetIdleExpiresAt().AsTime().Format(time.RFC3339),
		created.Msg.GetAbsoluteExpiresAt().AsTime().Format(time.RFC3339),
		created.Msg.GetRequiresCredentialRotation())

	// Only the digest is stored. Asserted directly, because a session token
	// held in the clear would be indistinguishable from this one at every layer
	// above the table.
	h.assertTokenStoredHashedOnly(t, bearer, created.Msg.GetSessionId())

	// --- 6. an authenticated RPC ------------------------------------------
	user, err := h.client.GetUser(ctx, read(&identityv1.GetUserRequest{}, bearer))
	if err != nil {
		t.Fatalf("GetUser with a live bearer token: %v\n%s", err, h.serverLogs())
	}
	if got := user.Msg.GetSubjectId(); got != account.subjectID {
		t.Errorf("GetUser returned subject %q, want %q", got, account.subjectID)
	}
	if user.Msg.GetState() != identityv1.AccountState_ACCOUNT_STATE_ACTIVE {
		t.Errorf("GetUser reports state %v, want ACTIVE", user.Msg.GetState())
	}
	if !user.Msg.GetEmailVerified() {
		t.Error("GetUser reports the address as unverified after VerifyEmail succeeded")
	}
	t.Logf("GetUser: subject=%s user=%s state=%v verified=%v",
		user.Msg.GetSubjectId(), user.Msg.GetUserId(),
		user.Msg.GetState(), user.Msg.GetEmailVerified())

	// No token at all is refused. Without this, "GetUser succeeded" would be
	// consistent with an authenticator that admits everybody.
	if _, err := h.client.GetUser(ctx, read(&identityv1.GetUserRequest{}, "")); err == nil {
		t.Error("GetUser answered a request carrying no bearer token")
	} else if code := connectrpc.CodeOf(err); code != connectrpc.CodeUnauthenticated {
		t.Errorf("an unauthenticated GetUser returned %v, want unauthenticated", code)
	}

	// --- 7. RevokeSession, and the token stops working ---------------------
	if _, err := h.client.RevokeSession(ctx, writeAuth(&identityv1.RevokeSessionRequest{
		SessionId: created.Msg.GetSessionId(),
	}, bearer)); err != nil {
		t.Fatalf("RevokeSession: %v\n%s", err, h.serverLogs())
	}

	// Immediately, not eventually. Revocation that only took effect once a
	// projector caught up would leave a window in which a token the holder has
	// just revoked still authenticates — which is the exact property opaque
	// hashed tokens were chosen over JWTs to avoid (IDENTITY-SLICE-1).
	_, err = h.client.GetUser(ctx, read(&identityv1.GetUserRequest{}, bearer))
	if err == nil {
		t.Fatal("a revoked bearer token still authenticated")
	}
	if code := connectrpc.CodeOf(err); code != connectrpc.CodeUnauthenticated {
		t.Errorf("a revoked token was refused with %v, want unauthenticated", code)
	}
	t.Logf("revoked token refused: code=%v err=%v", connectrpc.CodeOf(err), err)
}

// TestFirstFactorBootstrapClosesBehindItself is the test that replaced
// TestEnrolmentDeadlock, and it states the property that made closing the
// deadlock safe rather than merely convenient.
//
// The deadlock it replaces was real: EnrollTotp declares min_aal =
// ASSURANCE_LEVEL_2, a session was never minted below AAL2, and AAL2 needs a
// second factor — so a freshly verified account could not obtain the factor it
// was required to have before it could authenticate. The carve-out that closed
// it lets a verified-but-never-enrolled account mint ONE AAL1 session, and that
// session may enrol a first factor.
//
// The carve-out is only safe if it is one-way. An attacker holding a stolen
// password against an ESTABLISHED account must not be able to walk the same
// path: remove nothing, prove nothing, and enrol a factor of their own. So the
// assertion that matters here is the LAST one — the same session, moments after
// a successful confirmation, is refused a second enrolment. Everything before
// it is setup.
//
// It runs over real HTTP through the deployed interceptor chain, because the
// gate being tested is a transport-layer policy and an in-process call would
// bypass exactly the thing under test.
func TestFirstFactorBootstrapClosesBehindItself(t *testing.T) {
	ctx := context.Background()
	email := h.freshEmail("bootstrap")
	const password = "correct-horse-battery-staple-48"

	if _, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: email,
	})); err != nil {
		t.Fatalf("Register: %v\n%s", err, h.serverLogs())
	}
	index := h.emailIndex(t, email)
	account := h.awaitAccount(t, index)

	// Before the address is proven there is no bootstrap session either. The
	// carve-out is keyed on a VERIFIED address, so an unverified account cannot
	// use it to reach an authenticated surface.
	if _, err := h.client.CreateSession(ctx, write(&identityv1.CreateSessionRequest{
		Identifier: email, Password: password, DeviceId: "dev_unverified_" + h.suffix,
	})); err == nil {
		t.Error("an unverified account minted a bootstrap session")
	} else {
		t.Logf("unverified bootstrap refused: code=%v", connectrpc.CodeOf(err))
	}

	plaintext := h.mintVerificationToken(t, account.subjectID)
	if _, err := h.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
		Token: plaintext, Password: password, Username: h.freshUsername("bootstrap"),
	})); err != nil {
		t.Fatalf("VerifyEmail: %v\n%s", err, h.serverLogs())
	}

	bearer, secret := h.bootstrapFirstFactor(t, email, password)
	_ = secret

	// THE PROPERTY. The account now holds a proven second factor, so the same
	// session that was allowed to enrol the first one must no longer be allowed
	// to enrol another. This is the stolen-password attack, and it is refused
	// because the account no longer reports bootstrap enrolment — not because
	// the session was revoked or downgraded.
	_, again := h.client.EnrollTotp(ctx, writeAuth(&identityv1.EnrollTotpRequest{}, bearer))
	if again == nil {
		t.Fatal("an AAL1 bootstrap session enrolled a SECOND factor after the first was " +
			"confirmed; the carve-out is not one-way and a stolen password is enough to " +
			"add an attacker-controlled second factor")
	}
	if code := connectrpc.CodeOf(again); code != connectrpc.CodePermissionDenied {
		t.Errorf("a second enrolment from the bootstrap session was refused with %v, "+
			"want permission_denied", code)
	}
	t.Logf("second enrolment from the bootstrap session refused: code=%v", connectrpc.CodeOf(again))

	// The FRONT line, and the one that matters most: an established account is
	// refused the bootstrap session in the first place. The refusal above is the
	// second layer — it only has to hold for a session minted before the factor
	// existed. This one is what stops a stolen password from ever reaching an
	// authenticated surface, and it is the assertion that would catch
	// CanAuthenticate's Pending carve-out widening to admit an active account.
	if _, err := h.client.CreateSession(ctx, write(&identityv1.CreateSessionRequest{
		Identifier: email, Password: password, DeviceId: "dev_established_" + h.suffix,
	})); err == nil {
		t.Error("an established account minted a password-only session; the bootstrap " +
			"carve-out is not restricted to accounts without a factor")
	} else {
		t.Logf("password-only session on an established account refused: code=%v",
			connectrpc.CodeOf(err))
	}

	// The bootstrap session is AAL1 and stays AAL1. It buys enrolment and
	// nothing else — an AAL2 RPC is refused from it both before and after the
	// factor exists, so confirming a factor does not silently promote the
	// session that confirmed it.
	if _, err := h.client.RevokeAllSessions(ctx, writeAuth(
		&identityv1.RevokeAllSessionsRequest{}, bearer,
	)); err == nil {
		t.Error("an AAL1 bootstrap session revoked every session")
	} else if code := connectrpc.CodeOf(err); code != connectrpc.CodePermissionDenied {
		t.Errorf("RevokeAllSessions from the bootstrap session returned %v, "+
			"want permission_denied", code)
	}
}

// TestNoProductionCodeMintsAVerificationToken states the other defect found
// here, as a fact about the running system rather than as a claim about the
// source.
//
// It registers an account and then asserts that the server wrote NO row to
// identity_token. Every other step of the flow is reachable; this one is the
// gap that makes VerifyEmail unreachable in production, because the token it
// consumes is never created and is returned to nobody.
func TestNoProductionCodeMintsAVerificationToken(t *testing.T) {
	ctx := context.Background()
	email := h.freshEmail("notoken")

	if _, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: email,
	})); err != nil {
		t.Fatalf("Register: %v\n%s", err, h.serverLogs())
	}
	account := h.awaitAccount(t, h.emailIndex(t, email))

	// Generous, and deliberately so: a token minted asynchronously by a reactor
	// or a workflow would still land here, and the point is that none does.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if n := h.tokenRows(t, account.subjectID); n > 0 {
			t.Logf("identity_token rows for a fresh registration: %d — the flow is complete", n)
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Errorf("BUG: five seconds after a successful Register, identity_token holds 0 rows for "+
		"subject %s. Nothing in production calls TokenStore.Issue, so no verification token "+
		"is ever minted or mailed and VerifyEmail can never be satisfied by a real user.",
		account.subjectID)
}

// ---------------------------------------------------------------------------
// scenario helpers
// ---------------------------------------------------------------------------

type accountRow struct {
	subjectID string
	userID    string
	state     string
	verified  bool

	// username is the public handle, in the clear, and empty until the account is
	// verified (ADR-051).
	//
	// It is a FIELD on this struct rather than something a test queries when it
	// happens to care, and that placement is load-bearing:
	// TestRebuildPreservesCredentials compares the whole row before and after a
	// rebuild with `after != before`, so the handle is automatically part of
	// "the rebuild reconstructed the account identically". A handle that a
	// rebuild dropped, resurrected or rewrote would fail there without anybody
	// having to remember to check it.
	username string
}

func (hh *harness) freshEmail(tag string) string {
	return fmt.Sprintf("%s-%s-%d@identityit.example.com", tag, hh.suffix, time.Now().UnixNano())
}

// usernameSeq makes every handle this run mints distinct from every other,
// including two minted from concurrent goroutines in the same microsecond.
//
// A COUNTER and not a timestamp, and that is a bug fix rather than a preference.
// The first version derived the handle from time.Now().UnixNano(); on macOS the
// wall clock's granularity is coarser than a nanosecond, so two goroutines
// starting together read the same value and minted the SAME handle — and the
// second account's verification was then correctly refused with "that username
// is not available", which is the property under test failing a test that had
// nothing to do with it.
var usernameSeq atomic.Uint64

// freshUsername mints a handle no other test and no earlier run can collide
// with.
//
// It has to be unique across RUNS, and that is a stronger requirement than
// freshEmail's. Test isolation elsewhere in this package comes from the
// blind-index key: every run hashes its addresses into a private index space, so
// a leftover row from an earlier run cannot collide. A handle has NO keyed
// derivation — the stream is named by the handle in the clear (ADR-051) — and a
// handle is claimed FOREVER, so a reused one contends with a claim an earlier
// run left in KurrentDB and can never be freed. Hence the per-run suffix AND the
// per-call counter.
//
// The shape obeys domain.NormalizeUsername exactly: ASCII lowercase, digits and
// underscores, starting with a letter, no hyphen (a dash in a stream key is
// refused, because KurrentDB derives a category from everything before the
// first one), and comfortably inside the 30-byte ceiling by construction rather
// than by truncation — truncating is what threw the uniqueness away before.
func (hh *harness) freshUsername(tag string) string {
	label := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return -1
		}
	}, tag)
	if len(label) > 8 {
		label = label[:8]
	}
	// "u" leads so the handle always starts with a letter whatever the tag was.
	// 1 + 8 + 1 + 8 + 6 = 24 bytes at most.
	return fmt.Sprintf("u%s_%s%06x", label, hh.suffix[:8], usernameSeq.Add(1))
}

func (hh *harness) emailIndex(t *testing.T, email string) string {
	t.Helper()
	idx, err := hh.index.Of(email)
	if err != nil {
		t.Fatalf("blind index: %v", err)
	}
	return string(idx)
}

// write builds a mutating request. Every mutating RPC requires an
// Idempotency-Key (CONVENTIONS §6, gate 5), and a UNIQUE one per call: the
// concurrency property below depends on that, because a shared key would make
// the gate collapse the requests before KurrentDB ever saw them.
//
// Package-level rather than methods on the harness because Go methods may not
// take type parameters.
func write[T any](msg *T) *connectrpc.Request[T] {
	req := connectrpc.NewRequest(msg)
	req.Header().Set(interceptor.IdempotencyHeader, newIdempotencyKey())
	return req
}

func writeAuth[T any](msg *T, bearer string) *connectrpc.Request[T] {
	req := write(msg)
	if bearer != "" {
		req.Header().Set(interceptor.AuthorizationHeader, "Bearer "+bearer)
	}
	return req
}

func read[T any](msg *T, bearer string) *connectrpc.Request[T] {
	req := connectrpc.NewRequest(msg)
	if bearer != "" {
		req.Header().Set(interceptor.AuthorizationHeader, "Bearer "+bearer)
	}
	return req
}

func newIdempotencyKey() string {
	return "idem_" + ids.New[ids.Event](time.Now(), ids.Entropy()).String()
}

// awaitAccount waits for the projector to turn the appended events into the row
// every later step reads.
func (hh *harness) awaitAccount(t *testing.T, index string) accountRow {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		var row accountRow
		found := false
		hh.systemQuery(t, func(ctx context.Context, q db.Querier) error {
			// `email_released_at IS NULL` mirrors GetUserByEmailIndex, the
			// production lookup. An address can have been held by one account
			// and then be held by another (migration 00014), and a QueryRow
			// without this clause would return whichever row the planner
			// reached first — so a test could silently follow the SUPERSEDED
			// account through every step after this one.
			// COALESCE because the column is NULL until the handle is claimed and
			// again after an erasure. Both are "no handle" from a test's point of
			// view, and a scan error there would be a failure about the schema
			// rather than about the account.
			err := q.QueryRow(ctx, `
				SELECT subject_id, user_id, state, email_verified, coalesce(username, '')
				FROM user_view WHERE email_index = $1 AND email_released_at IS NULL`, index).
				Scan(&row.subjectID, &row.userID, &row.state, &row.verified, &row.username)
			if err != nil && strings.Contains(err.Error(), "no rows") {
				return nil
			}
			found = err == nil
			return err
		})
		if found {
			return row
		}
		if time.Now().After(deadline) {
			t.Fatalf("no user_view row for index %s after 30s; the identity projector never "+
				"applied the registration\n%s", hex.EncodeToString([]byte(index)), hh.serverLogs())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// awaitVerified waits for the projector to record that the address was proven
// AND that the public handle was claimed.
//
// Separate from awaitState because the state does not move on verification any
// more than it did before — an account with a proven address and no second
// factor is still Pending — so "wait for active" would time out and "read once"
// would race the projector.
//
// It waits for BOTH facts because they arrive from one atomic append but reach
// the projection as two rows of work: EmailVerified is applied before
// UsernameAssigned, so a caller that stopped at `verified` could observe the
// account in a half-projected state that never exists in the log. That is not a
// theoretical tidiness — TestRebuildPreservesCredentials compares the whole row
// before and after a rebuild, and a `before` snapshot taken between the two
// events would report a spurious difference every time the projector happened to
// be slow.
func (hh *harness) awaitVerified(t *testing.T, index string) accountRow {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var row accountRow
	for time.Now().Before(deadline) {
		row = hh.awaitAccount(t, index)
		if row.verified && row.username != "" {
			return row
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("the account for this index is still unverified or holds no handle after 30s: %+v",
		row)
	return row
}

func (hh *harness) awaitState(t *testing.T, index, want string) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var got string
	for time.Now().Before(deadline) {
		got = hh.awaitAccount(t, index).state
		if got == want {
			return got
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("account state is %q after 30s, want %q", got, want)
	return got
}

// mintVerificationToken supplies the token production never mints.
//
// # Why this is here
//
// `Register` takes a `TokenStore` and never calls `Issue` on it. Nothing else
// in the repository calls it either — `token.Minter` is fully implemented,
// fully tested, and constructed by no binary. So no verification token exists
// for any account, and `VerifyEmail` is unreachable through the product.
//
// # Why this shape, and not another
//
// The plaintext is returned to nobody and only its SHA-256 digest is stored, so
// there is no way to read a real one back out of the database — the digest
// cannot be inverted, and that is by design. The two honest options were:
//
//  1. mint here, through the production `token.Minter` and the production
//     `TokenStore` port, exactly as the missing production code would; or
//  2. skip verification entirely and assert nothing past step 2.
//
// The first is chosen. Every byte of the token path that DOES exist is still
// exercised: the same `Digest` function, the same `identity_token` row shape,
// the same single-use `Consume` in the same SQL statement, reached through the
// real `VerifyEmail` handler over HTTP. What is simulated is only the missing
// call site, and `TestNoProductionCodeMintsAVerificationToken` asserts that it
// is missing, so this helper cannot quietly paper over the gap.
func (hh *harness) mintVerificationToken(t *testing.T, subjectID string) string {
	t.Helper()
	// The SERVER's clock, not this process's. The token's expiry is written here
	// and checked there (identity_token.expires_at > $now), so minting against
	// wall time while the server runs ahead of it silently shortens the TTL by
	// however far the suite has travelled.
	minted, err := token.New().Mint(app.PurposeEmailVerification, hh.serverNow(t))
	if err != nil {
		t.Fatalf("minting a verification token: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := hh.guards.Issue(ctx, app.PurposeEmailVerification,
		subjectID, minted.Digest, minted.ExpiresAt); err != nil {
		t.Fatalf("issuing a verification token: %v", err)
	}
	return minted.Plaintext
}

// bootstrapFirstFactor drives the real enrolment ceremony over HTTP and returns
// the bootstrap session's bearer token together with the confirmed TOTP secret.
//
// It replaced an in-process workaround. Until the bootstrap carve-out existed
// the HTTP route was deadlocked, so this helper called app.SecondFactor
// directly and bypassed the one thing worth testing: the transport gate. Every
// step below now goes through the deployed interceptor chain, which is what
// lets the rest of the scenario claim it exercised the public API rather than
// the objects behind it.
func (hh *harness) bootstrapFirstFactor(t *testing.T, email, password string) (string, string) {
	t.Helper()
	return hh.bootstrapFirstFactorWith(t, email, password, (*harness).freshCode)
}

// codeSource is where a ceremony gets its TOTP codes: freshCode, which travels
// through the step boundary, or freshCodeByWaiting, which sits through it.
//
// A parameter rather than a field on the harness, because the harness is shared
// by every test in the package and a field would make one test's choice of
// clock discipline everybody else's.
type codeSource func(*harness, *testing.T, string) string

// bootstrapFirstFactorWith is bootstrapFirstFactor with the code source named.
func (hh *harness) bootstrapFirstFactorWith(
	t *testing.T, email, password string, code codeSource,
) (string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// A verified account with no factor gets a session from the password alone.
	// It is an ordinary, revocable session — the carve-out is in what the domain
	// will mint, not in a ticket the caller may present.
	boot, err := hh.client.CreateSession(ctx, write(&identityv1.CreateSessionRequest{
		Identifier: email,
		Password:   password,
		DeviceId:   "dev_boot_" + hh.suffix,
	}))
	if err != nil {
		t.Fatalf("CreateSession (bootstrap): %v\n%s", err, hh.serverLogs())
	}
	bearer := boot.Msg.GetToken()
	if bearer == "" {
		t.Fatal("the bootstrap CreateSession returned an empty bearer token")
	}
	if got := boot.Msg.GetAssuranceLevel(); got != optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1 {
		t.Errorf("the bootstrap session was minted at %v, want exactly AAL1", got)
	}
	t.Logf("bootstrap session: id=%s aal=%v", boot.Msg.GetSessionId(), boot.Msg.GetAssuranceLevel())

	// AWAITED before the bearer is presented, and this is a real race rather than
	// belt and braces. A session has TWO halves: the token digest, written
	// authoritatively by CreateSession, and the session_view row, written by the
	// session PROJECTOR from SessionCreated — and it resolves only when both exist
	// (migration 00010). So the token this call just returned is unusable for as
	// long as the projector takes to catch up, and presenting it early is refused
	// as `unauthenticated: authentication failed`, which reads exactly like a
	// broken credential.
	//
	// It failed that way intermittently under a full-package run and never in
	// isolation, because the window is a function of how much OTHER traffic the
	// projector is chewing through. Every event any test appends widens it.
	//
	// `signIn` already awaited this; this path did not, and that asymmetry is the
	// likeliest answer to the flake awaitSessionProjected's own doc records as
	// OPEN — it measured the window on the sign-in path, which was already
	// guarded, and every observed failure has been on a token minted HERE.
	hh.awaitSessionProjected(t, boot.Msg.GetSessionId())

	enrolled, err := hh.client.EnrollTotp(ctx, writeAuth(&identityv1.EnrollTotpRequest{}, bearer))
	if err != nil {
		t.Fatalf("EnrollTotp from the bootstrap session: %v\n%s", err, hh.serverLogs())
	}
	t.Logf("enrolled: credential=%s uri=otpauth://totp/... expires=%s",
		enrolled.Msg.GetCredentialId(), enrolled.Msg.GetExpiresAt().AsTime().Format(time.RFC3339))

	// The code is generated from the PROVISIONING URI, not from the raw secret,
	// so the URI an authenticator app would scan is the thing under test. A URI
	// with the wrong secret, the wrong algorithm or the wrong digit count
	// produces codes the server rejects, and nothing else in the repository
	// checks that round trip.
	secret := secretFromURI(t, enrolled.Msg.GetProvisioningUri())
	if secret != enrolled.Msg.GetSecret() {
		t.Errorf("the provisioning URI carries secret %q, but the response returned %q",
			secret, enrolled.Msg.GetSecret())
	}

	confirmed, err := hh.client.ConfirmTotp(ctx, writeAuth(&identityv1.ConfirmTotpRequest{
		Code: code(hh, t, secret),
	}, bearer))
	if err != nil {
		t.Fatalf("ConfirmTotp from the bootstrap session: %v\n%s", err, hh.serverLogs())
	}
	if !confirmed.Msg.GetActivated() {
		t.Errorf("confirming a TOTP factor on a verified account did not activate it: %+v",
			confirmed.Msg)
	}
	t.Logf("confirmed: credential=%s activated=%v changed=%v",
		confirmed.Msg.GetCredentialId(), confirmed.Msg.GetActivated(), confirmed.Msg.GetChanged())
	return bearer, secret
}

// usedSteps records which TOTP time steps this run has already spent, so a
// second code is never taken from a step the replay guard has claimed.
//
// The guard is keyed on (credential, step) and fails CLOSED. That is correct
// and is why it cannot be worked around: the only way to present a second valid
// code FOR ONE AUTHENTICATOR is to wait for a step boundary. Every wait here is
// real elapsed time.
//
// # Keyed by (secret, step), not by step alone
//
// It was keyed by step alone, which made every account in the package wait for
// every other account's code — the map said "this step is spent" when what the
// database records is "this step is spent FOR THIS CREDENTIAL". Two accounts can
// legitimately use the same step, and `totp_replay`'s primary key
// (credential_id, step) is the statement of that. The over-broad key cost
// thirty seconds per unrelated account and pushed this package past the ten
// minute `go test` timeout once the lifecycle tests were added.
//
// The mutex is what makes the map safe for the tests that run with
// t.Parallel(). Without it two parallel tests racing on the map is a data race
// the -race detector would report, and the failure it hides is worse: both
// could take the same step for one secret and the second code would be refused
// by a guard that is working exactly as designed.
var (
	usedStepsMu sync.Mutex
	usedSteps   = map[string]bool{}
)

// totpPeriod is RFC 6238's step, in seconds. Not imported from the totp adapter
// on purpose: a test that derived the period from the code under test would
// agree with it about a wrong value.
const totpPeriod = 30

// totpBoundaryMargin is how much of a step must remain for a code to be worth
// minting. A code generated in the last moment of a step can arrive at the
// server in the next one.
const totpBoundaryMargin = 3

// maxStepJumps bounds the loop in freshCode.
//
// Two would do — a spent step plus a boundary margin — and this is deliberately
// not tight. What it is here to prevent is an infinite loop when the control is
// answering but not moving anything: without it, a clock stuck at one instant
// turns a failing test into a hung suite with no output.
const maxStepJumps = 8

// freshCode returns a TOTP code the server will accept, TRAVELLING through the
// step boundary rather than waiting for it (ADR-054).
//
// # What this is buying, and why the cost was unavoidable before
//
// The replay guard is keyed on (credential, step) and fails closed. That is
// correct, it is the whole reason a stolen code is not reusable, and it means
// there is no way to get a SECOND valid code for one authenticator inside one
// thirty-second step. So a test needing two codes needs two steps, and a step
// is thirty seconds of the server's clock.
//
// It used to be thirty seconds of WALL clock, and that single fact was most of
// this package's four-minute runtime — fourteen call sites, several tests idle
// for a minute each. Nothing about RFC 6238 requires the wait. It was required
// because the server's clock was time.Now() and nothing could move it.
//
// So this asks the server what time it is, and when the step it lands in is
// already spent it pushes the server's clock into the next one. The server
// experiences a step boundary; the suite does not experience thirty seconds.
//
// # Why the whole loop holds the lock
//
// The map is shared, the advance is global, and parallel tests use both. The
// original released the mutex around each sleep because a sleep is long; an
// advance is a millisecond of loopback HTTP, so holding it costs nothing and
// removes the interleaving where two tests read the same step, both advance,
// and the clock jumps twice as far as either needed.
//
// # What it does NOT do
//
// It never rewinds. The control refuses a negative advance and the guard would
// refuse the replay anyway; the two are independent, and verifyClockControl
// asserts the first of them once per run.
func (hh *harness) freshCode(t *testing.T, secret string) string {
	t.Helper()
	usedStepsMu.Lock()
	defer usedStepsMu.Unlock()

	now := hh.serverNow(t)
	for range maxStepJumps {
		step := now.Unix() / totpPeriod
		key := secret + ":" + strconv.FormatInt(step, 10)
		remaining := totpPeriod - (now.Unix() % totpPeriod)

		if !usedSteps[key] && remaining >= totpBoundaryMargin {
			usedSteps[key] = true
			code, err := totp.GenerateCode(secret, now)
			if err != nil {
				t.Fatalf("generating a TOTP code: %v", err)
			}
			return code
		}
		now = hh.advanceServerClock(t, time.Duration(remaining+1)*time.Second)
	}
	t.Fatalf("no unspent TOTP step after %d advances; the clock control is answering but "+
		"the server's clock is not moving, so every step it reports is the same one",
		maxStepJumps)
	return ""
}

// freshCodeByWaiting is freshCode with the time travel taken out: it SLEEPS
// through the step boundary in real seconds.
//
// # Why one caller has to keep doing this
//
// Because the fast path proves a property about a server whose clock a test can
// move, and production does not have one. If every code in this package came
// from an advanced clock, then "thirty real seconds roll the step over on the
// deployed server" would be asserted nowhere, and the day the offset clock is
// wired in a way that quietly decouples TOTP verification from wall time — a
// second clock built somewhere in the graph, a handler reading time.Now
// directly — every test here would still pass.
//
// It reads the server's clock rather than its own for one subtle reason: the
// offset is shared by the whole process, so a parallel test may have moved it.
// The offset is a CONSTANT added to a real clock, so sleeping n real seconds
// still advances the server by exactly n seconds — which is the property under
// test. Computing the step from the test's own time.Now would instead mint a
// code for a step the server has already left.
//
// TestIdentitySliceEndToEnd is the only caller; see the comment there.
func (hh *harness) freshCodeByWaiting(t *testing.T, secret string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for {
		now := hh.serverNow(t)
		step := now.Unix() / totpPeriod
		key := secret + ":" + strconv.FormatInt(step, 10)

		usedStepsMu.Lock()
		spent := usedSteps[key]
		if !spent {
			if remaining := totpPeriod - (now.Unix() % totpPeriod); remaining < totpBoundaryMargin {
				usedStepsMu.Unlock()
				time.Sleep(time.Duration(remaining+1) * time.Second)
				continue
			}
			usedSteps[key] = true
			usedStepsMu.Unlock()
			code, err := totp.GenerateCode(secret, now)
			if err != nil {
				t.Fatalf("generating a TOTP code: %v", err)
			}
			return code
		}
		usedStepsMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("waited three minutes for an unspent TOTP step: real time is not " +
				"advancing the server's clock, which it must, because the offset clock " +
				"is an offset FROM the wall clock and not a replacement for it")
		}
		time.Sleep(time.Second)
	}
}

func secretFromURI(t *testing.T, uri string) string {
	t.Helper()
	key, err := otp.NewKeyFromURL(uri)
	if err != nil {
		t.Fatalf("parsing the provisioning URI: %v", err)
	}
	return key.Secret()
}

func hasKind(kinds []identityv1.MethodKind, want identityv1.MethodKind) bool {
	return slices.Contains(kinds, want)
}

// assertTokenStoredHashedOnly proves the bearer token is not recoverable from
// the database. A session token held in the clear behaves identically at every
// layer above the table, so nothing else in the flow can catch it.
func (hh *harness) assertTokenStoredHashedOnly(t *testing.T, bearer, sessionID string) {
	t.Helper()
	var plaintextRows, digestRows int
	hh.systemQuery(t, func(ctx context.Context, q db.Querier) error {
		if err := q.QueryRow(ctx,
			`SELECT count(*) FROM session_token WHERE session_token::text LIKE '%' || $1 || '%'`,
			bearer).Scan(&plaintextRows); err != nil {
			return err
		}
		return q.QueryRow(ctx,
			`SELECT count(*) FROM session_token WHERE session_id = $1`, sessionID).Scan(&digestRows)
	})
	if plaintextRows != 0 {
		t.Errorf("the plaintext bearer token appears in %d session_token row(s)", plaintextRows)
	}
	if digestRows != 1 {
		t.Errorf("session_token holds %d row(s) for session %s, want 1", digestRows, sessionID)
	}
	t.Logf("session_token: %d row for the session, %d containing the plaintext",
		digestRows, plaintextRows)
}

func (hh *harness) liveSessionCount(t *testing.T, subjectID string) int {
	t.Helper()
	var n int
	hh.systemQuery(t, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx,
			`SELECT count(*) FROM session_view WHERE subject_id = $1 AND revoked_at IS NULL`,
			subjectID).Scan(&n)
	})
	return n
}

// awaitLiveSessions polls session_view until it holds `want` live sessions.
//
// It exists because awaiting the ACCOUNT state proves nothing about the SESSION
// projection: they are two projectors with two checkpoints, and a revocation
// that has already reached user_view may still be in flight for session_view.
// TestADeactivationLeavesNoLiveSession asserted one after awaiting the other and
// failed intermittently — more often as the package grew, because every event any
// other test appends widens the window the session projector has to chew through.
//
// A poll rather than a longer wait: the correct outcome is reached in
// milliseconds on a quiet stack and the deadline only pays for a busy one.
// A predicate rather than a number, because both questions asked of it are real:
// "none survived" is exact, and "at least two exist" is a floor a fan-out test
// needs before it can prove anything.
func (hh *harness) awaitLiveSessions(
	t *testing.T, subjectID string, ok func(int) bool, want string,
) int {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var got int
	for time.Now().Before(deadline) {
		got = hh.liveSessionCount(t, subjectID)
		if ok(got) {
			return got
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("session_view holds %d live session(s) after 30s, want %s", got, want)
	return got
}

func (hh *harness) tokenRows(t *testing.T, subjectID string) int {
	t.Helper()
	var n int
	hh.systemQuery(t, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx,
			`SELECT count(*) FROM identity_token WHERE subject_id = $1`, subjectID).Scan(&n)
	})
	return n
}
