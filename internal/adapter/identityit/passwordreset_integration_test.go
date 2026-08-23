//go:build integration

package identityit_test

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/kurrent-io/KurrentDB-Client-Go/kurrentdb"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/token"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// The password reset is the P1 flow identity.md §4.5 specified before it was
// written. Everything below runs over real HTTP against cmd/api, through the
// production interceptor chain, against the real KurrentDB log, the real
// PostgreSQL read model and the real Valkey counter behind the ceiling.
//
// What the app-layer unit tests cannot prove and these can:
//
//   - the responses are byte-identical ON THE WIRE for every account state;
//   - the ceiling is a live counter shared with verification mail, not an
//     in-memory map;
//   - the sessions that die are real sessions whose real bearer tokens stop
//     resolving through the real authenticator;
//   - the second factor is still demanded afterwards by the real login path.
//
// What they do NOT cover is delivery. Nothing consumes PasswordResetRequested in
// this repository yet — the reset-mail issuer is the same missing component the
// verification reactor was before cmd/worker grew one — so the assertion here is
// that the EVENT was appended, and mintResetToken supplies the token production
// does not yet mint.

// mintResetToken supplies the reset token production does not yet mint.
//
// Identical in shape and in justification to mintVerificationToken: the
// plaintext is returned to nobody and only its SHA-256 digest is stored, so
// there is no way to read a real one back out of the database. Every byte of the
// path that DOES exist is still exercised — the same Digest function with the
// same purpose mixed in, the same identity_token row, the same single-use
// DELETE … RETURNING, reached through the real ResetPassword handler over HTTP.
// What is simulated is only the missing issuer.
func (hh *harness) mintResetToken(t *testing.T, subjectID string) string {
	t.Helper()
	minted, err := token.New().Mint(app.PurposePasswordReset, time.Now().UTC())
	if err != nil {
		t.Fatalf("minting a reset token: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := hh.guards.Issue(ctx, app.PurposePasswordReset,
		subjectID, minted.Digest, minted.ExpiresAt); err != nil {
		t.Fatalf("issuing a reset token: %v", err)
	}
	return minted.Plaintext
}

// countResetRequests reads the account's stream and counts the reset requests
// actually appended.
//
// The stream is the honest place to count. A refused request returns the same
// empty response as one that succeeded — that indistinguishability is the point
// — so the response tells a test nothing at all, and only the write can
// distinguish the two.
func countResetRequests(t *testing.T, userID string) int {
	t.Helper()
	id, err := eventsourcing.NewStreamID(eventsourcing.Category("user"), userID)
	if err != nil {
		t.Fatalf("stream id: %v", err)
	}
	events, err := h.store.ReadStream(context.Background(), id, 0)
	if err != nil {
		t.Fatalf("reading the account stream: %v", err)
	}
	n := 0
	for _, e := range events {
		if e.Type == (&contract.PasswordResetRequested{}).EventType() {
			n++
		}
	}
	return n
}

// countPasswordChanges counts the PasswordChanged events on an account's stream
// and reports how many of them were reset-driven.
func countPasswordChanges(t *testing.T, userID string) (total, viaReset int) {
	t.Helper()
	id, err := eventsourcing.NewStreamID(eventsourcing.Category("user"), userID)
	if err != nil {
		t.Fatalf("stream id: %v", err)
	}
	events, err := h.store.ReadStream(context.Background(), id, 0)
	if err != nil {
		t.Fatalf("reading the account stream: %v", err)
	}
	want := (&contract.PasswordChanged{}).EventType()
	for _, e := range events {
		if e.Type != want {
			continue
		}
		total++
		decoded, err := h.codec.Unmarshal(e.Type, e.Payload)
		if err != nil {
			t.Fatalf("decoding %s: %v", e.Type, err)
		}
		changed, ok := decoded.(*contract.PasswordChanged)
		if !ok {
			t.Fatalf("%s decoded as %T", e.Type, decoded)
		}
		if changed.ViaReset {
			viaReset++
		}
	}
	return total, viaReset
}

// TestAResetRequestIsIndistinguishableAcrossAccountStates is the enumeration
// property, asserted on the BYTES the server actually sent.
//
// Field-by-field comparison is not enough and the difference is not academic: a
// field added to the response later — a `sent` flag, a next-allowed timestamp —
// would pass a comparison written today while turning an unauthenticated
// endpoint into a precise account-state oracle for any address a prober can
// type.
//
// The byte comparison alone is also not enough, which is why the second half
// counts what was WRITTEN. A handler that answered identically and then mailed a
// reset link to an account that cannot use one would pass the byte comparison
// and still be a mail-bombing primitive.
func TestAResetRequestIsIndistinguishableAcrossAccountStates(t *testing.T) {
	clearCallerCeiling(t)
	ctx := context.Background()

	// (1) An address nothing claims.
	unknown := h.freshEmail("reset-nobody")

	// (2) A verified account with a usable password — the one state a reset can
	// actually help.
	resettableEmail := h.freshEmail("reset-resettable")
	resettable := h.registerThroughTheKernel(t, resettableEmail)
	if _, err := h.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
		Token:    h.mintVerificationToken(t, resettable.subjectID),
		Password: "the-original-passphrase",
		Username: h.freshUsername("resettable"),
	})); err != nil {
		t.Fatalf("VerifyEmail: %v\n%s", err, h.serverLogs())
	}
	h.awaitVerified(t, h.emailIndex(t, resettableEmail))

	// (3) A registered account that has never proven its address, and therefore
	// has no password at all. §4.3: the way into one of these is the verification
	// link, never a reset.
	pendingEmail := h.freshEmail("reset-pending")
	pending := h.registerThroughTheKernel(t, pendingEmail)

	type probe struct {
		name  string
		email string
	}
	probes := []probe{
		{"an address nothing claims", unknown},
		{"a verified account with a password", resettableEmail},
		{"a registered account that never proved its address", pendingEmail},
	}

	responses := make([][]byte, 0, len(probes))
	for _, p := range probes {
		resp, err := h.client.RequestPasswordReset(ctx, write(
			&identityv1.RequestPasswordResetRequest{Email: p.email},
		))
		if err != nil {
			t.Fatalf("RequestPasswordReset for %s returned %v (code=%v); every account "+
				"state must answer alike, and an error is the most distinguishable answer "+
				"of all\n%s", p.name, err, connectrpc.CodeOf(err), h.serverLogs())
		}
		raw, merr := proto.Marshal(resp.Msg)
		if merr != nil {
			t.Fatalf("marshalling the response for %s: %v", p.name, merr)
		}
		responses = append(responses, raw)
	}

	for i, raw := range responses {
		if string(raw) != string(responses[0]) {
			t.Errorf("%s answered %x while %s answered %x; the reset RPC discloses "+
				"account state", probes[i].name, raw, probes[0].name, responses[0])
		}
	}
	if len(responses[0]) != 0 {
		t.Errorf("RequestPasswordResetResponse carries %d bytes; it must stay empty",
			len(responses[0]))
	}
	t.Logf("all %d probes answered with %d identical byte(s)", len(responses), len(responses[0]))

	// The half a byte comparison cannot see.
	if got := countResetRequests(t, resettable.userID); got != 1 {
		t.Errorf("the resettable account carries %d reset request(s), want exactly 1", got)
	}
	if got := countResetRequests(t, pending.userID); got != 0 {
		t.Errorf("an account that never proved its address had %d reset link(s) requested "+
			"for it; there is no password to reset and the link would lead nowhere", got)
	}
}

// TestACompletedResetVoidsEverythingAndKeepsTheSecondFactor is identity.md
// §4.5's whole contract, end to end, over HTTP.
//
// The account is taken all the way to Active with a real TOTP factor and a real
// session, then reset, and every clause is checked against a consequence a
// client can observe:
//
//	§4.5 (1) every session dies      — the bearer token stops resolving
//	§4.5 (2) every token dies        — identity_token is empty for the subject,
//	                                   including an outstanding VERIFICATION link
//	§4.5 (4) no second-factor bypass — the new password alone still cannot sign in
//	§4.5 (5) the stored address      — the request supplies an address and the
//	                                   event records the account's own pseudonym
//
// Ask what each assertion would do if the feature were deleted: a reset that
// skipped the revocation leaves the bearer working, one that swept only reset
// tokens leaves the verification link live, and one that signed the caller in
// would let the no-code login succeed. All three fail here.
func TestACompletedResetVoidsEverythingAndKeepsTheSecondFactor(t *testing.T) {
	clearCallerCeiling(t)
	ctx := context.Background()

	const (
		oldPassword = "the-original-passphrase"
		newPassword = "an-entirely-different-passphrase"
	)

	email := h.freshEmail("reset-e2e")
	index := h.emailIndex(t, email)
	account := h.registerThroughTheKernel(t, email)

	if _, err := h.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
		Token:    h.mintVerificationToken(t, account.subjectID),
		Password: oldPassword,
		Username: h.freshUsername("resete2e"),
	})); err != nil {
		t.Fatalf("VerifyEmail: %v\n%s", err, h.serverLogs())
	}
	h.awaitVerified(t, index)

	// A real second factor, enrolled through the real ceremony, so "the reset
	// removed it" and "the reset bypassed it" are both reachable failures rather
	// than vacuous ones.
	_, secret := h.bootstrapFirstFactor(t, email, oldPassword)
	h.awaitState(t, index, "active")

	// A real AAL2 session, which is what must not survive.
	created, err := h.client.CreateSession(ctx, write(&identityv1.CreateSessionRequest{
		Identifier: email,
		Password:   oldPassword,
		Code:       h.freshCode(t, secret),
		DeviceId:   "dev_reset_" + h.suffix,
	}))
	if err != nil {
		t.Fatalf("CreateSession before the reset: %v\n%s", err, h.serverLogs())
	}
	bearer := created.Msg.GetToken()
	if bearer == "" {
		t.Fatal("CreateSession returned an empty bearer token")
	}
	// The token is minted by an APPEND and resolved from a PROJECTION, so there
	// is a window in which CreateSession has returned a bearer that
	// authenticates nothing. Under load — a full suite run rather than this test
	// alone — the projector is far enough behind to land inside it, and the
	// failure reads as "the reset broke the session" when the reset has not
	// happened yet.
	h.awaitSessionProjected(t, created.Msg.GetSessionId())

	if _, err := h.client.GetUser(ctx, read(&identityv1.GetUserRequest{}, bearer)); err != nil {
		t.Fatalf("the session does not work before the reset: %v\n%s", err, h.serverLogs())
	}

	// An outstanding VERIFICATION link for the same account — Sudhodanan &
	// Paverd's "trojan identifier" variant. It is a different PURPOSE, so only a
	// sweep across every purpose kills it.
	stray := h.mintVerificationToken(t, account.subjectID)
	if got := h.tokenRows(t, account.subjectID); got < 1 {
		t.Fatalf("identity_token holds %d row(s) before the reset, want at least the "+
			"stray verification link", got)
	}

	// --- the request ---------------------------------------------------------
	if _, err := h.client.RequestPasswordReset(ctx, write(
		&identityv1.RequestPasswordResetRequest{Email: email},
	)); err != nil {
		t.Fatalf("RequestPasswordReset: %v\n%s", err, h.serverLogs())
	}
	if got := countResetRequests(t, account.userID); got != 1 {
		t.Fatalf("the account carries %d reset request(s), want 1", got)
	}

	// --- the redemption ------------------------------------------------------
	resetToken := h.mintResetToken(t, account.subjectID)
	resp, err := h.client.ResetPassword(ctx, write(&identityv1.ResetPasswordRequest{
		Token:    resetToken,
		Password: newPassword,
	}))
	if err != nil {
		t.Fatalf("ResetPassword: %v\n%s", err, h.serverLogs())
	}
	body, err := proto.Marshal(resp.Msg)
	if err != nil {
		t.Fatalf("marshalling the reset response: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("ResetPasswordResponse carried %d bytes (%x); a reset must return nothing "+
			"a client could mistake for a session (ASVS 5.0 V6.4.3)", len(body), body)
	}

	// §4.5 (2): every outstanding token of EVERY purpose is gone.
	if got := h.tokenRows(t, account.subjectID); got != 0 {
		t.Errorf("identity_token holds %d row(s) for the subject after a reset, want 0", got)
	}
	if _, err := h.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
		Token:    stray,
		Password: "yet-another-passphrase",
		Username: h.freshUsername("stray"),
	})); err == nil {
		t.Error("a verification link outstanding at the moment of the reset still works; " +
			"§4.5 requires a reset to void every outstanding token of every purpose")
	}

	// §4.5 (1): every session, including one nobody asked about.
	if _, err := h.client.GetUser(ctx, read(&identityv1.GetUserRequest{}, bearer)); err == nil {
		t.Error("the bearer token minted before the reset still resolves; a reset exists " +
			"because control may have been lost, and keeping a session assumes the opposite")
	} else if code := connectrpc.CodeOf(err); code != connectrpc.CodeUnauthenticated {
		t.Errorf("the pre-reset session failed with %v, want unauthenticated", code)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		live := h.liveSessionCount(t, account.subjectID)
		if live == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Errorf("session_view still shows %d live session(s) 30s after the reset", live)
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	// The old password is dead.
	if _, err := h.client.CreateSession(ctx, write(&identityv1.CreateSessionRequest{
		Identifier: email,
		Password:   oldPassword,
		Code:       h.freshCode(t, secret),
		DeviceId:   "dev_reset_" + h.suffix,
	})); err == nil {
		t.Error("the password that was reset still authenticates")
	}

	// §4.5 (4): the new password ALONE still cannot sign in. This is the clause
	// that converts "the attacker controls the mailbox" into full account
	// takeover when it is broken, and it is the most commonly broken one.
	if _, err := h.client.CreateSession(ctx, write(&identityv1.CreateSessionRequest{
		Identifier: email,
		Password:   newPassword,
		DeviceId:   "dev_reset_" + h.suffix,
	})); err == nil {
		t.Fatal("the new password alone minted a session; the reset bypassed the account's " +
			"second factor (ASVS 5.0 V6.4.3)")
	} else {
		t.Logf("the new password alone is refused: code=%v", connectrpc.CodeOf(err))
	}

	// And with the factor the account still has, it works — so the reset changed
	// the credential and nothing else.
	after, err := h.client.CreateSession(ctx, write(&identityv1.CreateSessionRequest{
		Identifier: email,
		Password:   newPassword,
		Code:       h.freshCode(t, secret),
		DeviceId:   "dev_reset_" + h.suffix,
	}))
	if err != nil {
		t.Fatalf("the new password with the account's own second factor was refused: %v\n%s",
			err, h.serverLogs())
	}
	if got := after.Msg.GetAssuranceLevel(); got < optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2 {
		t.Errorf("the post-reset session is %v, below AAL2", got)
	}
	if after.Msg.GetToken() == bearer {
		t.Error("the post-reset session reuses the revoked bearer token")
	}

	// The account is unchanged in every other respect.
	if state := h.awaitAccount(t, index).state; state != "active" {
		t.Errorf("the account is %q after a reset, want active and untouched", state)
	}

	// The log records it once, as a reset.
	total, viaReset := countPasswordChanges(t, account.userID)
	if total != 1 || viaReset != 1 {
		t.Errorf("the account's stream carries %d PasswordChanged event(s), %d of them "+
			"ViaReset; want exactly 1 and 1", total, viaReset)
	}

	// Single-use, against the real DELETE … RETURNING.
	if _, err := h.client.ResetPassword(ctx, write(&identityv1.ResetPasswordRequest{
		Token:    resetToken,
		Password: "a-third-passphrase",
	})); err == nil {
		t.Error("a spent reset link was accepted a second time")
	}
	if total, _ := countPasswordChanges(t, account.userID); total != 1 {
		t.Errorf("the replayed link produced a second PasswordChanged")
	}
}

// TestResetMailAndVerificationMailShareOneAddressBudget is the assertion
// NOTIFICATIONS.md §4 asks for: "an hourly ceiling per address across ALL
// classes".
//
// It is only true if both endpoints increment the SAME Valkey key. If reset mail
// had its own budget, an attacker with two endpoints would alternate between
// them and double the mail one victim receives — and every unit test would still
// pass, because each limiter would be correctly enforcing its own half.
//
// Spent across the two endpoints deliberately: two resends and one reset request
// exhaust the documented ceiling of three, and the fourth call is refused
// whichever endpoint it arrives at.
func TestResetMailAndVerificationMailShareOneAddressBudget(t *testing.T) {
	clearCallerCeiling(t)
	ctx := context.Background()

	email := h.freshEmail("reset-shared-budget")
	if _, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: email,
	})); err != nil {
		t.Fatalf("Register: %v\n%s", err, h.serverLogs())
	}
	h.awaitAccount(t, h.emailIndex(t, email))

	// Registration itself does not spend the ceiling — it is not a triggered
	// resend — so the budget starts whole. Two resends and one reset request
	// exhaust the documented 3/hour.
	for i := 1; i <= 2; i++ {
		if _, err := h.client.ResendEmailVerification(ctx, write(
			&identityv1.ResendEmailVerificationRequest{Email: email},
		)); err != nil {
			t.Fatalf("resend #%d, within the ceiling: %v\n%s", i, err, h.serverLogs())
		}
	}
	if _, err := h.client.RequestPasswordReset(ctx, write(
		&identityv1.RequestPasswordResetRequest{Email: email},
	)); err != nil {
		t.Fatalf("the third triggered mail for this address was refused: %v\n%s",
			err, h.serverLogs())
	}

	// The fourth is refused, and it is refused at BOTH endpoints — which is only
	// possible if the counter is shared.
	_, refusedReset := h.client.RequestPasswordReset(ctx, write(
		&identityv1.RequestPasswordResetRequest{Email: email},
	))
	if refusedReset == nil {
		t.Fatal("a fourth triggered mail for one address was accepted at the reset " +
			"endpoint; reset mail has its own budget, so an attacker can double a " +
			"victim's mail by alternating endpoints")
	}
	if code := connectrpc.CodeOf(refusedReset); code != connectrpc.CodeResourceExhausted {
		t.Errorf("the over-ceiling reset request was refused with %v, want resource_exhausted",
			code)
	}
	_, refusedResend := h.client.ResendEmailVerification(ctx, write(
		&identityv1.ResendEmailVerificationRequest{Email: email},
	))
	if refusedResend == nil {
		t.Error("a resend was accepted after the shared per-address budget was spent " +
			"partly by a reset request")
	}
	t.Logf("both endpoints refuse the fourth message for one address: reset=%v resend=%v",
		connectrpc.CodeOf(refusedReset), connectrpc.CodeOf(refusedResend))
}

// TestTheResetCeilingRefusesAnUnknownAddressIdentically keeps the visible
// rate-limit refusal from becoming the enumeration oracle the empty response
// exists to prevent.
//
// If the ceiling were spent only once an account had been found, a caller could
// tell a registered address from an unregistered one by how many requests it
// takes to be refused: three for a real account, unlimited for a stranger.
func TestTheResetCeilingRefusesAnUnknownAddressIdentically(t *testing.T) {
	clearCallerCeiling(t)
	ctx := context.Background()
	unknown := h.freshEmail("reset-ceiling-nobody")

	for i := 1; i <= 3; i++ {
		if _, err := h.client.RequestPasswordReset(ctx, write(
			&identityv1.RequestPasswordResetRequest{Email: unknown},
		)); err != nil {
			t.Fatalf("reset request #%d for an address nothing claims was refused with %v; "+
				"a stranger's address must consume the ceiling exactly as a real one does, "+
				"or the refusal count discloses which addresses are registered",
				i, connectrpc.CodeOf(err))
		}
	}
	_, refused := h.client.RequestPasswordReset(ctx, write(
		&identityv1.RequestPasswordResetRequest{Email: unknown},
	))
	if refused == nil {
		t.Fatal("a fourth reset request for an unregistered address was accepted while " +
			"the same request for a registered one is refused; the ceiling is an " +
			"enumeration oracle")
	}
	if code := connectrpc.CodeOf(refused); code != connectrpc.CodeResourceExhausted {
		t.Errorf("refused with %v, want resource_exhausted", code)
	}
}

// TestTheResetSchemaIsEnforcedBeforeTheHandler proves the protovalidate rules on
// ResetPasswordRequest are actually running in the deployed interceptor chain.
//
// They are declared on the message, so they are only real if the validation
// interceptor is wired — and a rule that is declared and not enforced is exactly
// the shape of gap this repository keeps finding. The refusals also matter on
// their own: they run BEFORE the handler, so a caller who typed a short password
// keeps their link.
func TestTheResetSchemaIsEnforcedBeforeTheHandler(t *testing.T) {
	ctx := context.Background()

	tests := map[string]*identityv1.ResetPasswordRequest{
		"no token": {
			Password: "a-perfectly-fine-passphrase",
		},
		"a password below the eight-character floor": {
			Token:    "not-a-real-token-but-well-formed",
			Password: "short",
		},
	}
	for name, req := range tests {
		_, err := h.client.ResetPassword(ctx, write(req))
		if err == nil {
			t.Errorf("%s was accepted; the protovalidate rules on ResetPasswordRequest "+
				"are declared but not enforced", name)
			continue
		}
		if code := connectrpc.CodeOf(err); code != connectrpc.CodeInvalidArgument {
			t.Errorf("%s was refused with %v, want invalid_argument", name, code)
		}
	}

	// And the same for the request side's address rules.
	if _, err := h.client.RequestPasswordReset(ctx, write(
		&identityv1.RequestPasswordResetRequest{Email: "not-an-address"},
	)); err == nil {
		t.Error("a malformed address was accepted by RequestPasswordReset")
	} else if code := connectrpc.CodeOf(err); code != connectrpc.CodeInvalidArgument {
		t.Errorf("a malformed address was refused with %v, want invalid_argument", code)
	}
}

// TestTwoConcurrentResetsOverRealInfrastructure proves the property its unit
// counterpart cannot.
//
// `app.TestTwoConcurrentResetsProduceExactlyOnePasswordChange` used to assert
// that exactly one of two concurrent resets wins, and it was 60% flaky — because
// the mechanism that decides the winner is the expected-revision precondition on
// the account stream, and the unit suite's fake appender ignores `Expected`
// entirely and succeeds for every call. The assertion was made against a fake
// with no optimistic concurrency in it, so it passed only when the interleaving
// happened to let the winner's token sweep beat the loser's consume.
//
// Here the append goes to a real KurrentDB, so the precondition is real. Two
// live reset links — one an attacker triggered, one the victim did — race, and
// the assertion is made against the EVENT LOG rather than a projection, for the
// reason ADR-054 records: a unique index in a read model can conceal a duplicate
// while killing the projector, and the test that guarded it passed throughout.
func TestTwoConcurrentResetsOverRealInfrastructure(t *testing.T) {
	ctx := context.Background()
	email := h.freshEmail("reset-race")
	const oldPassword = "correct-horse-battery-staple-51"

	index := h.emailIndex(t, email)
	account := h.registerThroughTheKernel(t, email)
	if _, err := h.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
		Token:    h.mintVerificationToken(t, account.subjectID),
		Password: oldPassword,
		Username: h.freshUsername("resetrace"),
	})); err != nil {
		t.Fatalf("VerifyEmail: %v\n%s", err, h.serverLogs())
	}
	h.awaitVerified(t, index)

	// The log position BEFORE the race, so the count below sees only this test's
	// appends and cannot be perturbed by anything another test wrote.
	from := h.logTail(t)

	// Two links, minted before either is redeemed, exactly as two independent
	// RequestPasswordReset calls would leave the account.
	first := h.mintResetToken(t, account.subjectID)
	second := h.mintResetToken(t, account.subjectID)

	type outcome struct {
		password string
		err      error
	}
	results := make(chan outcome, 2)
	var start sync.WaitGroup
	start.Add(1)
	for i, pair := range []struct{ token, password string }{
		{first, "race-first-passphrase-2026"},
		{second, "race-second-passphrase-2026"},
	} {
		go func(i int, token, password string) {
			start.Wait()
			_, err := h.client.ResetPassword(ctx, write(&identityv1.ResetPasswordRequest{
				Token:    token,
				Password: password,
			}))
			results <- outcome{password: password, err: err}
		}(i, pair.token, pair.password)
	}
	start.Done()

	var winners []string
	var refused int
	for range 2 {
		got := <-results
		if got.err == nil {
			winners = append(winners, got.password)
			continue
		}
		refused++
		t.Logf("one reset was refused: code=%v", connectrpc.CodeOf(got.err))
	}
	t.Logf("winners=%d refused=%d", len(winners), refused)

	// THE assertion, against the log. Two PasswordChanged events for one account
	// from two concurrent resets means the loser overwrote the winner, and the
	// password that ends up on the account was decided by scheduling rather than
	// by the person holding the link.
	changes := h.passwordChangesFor(t, account.userID, from)
	if changes != 1 {
		t.Fatalf("the log carries %d PasswordChanged events for two concurrent resets, "+
			"want exactly 1; %d call(s) succeeded and %d were refused",
			changes, len(winners), refused)
	}
	if len(winners) != 1 {
		t.Errorf("%d resets reported success while the log recorded one change; a caller "+
			"was told its password was set when another reset's password is what stands",
			len(winners))
	}
}

// passwordChangesFor counts PasswordChanged events for one account in $all since
// `from`.
//
// $all rather than the account's own stream, and rather than any projection, for
// the reason accountsRegisteredFor gives: the log is consistent the moment the
// append returns, and it cannot filter a duplicate out of sight.
func (hh *harness) passwordChangesFor(
	t *testing.T, userID string, from kurrentdb.AllPosition,
) int {
	t.Helper()
	rs, err := hh.kurrent.ReadAll(context.Background(), kurrentdb.ReadAllOptions{
		Direction: kurrentdb.Forwards, From: from,
	}, ^uint64(0))
	if err != nil {
		t.Fatalf("reading $all: %v", err)
	}
	defer rs.Close()

	changed := new(contract.PasswordChanged)
	want := "user-" + userID
	count := 0
	for {
		ev, err := rs.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reading $all: %v", err)
		}
		if ev.Event == nil || ev.Event.EventType != changed.EventType() {
			continue
		}
		if ev.Event.StreamID == want {
			count++
		}
	}
	return count
}
