//go:build integration

package identityit_test

import (
	"context"
	"strings"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/token"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// mintChangeToken issues a token of an email-change purpose directly.
//
// Identical in shape and in justification to mintVerificationToken: production
// mints these inside the email-change reactor and mails them, and a test that
// waited for the mail would be asserting the mail adapter. The token comes from
// the SAME token.New() and guards.Issue() the server uses, so what is
// short-circuited is the delivery and not the credential — one of these is
// indistinguishable from a real one to everything downstream.
//
// It reads the SERVER's clock for mintVerificationToken's reason: the expiry is
// written here and checked there, so minting against wall time while the server
// runs ahead silently shortens the TTL by however far this suite has travelled.
func (hh *harness) mintChangeToken(
	t *testing.T, purpose app.TokenPurpose, subjectID string,
) string {
	t.Helper()
	minted, err := token.New().Mint(purpose, h.serverNow(t))
	if err != nil {
		t.Fatalf("minting a %s token: %v", purpose, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := hh.guards.Issue(ctx, purpose, subjectID, minted.Digest, minted.ExpiresAt); err != nil {
		t.Fatalf("issuing a %s token: %v", purpose, err)
	}
	return minted.Plaintext
}

// vaultAddress reads what the vault holds for a subject in one field.
//
// The ONE place in this suite that decrypts an address, and it exists because
// the property under test is exactly "which mailbox does this account's mail go
// to now". Nothing in the production path can answer it: identity's vault port
// is write-only by design, and the address book's moves happen inside the
// adapter.
func (hh *harness) vaultAddress(t *testing.T, subjectID string, field pii.Field) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	profile, err := hh.vault.Profile(ctx, pii.SubjectID(subjectID))
	if err != nil {
		t.Fatalf("reading the vault for %s: %v", subjectID, err)
	}
	return profile.Get(field)
}

// awaitEmailIndex waits for user_view to name a particular address index for a
// subject.
//
// It waits on the SUBJECT rather than on the index, which is the whole point:
// the question is "has the projection followed the account to its new address",
// and asking by index would find the row only once the answer was already yes.
func (hh *harness) awaitEmailIndex(t *testing.T, subjectID, wantIndex string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var got string
	for time.Now().Before(deadline) {
		h.systemQuery(t, func(ctx context.Context, q db.Querier) error {
			err := q.QueryRow(ctx,
				`SELECT email_index FROM user_view WHERE subject_id = $1`, subjectID).Scan(&got)
			if err != nil && strings.Contains(err.Error(), "no rows") {
				return nil
			}
			return err
		})
		if got == wantIndex {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("user_view still names a different address for %s after 30s. "+
		"AccountByEmailIndex reads that table, so this account cannot sign in with "+
		"its new address while whoever caused the change can still sign in with the "+
		"old one\n%s", subjectID, h.serverLogs())
}

// changeFixture is an activated account holding an AAL2 session.
type changeFixture struct {
	email     string
	index     string
	subjectID string
	bearer    string
	password  string
	secret    string
}

func (hh *harness) accountForChange(t *testing.T, tag string) changeFixture {
	t.Helper()
	const password = "correct-horse-battery-staple-55"

	email := h.freshEmail(tag)
	row := h.registerThroughTheKernel(t, email)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := h.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
		Token:    h.mintVerificationToken(t, row.subjectID),
		Password: password,
		Username: h.freshUsername(tag),
	})); err != nil {
		t.Fatalf("VerifyEmail: %v\n%s", err, h.serverLogs())
	}

	// AAL2, and the bootstrap session is NOT enough. RequestEmailChange declares
	// min_aal = ASSURANCE_LEVEL_2 with no bootstrap_min_aal, because identity.md
	// §4.3 lists an email change among the step-up operations and an account with
	// no second factor has no business moving its recovery address.
	//
	// The first version of this fixture stopped at bootstrapFirstFactor and every
	// test in this file failed with "this action requires a stronger
	// authentication level" — which is the gate working. Hence two calls: enrol a
	// factor, then sign in again with a code.
	_, secret := h.bootstrapFirstFactor(t, email, password)
	session := h.signIn(t, email, password, secret)

	return changeFixture{
		email:     email,
		index:     h.emailIndex(t, email),
		subjectID: row.subjectID,
		bearer:    session.bearer,
		password:  password,
		secret:    secret,
	}
}

// THE WHOLE FLOW, AGAINST REAL INFRASTRUCTURE.
//
// # What only this test can settle
//
// Every property below is one that unit tests assert about ONE component and
// that nothing proves holds end to end:
//
//   - The claim on the new address really contends on its own KurrentDB stream.
//   - The account, the new claim and the old one really move in one append, so
//     a reader of the log never sees an account pointing at an unconfirmed
//     address.
//   - user_view really follows the account to its new address, which is what
//     makes signing in with it possible at all.
//   - The VAULT really moves, so the person's mail really goes to the new
//     mailbox — and the old address is really recoverable for the revert.
//   - The sessions held before the change are really dead afterwards.
func TestAnEmailChangeMovesTheAccountEndToEnd(t *testing.T) {
	account := h.accountForChange(t, "change")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	newEmail := h.freshEmail("change-target")
	newIndex := h.emailIndex(t, newEmail)

	if _, err := h.client.RequestEmailChange(ctx, writeAuth(
		&identityv1.RequestEmailChangeRequest{NewEmail: newEmail}, account.bearer)); err != nil {
		t.Fatalf("RequestEmailChange: %v\n%s", err, h.serverLogs())
	}

	// NOTHING has moved. The account still answers to its old address and the
	// caller is still signed in — the new address has been claimed and proven by
	// nobody.
	h.awaitEmailIndex(t, account.subjectID, account.index)
	if got := h.vaultAddress(t, account.subjectID, pii.FieldEmail); got != account.email {
		t.Fatalf("the vault's primary address became %q on REQUEST; an attacker holding "+
			"a session has just taken the account by naming an address", got)
	}
	if staged := h.vaultAddress(t, account.subjectID, pii.FieldPendingEmail); staged != newEmail {
		t.Fatalf("the pending address is %q, want %q — the reactor has nowhere to mail "+
			"the proof link", staged, newEmail)
	}
	if _, err := h.client.GetUser(ctx, writeAuth(
		&identityv1.GetUserRequest{}, account.bearer)); err != nil {
		t.Fatalf("the caller was signed out by merely REQUESTING a change: %v", err)
	}

	// The link, as the reactor would have mailed it to the new address.
	if _, err := h.client.ConfirmEmailChange(ctx, write(&identityv1.ConfirmEmailChangeRequest{
		Token: h.mintChangeToken(t, app.PurposeEmailChange, account.subjectID),
	})); err != nil {
		t.Fatalf("ConfirmEmailChange: %v\n%s", err, h.serverLogs())
	}

	// The account has moved, in the projection AND in the vault.
	h.awaitEmailIndex(t, account.subjectID, newIndex)
	if got := h.vaultAddress(t, account.subjectID, pii.FieldEmail); got != newEmail {
		t.Fatalf("the vault's primary address is %q after a completed change; the log "+
			"says the account moved and its MAIL still goes to the old mailbox", got)
	}
	if got := h.vaultAddress(t, account.subjectID, pii.FieldPreviousEmail); got != account.email {
		t.Fatalf("the previous address is %q, want %q. The revert has nothing to restore "+
			"and the revert MAIL has nowhere to go — which is the address it must reach",
			got, account.email)
	}
	if staged := h.vaultAddress(t, account.subjectID, pii.FieldPendingEmail); staged != "" {
		t.Errorf("the pending address survived the change as %q, so the change link "+
			"stays deliverable after the change completed", staged)
	}

	// §4.4: every session is dead, including the one that asked.
	if _, err := h.client.GetUser(ctx, writeAuth(
		&identityv1.GetUserRequest{}, account.bearer)); err == nil {
		t.Fatal("the session that requested the change still works after it completed. " +
			"That is Sudhodanan & Paverd's unexpired-session variant: an attacker keeps " +
			"a live session across the identifier change they performed")
	} else if connectrpc.CodeOf(err) != connectrpc.CodeUnauthenticated {
		t.Errorf("the old session answered %v, want unauthenticated", connectrpc.CodeOf(err))
	}

	// And signing in with the NEW address works, which is the whole point of the
	// flow. Through the ordinary two-factor path, because the account has a
	// factor and identity never hands such an account a one-factor session.
	h.signIn(t, newEmail, account.password, account.secret)
}

// THE REVERT PUTS EVERYTHING BACK.
//
// The remedy identity.md §12 asks for, exercised through the real handler: an
// attacker holding a session can move the address, and cannot stop the person
// who reads the OLD mailbox from undoing it.
func TestARevertRestoresTheAccountEndToEnd(t *testing.T) {
	account := h.accountForChange(t, "revert")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	newEmail := h.freshEmail("revert-target")
	newIndex := h.emailIndex(t, newEmail)

	if _, err := h.client.RequestEmailChange(ctx, writeAuth(
		&identityv1.RequestEmailChangeRequest{NewEmail: newEmail}, account.bearer)); err != nil {
		t.Fatalf("RequestEmailChange: %v\n%s", err, h.serverLogs())
	}
	if _, err := h.client.ConfirmEmailChange(ctx, write(&identityv1.ConfirmEmailChangeRequest{
		Token: h.mintChangeToken(t, app.PurposeEmailChange, account.subjectID),
	})); err != nil {
		t.Fatalf("ConfirmEmailChange: %v\n%s", err, h.serverLogs())
	}
	h.awaitEmailIndex(t, account.subjectID, newIndex)

	// The link the reactor mails to the address the account moved AWAY from.
	if _, err := h.client.RevertEmailChange(ctx, write(&identityv1.RevertEmailChangeRequest{
		Token: h.mintChangeToken(t, app.PurposeEmailChangeRevert, account.subjectID),
	})); err != nil {
		t.Fatalf("RevertEmailChange: %v\n%s", err, h.serverLogs())
	}

	h.awaitEmailIndex(t, account.subjectID, account.index)
	if got := h.vaultAddress(t, account.subjectID, pii.FieldEmail); got != account.email {
		t.Fatalf("the vault's primary address is %q after a revert, want %q", got, account.email)
	}

	// The account signs in with its ORIGINAL address again.
	h.signIn(t, account.email, account.password, account.secret)

	// And NOT with the one it was moved to. Asserted with the SAME credentials
	// that just worked, so the only difference between the two calls is the
	// address — a failure here cannot be a stale password or a spent code.
	if _, err := h.client.CreateSession(ctx, write(&identityv1.CreateSessionRequest{
		Identifier: newEmail,
		Password:   account.password,
		Code:       h.freshCode(t, account.secret),
		DeviceId:   "dev_should_fail",
	})); err == nil {
		t.Fatal("the account still signs in with the address the revert abandoned; the " +
			"party who moved it retains a way in")
	}
}

// THE OLD ADDRESS IS HELD FOR THE WINDOW, NOT FREED.
//
// The property the whole revert design turns on, and the one that would be
// silently wrong: releasing the old address at the moment of the change lets
// whoever performed it re-register the address immediately, and the revert then
// has nowhere to go back to.
//
// Asserted by having a DIFFERENT party try to register it, through the real
// public Register call.
func TestTheOldAddressCannotBeReRegisteredDuringTheWindow(t *testing.T) {
	account := h.accountForChange(t, "hold")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	newEmail := h.freshEmail("hold-target")
	newIndex := h.emailIndex(t, newEmail)

	if _, err := h.client.RequestEmailChange(ctx, writeAuth(
		&identityv1.RequestEmailChangeRequest{NewEmail: newEmail}, account.bearer)); err != nil {
		t.Fatalf("RequestEmailChange: %v\n%s", err, h.serverLogs())
	}
	if _, err := h.client.ConfirmEmailChange(ctx, write(&identityv1.ConfirmEmailChangeRequest{
		Token: h.mintChangeToken(t, app.PurposeEmailChange, account.subjectID),
	})); err != nil {
		t.Fatalf("ConfirmEmailChange: %v\n%s", err, h.serverLogs())
	}
	h.awaitEmailIndex(t, account.subjectID, newIndex)

	// The reservation stream still holds the old address for this subject, and it
	// carries a deadline rather than being verified — which is what makes the
	// sweep free it when the window closes, with no special machinery.
	var (
		verified  bool
		expiresAt *time.Time
		holder    string
	)
	h.systemQuery(t, func(qctx context.Context, q db.Querier) error {
		return q.QueryRow(qctx, `
			SELECT subject_id, verified, expires_at
			FROM email_reservation_view
			WHERE email_index = $1 AND released_at IS NULL`, account.index).
			Scan(&holder, &verified, &expiresAt)
	})
	if holder != account.subjectID {
		t.Fatalf("the old address is held by %q, want the account that left it", holder)
	}
	if verified {
		t.Fatal("the old address is still VERIFIED, so it never lapses and this account " +
			"holds two addresses forever")
	}
	if expiresAt == nil {
		t.Fatal("the old address has no deadline, so the sweep will never free it")
	}
	if !expiresAt.After(h.serverNow(t)) {
		t.Fatalf("the old address's window already closed at %s; it is available to "+
			"anybody the instant the change lands, and whoever performed the change can "+
			"take it and block the revert", expiresAt)
	}

	// The real test: a stranger cannot claim it. Register answers the same empty
	// response either way (it must not be an existence oracle), so the assertion
	// is on whether the address CHANGED HANDS.
	if _, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: account.email,
	})); err != nil {
		t.Fatalf("Register: %v\n%s", err, h.serverLogs())
	}
	time.Sleep(2 * time.Second)

	var stillHeldBy string
	h.systemQuery(t, func(qctx context.Context, q db.Querier) error {
		return q.QueryRow(qctx, `
			SELECT subject_id FROM email_reservation_view
			WHERE email_index = $1 AND released_at IS NULL`, account.index).Scan(&stillHeldBy)
	})
	if stillHeldBy != account.subjectID {
		t.Fatalf("a registration took the old address during the revert window: it is now "+
			"held by %q. The revert has nowhere to go back to, and an account moved by "+
			"somebody else can never be recovered", stillHeldBy)
	}
}

// A PASSWORD RESET VOIDS A PENDING CHANGE (§4.4).
//
// Sudhodanan & Paverd's "unexpired email change": an attacker queues a change to
// their own address, the victim recovers the account believing they have secured
// it, and the queued change completes afterwards and hands it straight back.
//
// This is the variant that was UNREACHABLE until this flow existed, so it is the
// first time it can be tested at all.
func TestAPasswordResetKillsAPendingEmailChangeEndToEnd(t *testing.T) {
	account := h.accountForChange(t, "resetkill")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	attackerEmail := h.freshEmail("resetkill-attacker")

	// The attacker, holding a session, queues a change to an address they own.
	if _, err := h.client.RequestEmailChange(ctx, writeAuth(
		&identityv1.RequestEmailChangeRequest{NewEmail: attackerEmail}, account.bearer)); err != nil {
		t.Fatalf("RequestEmailChange: %v\n%s", err, h.serverLogs())
	}
	// The link is minted and, in production, is now sitting in the attacker's
	// mailbox. It is minted here BEFORE the reset, which is the honest ordering:
	// the attacker already has it when the victim recovers.
	queued := h.mintChangeToken(t, app.PurposeEmailChange, account.subjectID)

	// The victim recovers the account.
	if _, err := h.client.ResetPassword(ctx, write(&identityv1.ResetPasswordRequest{
		Token:    h.mintResetToken(t, account.subjectID),
		Password: "a-completely-different-passphrase-91",
	})); err != nil {
		t.Fatalf("ResetPassword: %v\n%s", err, h.serverLogs())
	}

	// The queued change must now be dead — twice over. The token is voided by
	// RevokeAllPurposes, and the pending change is voided on the aggregate, so
	// even a token that survived would find nothing to complete.
	if _, err := h.client.ConfirmEmailChange(ctx, write(&identityv1.ConfirmEmailChangeRequest{
		Token: queued,
	})); err == nil {
		t.Fatal("the change queued before the reset COMPLETED afterwards. The victim " +
			"recovered the account believing they had secured it, and it was handed " +
			"straight back to the attacker minutes later")
	}

	// And the account still answers to its own address.
	h.awaitEmailIndex(t, account.subjectID, account.index)
	if got := h.vaultAddress(t, account.subjectID, pii.FieldEmail); got != account.email {
		t.Fatalf("the account's address is %q after the reset should have killed the "+
			"pending change", got)
	}
}
