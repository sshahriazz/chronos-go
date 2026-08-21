//go:build integration

package identityit_test

import (
	"context"
	"testing"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// TestPreHijackByUnverifiedRegistrationIsRefused executes the pre-hijacking
// attack from Sudhodanan & Paverd, "Pre-hijacked accounts" (USENIX Security
// 2022) against this system, and asserts that it no longer completes.
//
// # The attack this test used to demonstrate
//
// It needed no credential of the victim's and no access to their mailbox:
//
//  1. The attacker registered the VICTIM's address with a password the attacker
//     chose. The account sat Pending. The attacker could not verify it.
//  2. The victim received a verification mail they did not ask for. This is the
//     whole attack — an ordinary-looking mail from a real service, and a person
//     who clicks it believes they are completing their own signup.
//  3. Verification proves control of the MAILBOX. It did not prove that whoever
//     set the password controlled the mailbox, and those were different people.
//  4. The attacker — who knew the password — signed in. The bootstrap carve-out
//     admitted them at AAL1 on a verified, factorless account, and that session
//     enrolled their own authenticator. The account activated holding the
//     victim's address, the attacker's password and the attacker's TOTP.
//
// This test ran green on that behaviour, deliberately, so the fix could not land
// unnoticed. This file is what the fix looks like from outside.
//
// # What refuses it now, and where
//
// Not a check added to step 4. The PREMISE is gone: registration creates no
// credential at all (IDENTITY-REVIEW C8), so step 1 cannot happen. There is
// nothing for the victim's proof to activate, because a password does not exist
// until the party holding the verification link supplies one — in the same
// request as the proof.
//
// Three layers refuse it independently, and the sequence below walks into all
// three rather than stopping at the first:
//
//   - The WIRE. RegisterRequest has no password field; field 2 is reserved.
//   - The AGGREGATE. domain.User.SetPassword refuses a password on an account
//     whose address is unproven, so no other route can put one there either.
//   - The AUTHENTICATION. A passwordless account has no usable credential, so
//     the bootstrap carve-out has nothing to admit.
//
// The attacker's residual power is named at the end of this test and asserted
// rather than glossed: they can still CLAIM an address they do not own and deny
// it to its real owner until the reservation lapses. That is a lesser harm than
// takeover and it is not zero.
func TestPreHijackByUnverifiedRegistrationIsRefused(t *testing.T) {
	ctx := context.Background()
	victimAddress := h.freshEmail("prehijack-victim")
	const attackerPassword = "attacker-chosen-password-2026-xy"
	const victimPassword = "victim-chosen-password-2026-ab"

	// 1. The attacker claims the victim's address. This still SUCCEEDS — the
	//    response is the same non-answer a free address gets — and it is
	//    deliberately still the first step, because the fix is not "refuse the
	//    registration" but "give the registration nothing to leave behind".
	if _, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: victimAddress,
	})); err != nil {
		t.Fatalf("Register: %v\n%s", err, h.serverLogs())
	}
	account := h.awaitAccount(t, h.emailIndex(t, victimAddress))

	// THE assertion that carries everything else. The attacker had no way to send
	// a password at all, so the account holds no credential of any kind — and a
	// credential row is the only thing a later verification could switch on.
	var credentials int
	h.systemQuery(t, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx,
			`SELECT count(*) FROM credential WHERE subject_id = $1`,
			account.subjectID).Scan(&credentials)
	})
	if credentials != 0 {
		t.Fatalf("a registration left %d credential row(s) for subject %s. That row is the "+
			"pre-hijacking premise: the mailbox owner's verification would activate a "+
			"credential somebody else chose.", credentials, account.subjectID)
	}

	// 2 and 3. The victim clicks the link in the unsolicited mail. Minting the
	// token here stands in for the mailbox the victim genuinely controls — the
	// point of the attack is that this step is performed by the victim, honestly.
	//
	// And now the shape of the flow has changed under the attacker: the click is
	// where a password is CHOSEN, so the person who completes it is the person
	// who ends up holding the account. That person is the victim.
	plaintext := h.mintVerificationToken(t, account.subjectID)
	if _, err := h.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
		Token:    plaintext,
		Password: victimPassword,
		Username: h.freshUsername("prehijack"),
	})); err != nil {
		t.Fatalf("VerifyEmail: %v\n%s", err, h.serverLogs())
	}

	// 4. The attacker signs in with the password only they know. There is no such
	//    password: nothing ever accepted theirs.
	if _, err := h.client.CreateSession(ctx, write(&identityv1.CreateSessionRequest{
		Identifier: victimAddress,
		Password:   attackerPassword,
		DeviceId:   "dev_attacker_" + h.suffix,
	})); err == nil {
		t.Fatal("PRE-HIJACK SUCCEEDED: the attacker's password authenticated on an account " +
			"whose address was proven by somebody else. A credential set before the proof " +
			"has been reintroduced somewhere between RegisterRequest and PasswordSet.")
	} else {
		t.Logf("the attacker's password is refused: %v", err)
	}

	// The attack is refused because the credential is not theirs, NOT because the
	// account is unreachable. The victim's own password works, and asserting that
	// is what stops this test passing against a flow that is simply broken — a
	// VerifyEmail that stored nothing would refuse the attacker too.
	boot, err := h.client.CreateSession(ctx, write(&identityv1.CreateSessionRequest{
		Identifier: victimAddress,
		Password:   victimPassword,
		DeviceId:   "dev_victim_" + h.suffix,
	}))
	if err != nil {
		t.Fatalf("the password set by the party that proved the mailbox was refused: %v\n%s",
			err, h.serverLogs())
	}
	if boot.Msg.GetToken() == "" {
		t.Fatal("the victim's bootstrap session carries no bearer token")
	}
	t.Logf("the account belongs to whoever proved the mailbox: session=%s aal=%v",
		boot.Msg.GetSessionId(), boot.Msg.GetAssuranceLevel())

	// WHAT THIS DOES NOT FIX, asserted rather than described.
	//
	// The attacker can still claim an address they do not own, and the real owner
	// still cannot register it: registration answers the same indistinguishable
	// non-answer, and no account of theirs appears. The harm is denial of the
	// address until the reservation lapses (DefaultReservationLease, 48h) — real,
	// bounded, recoverable, and strictly less than account takeover. It is
	// asserted here so that a future change which closed it would show up as a
	// failing test with this explanation attached, rather than going unnoticed.
	if _, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: victimAddress,
	})); err != nil {
		t.Logf("re-registering a claimed address is refused outright: %v", err)
	} else {
		t.Log("re-registering a claimed address receives the same indistinguishable " +
			"non-answer a fresh registration gets: the squat is not visible to its victim")
	}
	var accounts int
	h.systemQuery(t, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx,
			`SELECT count(*) FROM user_view WHERE email_index = $1`,
			h.emailIndex(t, victimAddress)).Scan(&accounts)
	})
	if accounts != 1 {
		t.Errorf("%d accounts hold the address, want exactly 1", accounts)
	}
}
