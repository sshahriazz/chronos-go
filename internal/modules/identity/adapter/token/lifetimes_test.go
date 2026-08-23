package token_test

import (
	"testing"

	"github.com/chronos/chronos-go/internal/modules/identity/adapter/token"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
)

// THE REVERT TOKEN AND THE REVERT WINDOW ARE THE SAME LENGTH.
//
// They are declared in two packages — the aggregate's window in `app`, the
// token's lifetime here — because the adapter owns lifetimes and the use case
// owns policy, and neither may import the other's number. Nothing but this test
// makes them agree, and they fail in two different ways if they drift:
//
//   - Token SHORTER than the window: the link dies while the aggregate still
//     says the change is revertible. The old address is held, unavailable to
//     everyone, for a window nobody can act on — and the person reading the mail
//     clicks a dead link at the moment they most need it to work.
//   - Token LONGER than the window: the link is live and redeems into
//     "the window to undo this address change has closed". Worse than a dead
//     link, because it reads as the system refusing rather than as a timeout.
//
// Neither has a runtime symptom that points at the cause.
func TestTheRevertTokenOutlivesNeitherMoreNorLessThanItsWindow(t *testing.T) {
	if token.RevertTTL != app.DefaultEmailRevertWindow {
		t.Fatalf("the revert TOKEN lives %s and the revert WINDOW is %s. %s",
			token.RevertTTL, app.DefaultEmailRevertWindow,
			map[bool]string{
				true: "The link dies first, so the old address stays held for a window " +
					"nobody can act on and the person reading the mail clicks a dead link.",
				false: "The link outlives the window, so it redeems into a refusal — which " +
					"reads as the system saying no rather than as a timeout.",
			}[token.RevertTTL < app.DefaultEmailRevertWindow])
	}
}

// THE CHANGE TOKEN AND THE PENDING-CHANGE DEADLINE MATCH TOO.
//
// Same argument, milder consequence: a mismatch here costs a request that has to
// be started again rather than an account that cannot be recovered.
func TestTheChangeTokenMatchesThePendingDeadline(t *testing.T) {
	if token.ChangeTTL != app.DefaultEmailChangeTTL {
		t.Fatalf("the change TOKEN lives %s and a pending change lapses after %s; one of "+
			"them expires first and the other's deadline is decoration",
			token.ChangeTTL, app.DefaultEmailChangeTTL)
	}
}

// EVERY PURPOSE THE APP CAN ASK FOR HAS A LIFETIME.
//
// The minter panics at construction on an unknown purpose, which is loud — but
// it is loud in whichever process first tries to MINT one, at request time, in a
// binary that started healthily. This fails at test time instead.
func TestEveryTokenPurposeHasALifetime(t *testing.T) {
	for _, p := range []app.TokenPurpose{
		app.PurposeEmailVerification,
		app.PurposePasswordReset,
		app.PurposeEmailChange,
		app.PurposeEmailChangeRevert,
	} {
		ttl, err := token.TTLFor(p)
		if err != nil {
			t.Errorf("purpose %q has no lifetime: %v. Minting one panics at request "+
				"time, in a process that started healthily", p, err)
			continue
		}
		if ttl <= 0 {
			t.Errorf("purpose %q has a lifetime of %s; every token it mints is already "+
				"expired", p, ttl)
		}
	}
}

// A TOKEN OF ONE PURPOSE DOES NOT DIGEST TO ANOTHER'S.
//
// The purpose is mixed INTO the digest rather than stored beside it, and that
// binding is what stops a verification link — which anyone can cause to be sent
// by registering an address they own — from completing an email change on
// somebody else's account.
func TestPurposesDigestDifferently(t *testing.T) {
	const plaintext = "the-same-bytes-presented-to-both"

	seen := map[string]app.TokenPurpose{}
	for _, p := range []app.TokenPurpose{
		app.PurposeEmailVerification,
		app.PurposePasswordReset,
		app.PurposeEmailChange,
		app.PurposeEmailChangeRevert,
	} {
		key := string(token.Digest(p, plaintext))
		if other, clash := seen[key]; clash {
			t.Fatalf("one token digests identically for %q and %q. A link issued for the "+
				"first is redeemable as the second, so anyone who can cause a %[1]s mail "+
				"holds a live %[2]s credential", other, p)
		}
		seen[key] = p
	}
}
