//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	identitypg "github.com/chronos/chronos-go/internal/modules/identity/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The emailed-token store, against the real schema.
//
// # Why this file exists
//
// Single use is the entire security value of a verification link and of a
// password-reset link, and it lives in ONE SQL statement — `ConsumeToken`'s
// `DELETE … RETURNING`. Nothing in this repository asserted it against a real
// database until now, and the gap was found by mutation: rewriting that
// statement as a plain `SELECT` left every test in the tree green, because the
// two flows that redeem a token each have a SECOND mechanism that happens to
// hide it. A password reset sweeps every token for the subject immediately after
// consuming one, and a verification issues a fresh token that revokes the last.
//
// Defence in depth is good; a property that only one layer enforces and no test
// can see is not. These tests drive the store directly, so the statement is the
// only thing standing between them and a multi-use credential.

func newGuards(t *testing.T) *identitypg.Guards {
	t.Helper()
	guards, err := identitypg.NewGuards(pgadapter.New(openPool(t)))
	if err != nil {
		t.Fatalf("building the guards: %v", err)
	}
	return guards
}

// randomDigest is a fresh 32-byte value per call.
//
// Deliberately NOT digestOf's deterministic pattern: the digest is
// identity_token's PRIMARY KEY and nothing here truncates the table, so a fixed
// fixture makes the second run of this file collide with the first. That is not
// hypothetical — it happened while these tests were being written, and the
// failure ("duplicate key value violates identity_token_pkey") reads as a broken
// store rather than as a test that cannot run twice.
func randomDigest(t *testing.T) []byte {
	t.Helper()
	out := make([]byte, 32)
	if _, err := io.ReadFull(ids.Entropy(), out); err != nil {
		t.Fatalf("entropy: %v", err)
	}
	return out
}

func newGuardsOn(t *testing.T, pool *pgxpool.Pool) *identitypg.Guards {
	t.Helper()
	guards, err := identitypg.NewGuards(pgadapter.New(pool))
	if err != nil {
		t.Fatalf("building the guards: %v", err)
	}
	return guards
}

// TestAnEmailedTokenIsRedeemableExactlyOnce is the property an intercepted link
// depends on being false.
//
// Asserted here rather than through a flow, because both flows that redeem a
// token would still pass with the statement broken: the reset voids every token
// for the subject a moment later, and a re-issue revokes the previous one. Only a
// direct redemption can tell whether the statement itself is single-use.
func TestAnEmailedTokenIsRedeemableExactlyOnce(t *testing.T) {
	ctx := context.Background()
	guards := newGuards(t)
	subject := testSubject(t)
	digest := randomDigest(t)
	now := time.Now().UTC()

	if err := guards.Issue(ctx, app.PurposePasswordReset, subject, digest,
		now.Add(time.Hour)); err != nil {
		t.Fatalf("issuing: %v", err)
	}

	got, err := guards.Consume(ctx, app.PurposePasswordReset, digest, now)
	if err != nil {
		t.Fatalf("the first redemption failed: %v", err)
	}
	if got != subject {
		t.Errorf("redeemed for subject %q, want %q", got, subject)
	}

	if _, err := guards.Consume(ctx, app.PurposePasswordReset, digest, now); !errors.Is(err, app.ErrTokenNotFound) {
		t.Fatalf("a spent token was redeemed a second time (err=%v); the link in an "+
			"intercepted mail stays live and a single-use credential is multi-use", err)
	}
}

// TestOneTokenPresentedConcurrentlyHasExactlyOneWinner is the concurrency the
// single-statement design exists for.
//
// A SELECT followed by a DELETE lets two simultaneous clicks of one link both
// observe it as unused and both succeed — and that concurrency is not
// hypothetical, it is what a mail client prefetching a link and a person clicking
// it produce between them, and what an attacker relaying one engineers.
func TestOneTokenPresentedConcurrentlyHasExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	// One pool shared by every racer, so they contend inside PostgreSQL rather
	// than being serialised by a single connection.
	pool := openPool(t)
	guards := newGuardsOn(t, pool)
	subject := testSubject(t)
	digest := randomDigest(t)
	now := time.Now().UTC()

	if err := guards.Issue(ctx, app.PurposePasswordReset, subject, digest,
		now.Add(time.Hour)); err != nil {
		t.Fatalf("issuing: %v", err)
	}

	const racers = 8
	var (
		start sync.WaitGroup
		done  sync.WaitGroup
		mu    sync.Mutex
		won   int
		other []error
	)
	start.Add(1)
	for range racers {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			_, err := guards.Consume(ctx, app.PurposePasswordReset, digest, now)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				won++
			case errors.Is(err, app.ErrTokenNotFound):
			default:
				other = append(other, err)
			}
		}()
	}
	start.Done()
	done.Wait()

	if len(other) > 0 {
		t.Fatalf("%d racer(s) failed for a reason other than the token being spent: %v",
			len(other), other)
	}
	if won != 1 {
		t.Fatalf("%d of %d simultaneous presentations of ONE token succeeded, want exactly 1",
			won, racers)
	}
}

// TestAnExpiredTokenIsIndistinguishableFromAnUnknownOne keeps the expiry check
// inside the statement.
//
// A caller that checked the deadline itself would have to read the row first,
// and then "this token was valid but has expired" becomes an answer it can give
// — which confirms that the address the link was sent to has an account.
func TestAnExpiredTokenIsIndistinguishableFromAnUnknownOne(t *testing.T) {
	ctx := context.Background()
	guards := newGuards(t)
	subject := testSubject(t)
	digest := randomDigest(t)
	now := time.Now().UTC()

	if err := guards.Issue(ctx, app.PurposePasswordReset, subject, digest,
		now.Add(-time.Minute)); err != nil {
		t.Fatalf("issuing: %v", err)
	}

	_, expired := guards.Consume(ctx, app.PurposePasswordReset, digest, now)
	_, unknown := guards.Consume(ctx, app.PurposePasswordReset, randomDigest(t), now)
	if !errors.Is(expired, app.ErrTokenNotFound) {
		t.Fatalf("an expired token was redeemed: %v", expired)
	}
	if !errors.Is(unknown, app.ErrTokenNotFound) {
		t.Fatalf("an unknown token produced %v, want ErrTokenNotFound", unknown)
	}
	if expired.Error() != unknown.Error() {
		t.Errorf("expired says %q and unknown says %q; the difference confirms that the "+
			"address the link was sent to has an account", expired, unknown)
	}
}

// TestATokenIssuedForOnePurposeCannotBeRedeemedUnderAnother.
//
// The purpose is mixed into the digest by adapter/token, so in production the two
// forms differ before they reach this store. The column filter is the second
// layer, and it is the one asserted here: a store that ignored it would let a
// caller who obtained a VERIFICATION digest — by any means — redeem it as a
// password reset.
func TestATokenIssuedForOnePurposeCannotBeRedeemedUnderAnother(t *testing.T) {
	ctx := context.Background()
	guards := newGuards(t)
	subject := testSubject(t)
	digest := randomDigest(t)
	now := time.Now().UTC()

	if err := guards.Issue(ctx, app.PurposeEmailVerification, subject, digest,
		now.Add(time.Hour)); err != nil {
		t.Fatalf("issuing: %v", err)
	}
	if _, err := guards.Consume(ctx, app.PurposePasswordReset, digest, now); !errors.Is(err, app.ErrTokenNotFound) {
		t.Fatalf("a verification digest was redeemed as a password reset (err=%v)", err)
	}
	// And it is still redeemable under its own purpose, so the refusal above was
	// the filter rather than the row having gone missing.
	if _, err := guards.Consume(ctx, app.PurposeEmailVerification, digest, now); err != nil {
		t.Fatalf("the token is not redeemable under its own purpose: %v", err)
	}
}

// TestRevokeAllPurposesSweepsEveryPurposeAndOnlyThisSubject is identity.md
// §4.5's "void every outstanding token of every purpose".
//
// The two halves are asserted together on purpose. A statement that swept every
// purpose but ignored the subject would void the whole system's outstanding
// links on every reset, which is a denial of service with no error anywhere; one
// that scoped correctly but filtered by purpose would leave the trojan
// verification link the rule exists to kill.
func TestRevokeAllPurposesSweepsEveryPurposeAndOnlyThisSubject(t *testing.T) {
	ctx := context.Background()
	guards := newGuards(t)
	mine, theirs := testSubject(t), testSubject(t)
	now := time.Now().UTC()

	myReset := randomDigest(t)
	myVerification := randomDigest(t)
	theirVerification := randomDigest(t)
	for _, tok := range []struct {
		purpose app.TokenPurpose
		subject string
		digest  []byte
	}{
		{app.PurposePasswordReset, mine, myReset},
		{app.PurposeEmailVerification, mine, myVerification},
		{app.PurposeEmailVerification, theirs, theirVerification},
	} {
		if err := guards.Issue(ctx, tok.purpose, tok.subject, tok.digest,
			now.Add(time.Hour)); err != nil {
			t.Fatalf("issuing: %v", err)
		}
	}

	swept, err := guards.RevokeAllPurposes(ctx, mine)
	if err != nil {
		t.Fatalf("sweeping: %v", err)
	}
	if swept != 2 {
		t.Errorf("the sweep removed %d token(s), want both of this subject's", swept)
	}
	if _, err := guards.Consume(ctx, app.PurposePasswordReset, myReset, now); !errors.Is(err, app.ErrTokenNotFound) {
		t.Errorf("the subject's reset token survived the sweep: %v", err)
	}
	if _, err := guards.Consume(ctx, app.PurposeEmailVerification, myVerification, now); !errors.Is(err, app.ErrTokenNotFound) {
		t.Error("the subject's VERIFICATION token survived a cross-purpose sweep; a reset " +
			"leaves a live link an attacker triggered, which is the trojan-identifier variant")
	}
	if _, err := guards.Consume(ctx, app.PurposeEmailVerification, theirVerification, now); err != nil {
		t.Errorf("another subject's token was swept: %v; a reset would take out every "+
			"outstanding link in the system", err)
	}
}

// RevokeAllPurposes refuses an empty subject rather than executing.
//
// It matches no row in this statement, but the refusal belongs at the boundary
// rather than in the WHERE clause's luck: the same mistake against a store that
// treated an empty scope as a wildcard would delete every outstanding token
// there is.
func TestRevokeAllPurposesRefusesAnEmptySubject(t *testing.T) {
	guards := newGuards(t)
	if _, err := guards.RevokeAllPurposes(context.Background(), ""); err == nil {
		t.Fatal("revoking every token for an empty subject was accepted")
	}
}
