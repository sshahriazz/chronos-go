//go:build integration

package identityit_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/kurrent-io/KurrentDB-Client-Go/kurrentdb"
	"google.golang.org/protobuf/proto"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
)

// ADR-055 over the real RPC: a registration aimed at an address a VERIFIED
// account already holds answers with the same empty bytes AND puts a notice in
// the log for the holder's mailbox.
//
// The unit tests prove the use case records the right thing. They cannot prove
// the deployed binary does, and this repository has shipped six components that
// were built, tested and constructed by nothing — so the claim is made here,
// against cmd/api as it is actually compiled and wired, over TCP.
//
// # What this test does NOT cover, and why the coverage is elsewhere
//
// The mail. cmd/worker is a separate binary and is not running here, so the
// catalogue entry that turns this event into a message is proven in
// internal/modules/identity/reactor/duplicateregistration_integration_test.go,
// end to end into Mailpit. This half proves the event exists to be caught.
func TestARegistrationOnAClaimedAddressNotifiesItsHolder(t *testing.T) {
	ctx := context.Background()
	account := h.verifiedAccountFor(t, "dup-notice")
	from := h.logTail(t)

	// A fresh address, answered by the same handler in the same run, so the two
	// responses below are comparable as bytes.
	free, errFree := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: h.freshEmail("dup-notice-free"),
	}))
	if errFree != nil {
		t.Fatalf("registering a free address: %v\n%s", errFree, h.serverLogs())
	}

	claimed, errClaimed := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: account.email,
	}))
	if errClaimed != nil {
		t.Fatalf("BUG: registering an address a verified account holds was refused with %v, "+
			"while registering a free one succeeds. That difference IS the "+
			"account-existence oracle the empty RegisterResponse exists to close.",
			errClaimed)
	}

	// Compared as MARSHALLED BYTES rather than field by field. A field added
	// later — "already registered", "check your email", a retry hint — would pass
	// a field-by-field comparison written today and reopen the oracle. This is
	// the assertion the whole notice mechanism had to be built around: the answer
	// goes to the mailbox precisely because it may not go here.
	a, err := proto.Marshal(free.Msg)
	if err != nil {
		t.Fatalf("marshalling the free-address response: %v", err)
	}
	b, err := proto.Marshal(claimed.Msg)
	if err != nil {
		t.Fatalf("marshalling the claimed-address response: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("the responses differ on the wire: free=%x claimed=%x; Register now "+
			"discloses whether an address has an account", a, b)
	}
	t.Logf("both responses marshal to %d identical byte(s)", len(a))

	// And the half that was missing until ADR-055: the holder is told.
	notices := h.duplicateNoticesFor(t, account.index, from)
	if len(notices) != 1 {
		t.Fatalf("%d duplicate-registration notices were appended, want exactly 1. Without "+
			"one the person who owns this mailbox is shown \"check your email\" and sent "+
			"nothing at all", len(notices))
	}
	notice := notices[0]
	if notice.event.SubjectID != account.subjectID {
		t.Errorf("the notice names %q, want the holder %q; the notification kernel resolves "+
			"the mailbox from this, so a wrong one mails a stranger",
			notice.event.SubjectID, account.subjectID)
	}
	if string(notice.event.Index) != account.index {
		t.Errorf("the notice carries index %q, want %q", notice.event.Index, account.index)
	}
	if want := "reservation_email-" + account.index; notice.stream != want {
		t.Errorf("the notice landed on %q, want %q — the ADDRESS's stream, not the "+
			"holder's account stream, which an unauthenticated prober must not be able "+
			"to move", notice.stream, want)
	}
	// The address itself is never in the log (ADR-002). Asserted against the raw
	// stored bytes rather than the decoded struct, because a field added to the
	// event later would be invisible to a struct-shaped assertion.
	for _, form := range []string{account.email, strings.ToLower(account.email)} {
		if strings.Contains(string(notice.raw), form) {
			t.Errorf("the stored notice contains the address: %s", notice.raw)
		}
	}
}

// The per-address ceiling, against the real KurrentDB.
//
// It is what stops this endpoint being a mail bomb: without it, anyone who knows
// a registered address can make it receive a message as often as they can send a
// request. It is enforced from the address's own reservation stream — state
// rebuilt from the log — so unlike the shared Valkey ceiling it holds while the
// cache is down, flushed, or (as today) not wired to this use case at all.
//
// Every attempt still answers identically. A ceiling that refused the fourth
// registration VISIBLY would be the account-existence oracle again: a prober
// would learn which addresses are taken by counting how many attempts it takes
// to be refused.
func TestTheDuplicateNoticeCeilingBoundsWhatOneAddressReceives(t *testing.T) {
	ctx := context.Background()
	account := h.verifiedAccountFor(t, "dup-ceiling")
	from := h.logTail(t)

	attempts := domain.MaxDuplicateNoticesPerHour + 2
	for i := 1; i <= attempts; i++ {
		if _, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
			Email: account.email,
		})); err != nil {
			t.Fatalf("registration attempt %d on a claimed address was refused with %v; "+
				"every attempt must answer identically, or the refusal count discloses "+
				"which addresses are registered", i, err)
		}
	}

	notices := h.duplicateNoticesFor(t, account.index, from)
	if len(notices) != domain.MaxDuplicateNoticesPerHour {
		t.Errorf("%d attempts produced %d notices, want %d. A ceiling that appends and then "+
			"apologises is not a ceiling: the message is already on its way",
			attempts, len(notices), domain.MaxDuplicateNoticesPerHour)
	}
	t.Logf("%d attempts within the hour produced %d notices", attempts, len(notices))
}

// A PENDING account's address gets no notice, however often it is registered.
//
// Nobody has proven they can read mail there. Sending would be unsolicited mail
// to a person who never asked for anything (NOTIFICATIONS §5), at an address a
// stranger typed — and the pending registrant is not stranded by the silence:
// they hold a verification link and ResendEmailVerification issues another.
func TestAnUnverifiedClaimProducesNoNotice(t *testing.T) {
	ctx := context.Background()
	email := h.freshEmail("dup-pending")

	if _, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: email,
	})); err != nil {
		t.Fatalf("first Register: %v\n%s", err, h.serverLogs())
	}
	index := h.emailIndex(t, email)
	h.awaitAccount(t, index)

	from := h.logTail(t)
	if _, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: email,
	})); err != nil {
		t.Fatalf("second Register: %v\n%s", err, h.serverLogs())
	}

	if notices := h.duplicateNoticesFor(t, index, from); len(notices) != 0 {
		t.Errorf("%d notices were appended for an UNVERIFIED claim; that is unsolicited "+
			"mail to an address nobody has proven they can read", len(notices))
	}
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// claimedAccount is a verified account and the address it holds — the state a
// returning user's registration attempt runs into.
type claimedAccount struct {
	email     string
	index     string
	subjectID string
}

// verifiedAccountFor builds an account that has PROVEN its address, through the
// real VerifyEmail handler.
//
// Verification is what makes the notice permissible at all, so a fixture that
// stopped at registration would exercise the branch that deliberately sends
// nothing and prove the opposite of what these tests claim.
func (hh *harness) verifiedAccountFor(t *testing.T, tag string) claimedAccount {
	t.Helper()
	email := hh.freshEmail(tag)
	row := hh.registerThroughTheKernel(t, email)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := hh.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
		Token:    hh.mintVerificationToken(t, row.subjectID),
		Password: "correct-horse-battery-staple-55",
		Username: hh.freshUsername("dup"),
	})); err != nil {
		t.Fatalf("VerifyEmail: %v\n%s", err, hh.serverLogs())
	}
	return claimedAccount{email: email, index: hh.emailIndex(t, email), subjectID: row.subjectID}
}

// storedNotice is one DuplicateRegistrationAttempted as the log holds it.
type storedNotice struct {
	event  *contract.DuplicateRegistrationAttempted
	stream string
	raw    []byte
}

// duplicateNoticesFor returns every notice the LOG carries for an address index,
// in commit order.
//
// Read from $all rather than from a projection, for the reason
// accountsRegisteredFor spells out: a projection is derived, behind, and able to
// filter, so an assertion against one measures the projection. $all is the log
// itself and is consistent the moment the append returns.
func (hh *harness) duplicateNoticesFor(
	t *testing.T, index string, from kurrentdb.AllPosition,
) []storedNotice {
	t.Helper()
	rs, err := hh.kurrent.ReadAll(context.Background(), kurrentdb.ReadAllOptions{
		Direction: kurrentdb.Forwards, From: from,
	}, ^uint64(0))
	if err != nil {
		t.Fatalf("reading $all: %v", err)
	}
	defer rs.Close()

	wanted := (&contract.DuplicateRegistrationAttempted{}).EventType()
	var out []storedNotice
	for {
		ev, err := rs.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reading $all: %v", err)
		}
		if ev.Event == nil || ev.Event.EventType != wanted {
			continue
		}
		decoded, err := hh.codec.Unmarshal(ev.Event.EventType, ev.Event.Data)
		if err != nil {
			t.Fatalf("decoding %s at %s: %v", ev.Event.EventType, ev.Event.StreamID, err)
		}
		notice, ok := decoded.(*contract.DuplicateRegistrationAttempted)
		if !ok {
			t.Fatalf("%s decoded as %T", ev.Event.EventType, decoded)
		}
		if string(notice.Index) != index {
			continue
		}
		out = append(out, storedNotice{
			event: notice, stream: ev.Event.StreamID, raw: ev.Event.Data,
		})
	}
	return out
}
