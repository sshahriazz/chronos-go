//go:build integration

package identityit_test

import (
	"context"
	"os"
	"testing"

	connectrpc "connectrpc.com/connect"
	"github.com/valkey-io/valkey-go"
	"google.golang.org/protobuf/proto"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// clearCallerCeiling deletes this suite's per-caller counter keys.
//
// It is NOT a convenience. The per-caller rule is 20/hour scoped to the peer
// address, the counter is a real Valkey key with a real one-hour window, and
// every test in this package calls from the same process — so the second run of
// the suite within an hour inherits the first run's spend and the ceiling tests
// fail on residue rather than on behaviour. Clearing the caller budget (and only
// the caller budget) makes each run measure the rule instead of the clock.
//
// The per-ADDRESS counter is deliberately left alone: every test mints a fresh
// address, so it starts empty on its own, and clearing it would hide a real
// regression in how it is keyed.
//
// A failure here fails the test. A helper that silently skipped its own cleanup
// would leave exactly the residue it exists to remove, and the ceiling tests
// would then fail for a reason that has nothing to do with the ceiling.
func clearCallerCeiling(t *testing.T) {
	t.Helper()
	addr := os.Getenv("VALKEY_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress:  []string{addr},
		Password:     os.Getenv("VALKEY_PASSWORD"),
		DisableCache: true,
	})
	if err != nil {
		t.Fatalf("dialling valkey at %s to clear the caller ceiling: %v", addr, err)
	}
	defer client.Close()

	ctx := context.Background()
	keys, err := client.Do(ctx, client.B().Keys().Pattern("*mail_caller*").Build()).AsStrSlice()
	if err != nil {
		t.Fatalf("listing the caller-ceiling keys: %v", err)
	}
	if len(keys) == 0 {
		return
	}
	if err := client.Do(ctx, client.B().Del().Key(keys...).Build()).Error(); err != nil {
		t.Fatalf("clearing the caller-ceiling keys: %v", err)
	}
	t.Logf("cleared %d caller-ceiling key(s) before measuring", len(keys))
}

// The resend path was built and unit-tested but had never been executed against
// anything live. These tests close that gap: they run over real HTTP against
// cmd/api, with the real Valkey counter behind the ceiling and the real
// KurrentDB stream as the record of what was actually issued.
//
// What they do NOT cover is delivery. The reactor that turns
// EmailVerificationRequested into mail lives in cmd/worker, and this harness
// runs cmd/api only, so the assertion here is that the EVENT was appended —
// the reactor's own Mailpit test covers the rest of the chain.

// countVerificationRequests reads the account's stream and counts the
// verification requests actually appended.
//
// The stream is the honest place to count. A resend that is refused returns the
// same empty response as one that succeeded — that indistinguishability is the
// point — so the response tells a test nothing at all, and only the write the
// ceiling was supposed to prevent can distinguish the two.
func countVerificationRequests(t *testing.T, userID string) int {
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
		if e.Type == (&contract.EmailVerificationRequested{}).EventType() {
			n++
		}
	}
	return n
}

// TestResendCeilingStopsTheFourthRequest proves the per-address ceiling against
// the REAL limiter and the REAL Valkey counter, over HTTP.
//
// The unit test for this uses an in-memory counter, which proves the app layer
// spends a budget but not that the budget survives the process boundary — a
// limiter wired to a counter that silently no-ops in the deployed binary passes
// every unit test in the repository.
func TestResendCeilingStopsTheFourthRequest(t *testing.T) {
	clearCallerCeiling(t)
	ctx := context.Background()
	email := h.freshEmail("resend-ceiling")
	const password = "correct-horse-battery-staple-48"

	if _, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: email,
	})); err != nil {
		t.Fatalf("Register: %v\n%s", err, h.serverLogs())
	}
	index := h.emailIndex(t, email)
	account := h.awaitAccount(t, index)

	// Registration itself issues the first link, so the stream starts at one and
	// the ceiling is spent by the resends that follow.
	atRegistration := countVerificationRequests(t, account.userID)
	t.Logf("after registration the stream carries %d verification request(s)", atRegistration)

	// The documented ceiling is 3 per address per hour.
	for i := 1; i <= 3; i++ {
		if _, err := h.client.ResendEmailVerification(ctx, write(
			&identityv1.ResendEmailVerificationRequest{Email: email},
		)); err != nil {
			t.Fatalf("ResendEmailVerification #%d, within the ceiling: %v\n%s",
				i, err, h.serverLogs())
		}
	}

	// The fourth is refused, and refused VISIBLY — resource_exhausted rather
	// than the silent empty response the outcome guards use. That asymmetry is
	// deliberate and it is safe only because the ceiling is spent before the
	// lookup, so it says "you have asked too often", never "this address
	// exists". TestTheCeilingRefusesAnUnknownAddressIdentically is what holds
	// that second half up; without it this visible refusal is an oracle.
	_, refused := h.client.ResendEmailVerification(ctx, write(
		&identityv1.ResendEmailVerificationRequest{Email: email},
	))
	if refused == nil {
		t.Fatal("a fourth resend within the hour was accepted; the per-address ceiling " +
			"is not enforced against the live counter")
	}
	if code := connectrpc.CodeOf(refused); code != connectrpc.CodeResourceExhausted {
		t.Errorf("the over-ceiling resend was refused with %v, want resource_exhausted", code)
	}
	t.Logf("the fourth resend was refused: code=%v", connectrpc.CodeOf(refused))

	// The refusal has to mean the mail did not happen. A limiter that appends
	// and then apologises passes an error-only assertion and still sends the
	// mail it was installed to prevent.
	got := countVerificationRequests(t, account.userID) - atRegistration
	if got != 3 {
		t.Errorf("four resends appended %d verification request(s), want exactly 3; "+
			"the refusal did not prevent the write", got)
	}
	t.Logf("four resends appended %d verification request(s)", got)
}

// TestTheCeilingRefusesAnUnknownAddressIdentically is the test that keeps the
// visible rate-limit refusal from becoming the enumeration oracle the silent
// outcome guards exist to prevent.
//
// If the ceiling were spent only once an account had been found, then a caller
// could tell a registered address from an unregistered one by how many requests
// it takes to get refused: three for a real account, unlimited for a stranger.
// The budget therefore has to be spent BEFORE the lookup, and the observable
// consequence — an address nothing claims is refused on exactly the same
// request number — is what this asserts.
func TestTheCeilingRefusesAnUnknownAddressIdentically(t *testing.T) {
	clearCallerCeiling(t)
	ctx := context.Background()
	unknown := h.freshEmail("resend-ceiling-nobody")

	for i := 1; i <= 3; i++ {
		if _, err := h.client.ResendEmailVerification(ctx, write(
			&identityv1.ResendEmailVerificationRequest{Email: unknown},
		)); err != nil {
			t.Fatalf("resend #%d for an address nothing claims was refused with %v; a "+
				"stranger's address must consume the ceiling exactly as a real one does, "+
				"or the refusal count discloses which addresses are registered",
				i, connectrpc.CodeOf(err))
		}
	}

	_, refused := h.client.ResendEmailVerification(ctx, write(
		&identityv1.ResendEmailVerificationRequest{Email: unknown},
	))
	if refused == nil {
		t.Fatal("a fourth resend for an unregistered address was accepted while the same " +
			"request for a registered one is refused; the ceiling is an enumeration oracle")
	}
	if code := connectrpc.CodeOf(refused); code != connectrpc.CodeResourceExhausted {
		t.Errorf("the over-ceiling resend for an unknown address was refused with %v, "+
			"want resource_exhausted — the same code a registered address gets", code)
	}
	t.Logf("an unknown address is refused on the same request: code=%v",
		connectrpc.CodeOf(refused))
}

// TestResendIsIndistinguishableForAnUnknownAddress asserts the property that
// makes an unauthenticated resend safe to expose at all.
//
// Compared as MARSHALLED BYTES rather than field by field: a field added to the
// response later — an "email sent" flag, a retry hint, a next-allowed timestamp
// — would pass a field-by-field comparison written today while turning the RPC
// into the enumeration oracle this test exists to prevent.
func TestResendIsIndistinguishableForAnUnknownAddress(t *testing.T) {
	clearCallerCeiling(t)
	ctx := context.Background()
	known := h.freshEmail("resend-known")
	unknown := h.freshEmail("resend-nobody")
	const password = "correct-horse-battery-staple-48"

	if _, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: known,
	})); err != nil {
		t.Fatalf("Register: %v\n%s", err, h.serverLogs())
	}
	h.awaitAccount(t, h.emailIndex(t, known))

	forKnown, errKnown := h.client.ResendEmailVerification(ctx, write(
		&identityv1.ResendEmailVerificationRequest{Email: known},
	))
	forUnknown, errUnknown := h.client.ResendEmailVerification(ctx, write(
		&identityv1.ResendEmailVerificationRequest{Email: unknown},
	))

	switch {
	case errKnown != nil:
		t.Fatalf("resend for a registered address: %v\n%s", errKnown, h.serverLogs())
	case errUnknown != nil:
		t.Fatalf("resend for an address nothing claims returned %v (code=%v); an unknown "+
			"address must answer exactly as a known one does",
			errUnknown, connectrpc.CodeOf(errUnknown))
	}

	a, err := proto.Marshal(forKnown.Msg)
	if err != nil {
		t.Fatalf("marshalling the known-address response: %v", err)
	}
	b, err := proto.Marshal(forUnknown.Msg)
	if err != nil {
		t.Fatalf("marshalling the unknown-address response: %v", err)
	}
	if string(a) != string(b) {
		t.Errorf("the responses differ on the wire: known=%x unknown=%x; the resend RPC "+
			"discloses whether an address is registered", a, b)
	}
	t.Logf("both responses marshal to %d identical byte(s)", len(a))

	// Nothing was appended for an address no account claims. The response being
	// identical is necessary but not sufficient — a resend that answers silently
	// and then mails a stranger is the mail-bomb primitive.
	if n := countVerificationRequests(t, h.awaitAccount(t, h.emailIndex(t, known)).userID); n < 1 {
		t.Errorf("the known account carries %d verification request(s), want at least 1", n)
	}
}
