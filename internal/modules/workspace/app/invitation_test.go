package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	identitycontract "github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/secret"
)

const (
	inviteWS     = "ws_01ARZ3NDEKTSV4RRFFQ69G5FAW"
	inviteeEmail = "colleague@example.com"
	knownSubject = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAK"
	mintedSubjct = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAM"
)

// ---------------------------------------------------------------------------
// fakes
// ---------------------------------------------------------------------------

type fakeIndexer struct{ err error }

func (f fakeIndexer) Of(email string) (identitycontract.EmailIndex, error) {
	if f.err != nil {
		return "", f.err
	}
	// Deterministic and obviously not the address: an index that contained the
	// address would defeat the point of having one.
	return identitycontract.EmailIndex("idx_" + strings.ToLower(strings.TrimSpace(email))[:3]), nil
}

type fakeDirectory struct {
	subject string
	known   bool
	err     error
}

func (f fakeDirectory) SubjectFor(context.Context, identitycontract.EmailIndex) (string, bool, error) {
	return f.subject, f.known, f.err
}

// IsAccount answers for the pseudonym the fake directory knows about, and false
// for anything else — which is exactly the shape of a minted invitation
// pseudonym, the case acceptance must NOT compare against.
func (f fakeDirectory) IsAccount(_ context.Context, subjectID string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.known && subjectID == f.subject, nil
}

type fakeVault struct {
	stored map[string]string
	err    error
}

func (f *fakeVault) PutEmail(_ context.Context, subjectID, email string) error {
	if f.err != nil {
		return f.err
	}
	if f.stored == nil {
		f.stored = map[string]string{}
	}
	f.stored[subjectID] = email
	return nil
}

// fakeSubs stands in for gate 3, asked about an organization the caller did not
// name.
type fakeSubs struct{ err error }

func (f fakeSubs) PermitJoin(context.Context, string) error { return f.err }

type fakeSubjects struct{ minted int }

func (f *fakeSubjects) NewSubject() string { f.minted++; return mintedSubjct }

type storedToken struct {
	digest       []byte
	invitationID string
	orgID        string
	expiresAt    time.Time
}

type fakeTokens struct {
	issued  []storedToken
	spent   []string
	revoked []string
	err     error
}

func (f *fakeTokens) Issue(
	_ context.Context, digest []byte, invitationID, orgID string, expiresAt time.Time,
) error {
	if f.err != nil {
		return f.err
	}
	f.issued = append(f.issued, storedToken{digest, invitationID, orgID, expiresAt})
	return nil
}

// Lookup and Consume both resolve a presented digest against what was issued.
// Consume additionally SPENDS it, so a second call finds nothing — which is the
// single-use property the real store gets from DELETE ... RETURNING.
func (f *fakeTokens) Lookup(_ context.Context, digest []byte, now time.Time) (string, string, error) {
	for _, t := range f.issued {
		if secret.Equal(t.digest, digest) && now.Before(t.expiresAt) {
			return t.invitationID, t.orgID, nil
		}
	}
	return "", "", app.ErrInvitationTokenNotFound
}

func (f *fakeTokens) Consume(ctx context.Context, digest []byte, now time.Time) (string, string, error) {
	invitationID, orgID, err := f.Lookup(ctx, digest, now)
	if err != nil {
		return "", "", err
	}
	kept := f.issued[:0]
	for _, t := range f.issued {
		if !secret.Equal(t.digest, digest) {
			kept = append(kept, t)
		}
	}
	f.issued = kept
	f.spent = append(f.spent, invitationID)
	return invitationID, orgID, nil
}

// RevokeAll actually DELETES, which the first version of this fake did not — it
// recorded the call and left the digests in place, so every resend appeared to
// leave one live link while leaving two. A fake that records intent instead of
// performing it turns the assertion into a check that the code called something.
func (f *fakeTokens) RevokeAll(_ context.Context, invitationID string) (int64, error) {
	f.revoked = append(f.revoked, invitationID)
	kept := f.issued[:0]
	var removed int64
	for _, t := range f.issued {
		if t.invitationID == invitationID {
			removed++
			continue
		}
		kept = append(kept, t)
	}
	f.issued = kept
	return removed, nil
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

type inviteHarness struct {
	invitations *app.Invitations
	store       *memStore
	tokens      *fakeTokens
	vault       *fakeVault
	subjects    *fakeSubjects
	reserver    *fakeReserver
	counter     *countingMembers
	memberships *eventsourcing.Repository[*domain.Membership]
	workspaceID string
	clock       *testClock
}

// testClock is a clock a test can move.
type testClock struct{ at time.Time }

func (c *testClock) Now() time.Time { return c.at }

func (c *testClock) advance(d time.Duration) { c.at = c.at.Add(d) }

type inviteOpts struct {
	knownAccount bool
	existingWS   int
	indexErr     error
	dirErr       error
	vaultErr     error
	tokenErr     error
	poolFull     string
	suspended    error
	archived     bool
}

func newInviteHarness(t *testing.T, o inviteOpts) *inviteHarness {
	t.Helper()
	store := newMemStore()

	// MOVABLE, because a frozen clock cannot express a resend: the new window is
	// measured from now, so with time standing still it lands exactly where the
	// old one did — and "the resend extended the window" is unfalsifiable.
	clock := &testClock{at: time.Unix(1_700_000_000, 0).UTC()}
	now := clock.Now

	repo := eventsourcing.NewRepository[*domain.Invitation](
		store, jsonCodec{}, nil, domain.InvitationCategory, domain.NewInvitation)
	workspaces := eventsourcing.NewRepository[*domain.Workspace](
		store, jsonCodec{}, nil, domain.Category, domain.NewWorkspace)
	memberships := eventsourcing.NewRepository[*domain.Membership](
		store, jsonCodec{}, nil, domain.MembershipCategory, domain.NewMembership)

	reserver := newFakeReserver()
	if o.poolFull != "" {
		reserver.full[o.poolFull] = true
	}
	seats, err := app.NewSeats(app.SeatsDeps{
		Reserver: reserver, Members: &countingMembers{n: o.existingWS},
	})
	if err != nil {
		t.Fatal(err)
	}

	minter, err := secret.New(map[secret.Purpose]time.Duration{
		app.PurposeInvitation: app.InvitationTTL,
	})
	if err != nil {
		t.Fatal(err)
	}

	dir := fakeDirectory{err: o.dirErr}
	if o.knownAccount {
		dir.subject, dir.known = knownSubject, true
	}

	tokens := &fakeTokens{err: o.tokenErr}
	vault := &fakeVault{err: o.vaultErr}
	subjects := &fakeSubjects{}
	counter := &countingMembers{n: o.existingWS}

	invitations, err := app.NewInvitations(app.InvitationsDeps{
		Repo: repo, Workspaces: workspaces, Memberships: memberships,
		Appender: store, Schemas: noSchemas{},
		Tokens: tokens, Minter: minter,
		Indexer: fakeIndexer{err: o.indexErr}, Dir: dir, Subs: fakeSubs{err: o.suspended},
		Vault: vault, Subjects: subjects, Seats: seats, Now: now,
	})
	if err != nil {
		t.Fatalf("NewInvitations: %v", err)
	}

	_ = clock

	// A REAL workspace, opened through its own aggregate. Acceptance revalidates
	// that it is still active, and a fabricated one would skip the check this
	// harness exists to exercise.
	ws, err := workspaces.Load(context.Background(), domain.StreamKey(inviteWS))
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.Create(inviteWS, testOrg, "Invites", founder, now()); err != nil {
		t.Fatal(err)
	}
	if o.archived {
		if err := ws.Archive(now()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := workspaces.Save(context.Background(), domain.StreamKey(inviteWS), ws,
		"seed-ws", eventsourcing.Metadata{}); err != nil {
		t.Fatal(err)
	}

	return &inviteHarness{
		invitations: invitations, store: store, tokens: tokens,
		vault: vault, subjects: subjects, reserver: reserver, counter: counter,
		memberships: memberships, workspaceID: inviteWS, clock: clock,
	}
}

func (h *inviteHarness) issue(role contract.MemberRole) (app.IssueInvitationResult, error) {
	return h.invitations.Issue(context.Background(), app.IssueInvitationCommand{
		OrgID: testOrg, WorkspaceID: inviteWS, Email: inviteeEmail,
		Role: role, InvitedBy: founder, IdempotencyKey: "key-invite",
	})
}

// invitationStreams counts how many invitations were appended.
//
// Counting the INVITATION streams rather than every stream, because the harness
// seeds a real workspace: `len(store.streams) == 0` would have been an assertion
// about the fixture rather than about the command.
func (h *inviteHarness) invitationStreams() int {
	var n int
	for stream := range h.store.streams {
		if strings.HasPrefix(string(stream), string(domain.InvitationCategory)+"-") {
			n++
		}
	}
	return n
}

// issuedEvent digs the one event out of the store.
func (h *inviteHarness) issuedEvent(t *testing.T) *contract.InvitationIssued {
	t.Helper()
	for stream, events := range h.store.streams {
		if !strings.HasPrefix(string(stream), string(domain.InvitationCategory)+"-") {
			continue
		}
		if len(events) != 1 {
			t.Fatalf("%s holds %d events, want 1", stream, len(events))
		}
		decoded, err := jsonCodec{}.Unmarshal(events[0].Type, events[0].Payload)
		if err != nil {
			t.Fatal(err)
		}
		issued, ok := decoded.(*contract.InvitationIssued)
		if !ok {
			t.Fatalf("decoded %T", decoded)
		}
		return issued
	}
	t.Fatal("no invitation stream was written")
	return nil
}

// ---------------------------------------------------------------------------
// the address never leaves the vault
// ---------------------------------------------------------------------------

// NO ADDRESS REACHES THE EVENT LOG.
//
// ADR-002, and it is the one property here that cannot be fixed after the fact:
// an event log is append-only, so an address written into one is there for as
// long as the log exists, and erasure-by-key-destruction cannot touch it.
//
// The event carries the blind INDEX and a pseudonym. The index answers "is this
// the same address?" and nothing else — it cannot be rendered to a human, and no
// mail may be addressed from it.
func TestAnInvitationPutsNoAddressInTheLog(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	if _, err := h.issue(contract.RoleMember); err != nil {
		t.Fatalf("issuing: %v", err)
	}

	for stream, events := range h.store.streams {
		for _, e := range events {
			if strings.Contains(string(e.Payload), inviteeEmail) {
				t.Fatalf("the address appears in %s: %s\nAn event log is append-only, so "+
					"this cannot be undone and erasure by key destruction cannot reach it",
					stream, e.Payload)
			}
			// The local part alone is enough to identify somebody.
			if strings.Contains(string(e.Payload), "colleague") {
				t.Fatalf("part of the address appears in %s: %s", stream, e.Payload)
			}
		}
	}

	issued := h.issuedEvent(t)
	if issued.EmailIndex == "" {
		t.Error("the event carries no blind index, so a second invitation to the same " +
			"address cannot be recognised and would take a second seat")
	}
	if strings.Contains(issued.EmailIndex, "@") {
		t.Errorf("the blind index %q contains an address", issued.EmailIndex)
	}
}

// THE ADDRESS REACHES THE VAULT, under the pseudonym the event names.
//
// Without this the invitation names a subject that means nothing: the mail
// activity resolves the address from the vault at send time, and an entry that
// was never written is an invitation nobody can send — which nothing in the log
// can repair.
func TestAnInvitationRecordsTheAddressInTheVault(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	if _, err := h.issue(contract.RoleMember); err != nil {
		t.Fatalf("issuing: %v", err)
	}

	issued := h.issuedEvent(t)
	got, ok := h.vault.stored[issued.SubjectID]
	if !ok {
		t.Fatalf("nothing was recorded for %s; the mail has no address to resolve at send "+
			"time, and no event carries one", issued.SubjectID)
	}
	if got != inviteeEmail {
		t.Errorf("recorded %q, want %q", got, inviteeEmail)
	}
}

// A VAULT FAILURE STOPS THE INVITATION, before the seat and before the append.
//
// The order is the point. An invitation appended with no vault entry behind it
// holds a seat for somebody nobody can contact, and there is no event that
// repairs it.
func TestAVaultFailureIssuesNothing(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{vaultErr: errors.New("openbao: unreachable")})

	if _, err := h.issue(contract.RoleMember); err == nil {
		t.Fatal("an invitation was issued with no address recorded; it holds a seat for " +
			"somebody nobody can contact")
	}
	if h.invitationStreams() != 0 {
		t.Error("an event was appended for an invitation that could not record its address")
	}
	if len(h.reserver.reserved) != 0 {
		t.Errorf("a seat was reserved: %v", h.reserver.reserved)
	}
}

// ---------------------------------------------------------------------------
// the subject
// ---------------------------------------------------------------------------

// AN INVITATION TO A KNOWN ADDRESS NAMES THAT ACCOUNT'S PSEUDONYM.
//
// Minting a fresh one would create a second identity for one person: accepting
// would make the new pseudonym a member while the account they actually log in
// with is not, and the seat would be counted against somebody who does not exist.
func TestInvitingAnExistingAccountUsesItsPseudonym(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{knownAccount: true})
	if _, err := h.issue(contract.RoleMember); err != nil {
		t.Fatalf("issuing: %v", err)
	}

	if issued := h.issuedEvent(t); issued.SubjectID != knownSubject {
		t.Fatalf("the invitation names %s, want the existing account's %s; a fresh "+
			"pseudonym would make accepting create a second identity for one person",
			issued.SubjectID, knownSubject)
	}
	if h.subjects.minted != 0 {
		t.Error("a pseudonym was minted for somebody who already has one")
	}
}

// AN INVITATION TO A STRANGER GETS A FRESH PSEUDONYM.
//
// Most invitations go to people who have never used this system, and treating
// that as a failure would make inviting a new colleague impossible.
func TestInvitingAStrangerMintsAPseudonym(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{knownAccount: false})
	if _, err := h.issue(contract.RoleMember); err != nil {
		t.Fatalf("issuing: %v", err)
	}

	if issued := h.issuedEvent(t); issued.SubjectID != mintedSubjct {
		t.Errorf("the invitation names %s, want the freshly minted %s",
			issued.SubjectID, mintedSubjct)
	}
	if h.subjects.minted != 1 {
		t.Errorf("minted %d pseudonyms, want 1", h.subjects.minted)
	}
}

// ---------------------------------------------------------------------------
// the seat
// ---------------------------------------------------------------------------

// THE SEAT IS TAKEN AT ISSUE, not at acceptance.
//
// workspace.md §5. Reserving at acceptance means 60 pending invitations against
// 50 seats all look valid, and the 51st person to click their link is refused
// for something somebody else did — with no way for them or the inviter to tell
// what went wrong.
func TestASeatIsTakenAtIssue(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})

	result, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	if !result.SeatConsumed {
		t.Fatal("issuing took no seat, so pending invitations do not count against the " +
			"limit and it binds only when people accept")
	}
	if len(h.reserver.reserved) != 1 || h.reserver.reserved[0] != "seats.member" {
		t.Fatalf("reserved %v, want one member seat", h.reserver.reserved)
	}
	if issued := h.issuedEvent(t); !issued.SeatConsumed {
		t.Error("the event does not record that a seat was taken, so settling the " +
			"invitation would return nothing and the seat leaks")
	}
}

// THE RESERVATION IS STILL CONDITIONAL.
//
// Somebody already in the organization holds a seat, and inviting them into
// another workspace costs nothing — the same rule a join follows. Reserving
// unconditionally here would charge a second seat, which is why this RPC
// declares no entitlement for gate 4 to act on.
func TestInvitingAnExistingOrgMemberTakesNoSeat(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{knownAccount: true, existingWS: 2})

	result, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	if result.SeatConsumed {
		t.Fatal("a second seat was taken for somebody already in the organization; five " +
			"workspaces would cost five seats (workspace.md §2)")
	}
	if len(h.reserver.reserved) != 0 {
		t.Errorf("reserved %v for a person who already holds a seat", h.reserver.reserved)
	}
}

// GUESTS DRAW ON THE GUEST POOL.
func TestInvitingAGuestDrawsOnTheGuestPool(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	if _, err := h.issue(contract.RoleGuest); err != nil {
		t.Fatalf("issuing: %v", err)
	}
	if len(h.reserver.reserved) != 1 || h.reserver.reserved[0] != "seats.guest" {
		t.Fatalf("reserved %v, want one guest seat; the pools are independent limits so "+
			"exhausting one must not block the other (ADR-027)", h.reserver.reserved)
	}
}

// AN EXHAUSTED POOL REFUSES THE INVITATION, and appends nothing.
func TestAFullPoolIssuesNothing(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{poolFull: "seats.member"})

	_, err := h.issue(contract.RoleMember)
	if err == nil {
		t.Fatal("an invitation was issued against a full seat pool")
	}
	if got := errs.ReasonOf(err); got != errs.QuotaExceeded {
		t.Errorf("refused with %s, want QUOTA_EXCEEDED: the customer needs to be told to "+
			"upgrade, not that they lack permission", got)
	}
	if h.invitationStreams() != 0 {
		t.Error("an invitation was appended for a seat that was never granted")
	}
}

// ---------------------------------------------------------------------------
// the token
// ---------------------------------------------------------------------------

// THE TOKEN NEVER ENTERS THE LOG, in any form.
//
// Not the plaintext, and not the digest. An event log is replicated, retained
// far longer than any token's lifetime, and readable by every projector — a
// digest there would let a token be recovered from a backup long after it was
// spent. It goes in its own store, which is exactly what identity_token does.
func TestTheTokenNeverEntersTheLog(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	result, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	if result.Token == "" {
		t.Fatal("no token was returned, so the mail has no link to carry")
	}

	for stream, events := range h.store.streams {
		for _, e := range events {
			if strings.Contains(string(e.Payload), result.Token) {
				t.Fatalf("the token plaintext is in %s: a live credential in a log that "+
					"outlives it by years", stream)
			}
		}
	}

	if len(h.tokens.issued) != 1 {
		t.Fatalf("stored %d digests, want 1", len(h.tokens.issued))
	}
	stored := h.tokens.issued[0]
	if !secret.Equal(stored.digest, secret.Digest(app.PurposeInvitation, result.Token)) {
		t.Error("the stored digest is not the digest of the returned token, so the link " +
			"in the mail can never be redeemed")
	}
	if secret.Equal(stored.digest, secret.Digest("email_verification", result.Token)) {
		t.Error("the digest is not scoped to the invitation purpose, so a verification " +
			"link could be presented to join a workspace")
	}
	if stored.invitationID != result.InvitationID {
		t.Errorf("the digest names invitation %s, want %s",
			stored.invitationID, result.InvitationID)
	}
}

// THE TOKEN AND THE INVITATION EXPIRE TOGETHER.
//
// A digest that outlives its invitation is a link that redeems an expired
// invitation; one that dies first is a link that stops working while the seat is
// still held.
func TestTheTokenAndTheInvitationShareAWindow(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	result, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}

	issued := h.issuedEvent(t)
	if !issued.ExpiresAt.Equal(result.ExpiresAt) {
		t.Errorf("the event expires at %s and the result says %s",
			issued.ExpiresAt, result.ExpiresAt)
	}
	if !h.tokens.issued[0].expiresAt.Equal(result.ExpiresAt) {
		t.Errorf("the token expires at %s and the invitation at %s; whichever is shorter "+
			"is the one that actually applies, and neither is what was published",
			h.tokens.issued[0].expiresAt, result.ExpiresAt)
	}
	if got := result.ExpiresAt.Sub(time.Unix(1_700_000_000, 0).UTC()); got != app.InvitationTTL {
		t.Errorf("the window is %s, want %s", got, app.InvitationTTL)
	}
}

// A TOKEN THAT CANNOT BE STORED IS A PARTIAL SUCCESS, not a rollback.
//
// The invitation exists and holds its seat by then. Reporting a plain failure
// would have the caller issue a second one — a second seat and a second pending
// invitation for one person — so the error says to RESEND.
func TestAFailedTokenLeavesTheInvitationAndSaysToResend(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{tokenErr: errors.New("postgres: down")})

	result, err := h.issue(contract.RoleMember)
	if err == nil {
		t.Fatal("an invitation with no live link was reported as a success")
	}
	if !strings.Contains(err.Error(), "resend") {
		t.Errorf("the error does not say to resend: %v\nA caller who re-invites instead "+
			"takes a second seat for one person", err)
	}
	if result.InvitationID == "" {
		t.Error("the invitation id was not returned, so the caller cannot resend the " +
			"invitation that exists")
	}
	if h.invitationStreams() == 0 {
		t.Error("nothing was appended, so this is a rollback rather than a partial success")
	}
}

// ---------------------------------------------------------------------------
// wiring
// ---------------------------------------------------------------------------

// EVERY DEPENDENCY IS REQUIRED.
//
// Each absence has a distinct silent failure: no indexer means the address would
// have to go in the event, no directory means every invitation creates a second
// identity, no vault means the mail cannot be addressed, no token store means
// nothing can be redeemed, and no seats means the limit never binds.
func TestInvitationsRefusesAnIncompleteWiring(t *testing.T) {
	store := newMemStore()
	repo := eventsourcing.NewRepository[*domain.Invitation](
		store, jsonCodec{}, nil, domain.InvitationCategory, domain.NewInvitation)
	seats, err := app.NewSeats(app.SeatsDeps{
		Reserver: newFakeReserver(), Members: &countingMembers{},
	})
	if err != nil {
		t.Fatal(err)
	}
	minter, err := secret.New(map[secret.Purpose]time.Duration{
		app.PurposeInvitation: app.InvitationTTL,
	})
	if err != nil {
		t.Fatal(err)
	}
	full := app.InvitationsDeps{
		Repo: repo,
		Workspaces: eventsourcing.NewRepository[*domain.Workspace](
			store, jsonCodec{}, nil, domain.Category, domain.NewWorkspace),
		Memberships: eventsourcing.NewRepository[*domain.Membership](
			store, jsonCodec{}, nil, domain.MembershipCategory, domain.NewMembership),
		Appender: store, Schemas: noSchemas{},
		Tokens: &fakeTokens{}, Minter: minter,
		Indexer: fakeIndexer{}, Dir: fakeDirectory{}, Subs: fakeSubs{},
		Vault: &fakeVault{}, Subjects: &fakeSubjects{}, Seats: seats, Now: time.Now,
	}
	if _, err := app.NewInvitations(full); err != nil {
		t.Fatalf("precondition: a complete wiring was refused, so every case below would "+
			"pass for the wrong reason: %v", err)
	}

	tests := []struct {
		name string
		mut  func(*app.InvitationsDeps)
		want string
	}{
		{"no repository", func(d *app.InvitationsDeps) { d.Repo = nil }, "invitation repository"},
		{"no workspaces", func(d *app.InvitationsDeps) { d.Workspaces = nil }, "workspace repository"},
		{"no memberships", func(d *app.InvitationsDeps) { d.Memberships = nil }, "membership repository"},
		{"no appender", func(d *app.InvitationsDeps) { d.Appender = nil }, "appender"},
		{"no schemas", func(d *app.InvitationsDeps) { d.Schemas = nil }, "schema registry"},
		{"no subscriptions", func(d *app.InvitationsDeps) { d.Subs = nil }, "subscription check"},
		{"no token store", func(d *app.InvitationsDeps) { d.Tokens = nil }, "token store"},
		{"no minter", func(d *app.InvitationsDeps) { d.Minter = nil }, "minter"},
		{"no indexer", func(d *app.InvitationsDeps) { d.Indexer = nil }, "blind indexer"},
		{"no directory", func(d *app.InvitationsDeps) { d.Dir = nil }, "directory"},
		{"no vault", func(d *app.InvitationsDeps) { d.Vault = nil }, "vault"},
		{"no subject minter", func(d *app.InvitationsDeps) { d.Subjects = nil }, "subject minter"},
		{"no seats", func(d *app.InvitationsDeps) { d.Seats = nil }, "seat accounting"},
		{"no clock", func(d *app.InvitationsDeps) { d.Now = nil }, "clock"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := full
			tt.mut(&d)
			_, err := app.NewInvitations(d)
			if err == nil {
				t.Fatalf("constructed with %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("refused for the wrong reason: %v", err)
			}
		})
	}
}

// AN ADDRESS THIS SYSTEM WILL NOT ACCEPT IS REFUSED WITHOUT QUOTING IT.
//
// A message containing the address would be logged, and a log line is exactly
// where an address must not be (ADR-002).
func TestARejectedAddressIsNotQuotedBack(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{indexErr: errors.New("not an address")})

	_, err := h.issue(contract.RoleMember)
	if err == nil {
		t.Fatal("an address the indexer rejected was accepted")
	}
	if strings.Contains(err.Error(), inviteeEmail) || strings.Contains(err.Error(), "colleague") {
		t.Errorf("the error quotes the address: %v", err)
	}
	if got := errs.ReasonOf(err); got != errs.ValidationFailed {
		t.Errorf("refused with %s, want VALIDATION_FAILED", got)
	}
}

// ---------------------------------------------------------------------------
// acceptance
// ---------------------------------------------------------------------------

const acceptor = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAP"

// issueThenAccept issues an invitation and redeems it as `by`.
func (h *inviteHarness) accept(token, by string) (app.AcceptInvitationResult, error) {
	return h.invitations.Accept(context.Background(), app.AcceptInvitationCommand{
		Token: token, AcceptedBy: by, IdempotencyKey: "key-accept-" + by,
	})
}

// ACCEPTING CREATES THE MEMBERSHIP AND SETTLES THE INVITATION, atomically.
//
// Two streams, one append. Two appends would leave either an invitation spent
// with nobody admitted, or a membership beside a still-pending invitation — and
// the second is the expensive one: the expiry workflow would later "release the
// seat" for that invitation, taking back the seat the new member is sitting in.
func TestAcceptingCreatesTheMembership(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}

	result, err := h.accept(issued.Token, acceptor)
	if err != nil {
		t.Fatalf("accepting: %v", err)
	}
	if result.WorkspaceID != h.workspaceID || result.Role != contract.RoleMember {
		t.Errorf("joined %s as %q", result.WorkspaceID, result.Role)
	}

	membership, err := h.memberships.Load(context.Background(),
		domain.MembershipStreamKey(h.workspaceID, acceptor))
	if err != nil {
		t.Fatal(err)
	}
	if !membership.Exists() || !membership.Active() {
		t.Fatal("no membership was created, so a spent invitation admitted nobody")
	}
	if !membership.SeatConsumed() {
		t.Error("the membership records no seat, so removing this person would return " +
			"nothing and the seat the invitation took leaks")
	}

	// The LINK is spent, asserted separately from the invitation's state.
	//
	// Both would refuse a second click, and that redundancy is deliberate — but
	// asserting only the aggregate lets the token quietly stop being consumed:
	// the invitation is Accepted either way, so the second click is refused for
	// the wrong reason and nothing says so. A live digest for a settled
	// invitation is a credential outliving what it authorised.
	if len(h.tokens.spent) != 1 {
		t.Errorf("the link was spent %d times, want once; a digest that survives its own "+
			"redemption is a live credential for an invitation that is already closed",
			len(h.tokens.spent))
	}
	if _, _, err := h.tokens.Lookup(context.Background(), secret.Digest(
		app.PurposeInvitation, issued.Token), time.Unix(1_700_000_000, 0).UTC()); err == nil {
		t.Error("the digest is still redeemable after the invitation was accepted")
	}

	inv := h.loadInvitation(t, issued.InvitationID)
	if inv.Status() != domain.InvitationAccepted {
		t.Errorf("the invitation is %s, want accepted; a still-pending one would be "+
			"expired later and its seat returned out from under the new member",
			inv.Status())
	}
}

// loadInvitation rebuilds one invitation from the store.
func (h *inviteHarness) loadInvitation(t *testing.T, invitationID string) *domain.Invitation {
	t.Helper()
	repo := eventsourcing.NewRepository[*domain.Invitation](
		h.store, jsonCodec{}, nil, domain.InvitationCategory, domain.NewInvitation)
	inv, err := repo.Load(context.Background(), domain.InvitationStreamKey(invitationID))
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

// A LINK IS SINGLE USE.
//
// Two people cannot join on one invitation. The second attempt is NOT_FOUND,
// which is also what a wrong token gets: nothing distinguishes "already used"
// from "never existed".
func TestALinkCannotBeRedeemedTwice(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.accept(issued.Token, acceptor); err != nil {
		t.Fatalf("the first acceptance failed, so this proves nothing: %v", err)
	}

	const second = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAQ"
	_, err = h.accept(issued.Token, second)
	if err == nil {
		t.Fatal("a second person joined on one invitation, which is one seat admitting two")
	}
	if got := errs.ReasonOf(err); got != errs.NotFound {
		t.Errorf("refused with %s, want NOT_FOUND: a spent link must be indistinguishable "+
			"from one that never existed", got)
	}
}

// A WRONG OR ABSENT TOKEN IS NOT_FOUND, and reveals nothing.
func TestAWrongTokenIsNotFound(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	if _, err := h.issue(contract.RoleMember); err != nil {
		t.Fatal(err)
	}

	for _, token := range []string{"", "not-a-token", strings.Repeat("A", 43)} {
		_, err := h.accept(token, acceptor)
		if err == nil {
			t.Fatalf("token %q was accepted", token)
		}
		if got := errs.ReasonOf(err); got != errs.NotFound {
			t.Errorf("token %q refused with %s, want NOT_FOUND", token, got)
		}
	}
}

// A SUSPENDED ORGANIZATION REFUSES THE JOIN, and leaves the link alive.
//
// ORG_SUSPENDED rather than NOT_FOUND, because the caller has presented a valid
// credential for this organization and is entitled to know why they cannot join
// — "not found" would send them back to an inviter who can see the invitation is
// perfectly fine.
//
// The link SURVIVES, which is why the token is looked up before it is spent: the
// organization's payment is not the recipient's doing, and burning their link
// for it would need a resend to repair.
func TestASuspendedOrganizationRefusesAcceptance(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{suspended: errs.OrgSuspendedf("this organization is suspended")})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}

	_, err = h.accept(issued.Token, acceptor)
	if err == nil {
		t.Fatal("somebody joined a suspended organization")
	}
	if got := errs.ReasonOf(err); got != errs.OrgSuspended {
		t.Errorf("refused with %s, want ORG_SUSPENDED", got)
	}
	if len(h.tokens.spent) != 0 {
		t.Fatal("the link was spent for a refusal the recipient did not cause; only a " +
			"resend could repair it, and nobody knows to send one")
	}
}

// AN ARCHIVED WORKSPACE REFUSES THE JOIN.
//
// Checked against the AGGREGATE and not a projection: a projection lags, and
// this decision admits somebody to a tenant.
func TestAnArchivedWorkspaceRefusesAcceptance(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{archived: true})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}

	_, err = h.accept(issued.Token, acceptor)
	if err == nil {
		t.Fatal("somebody joined an archived workspace")
	}
	if got := errs.ReasonOf(err); got != errs.NotFound {
		t.Errorf("refused with %s, want NOT_FOUND: a non-member has no standing to learn "+
			"that the workspace exists but is archived (ADR-036)", got)
	}
	if len(h.tokens.spent) != 0 {
		t.Error("the link was spent for a workspace that may be restored")
	}
}

// A DIFFERENT SIGNED-IN ACCOUNT IS TOLD SO, explicitly.
//
// The footgun workspace.md §5 names: a forwarded link, or a shared machine,
// silently binding the invitation to whoever happened to be signed in. It only
// applies when the invitation names a REAL account — an invitation to somebody
// with no account names a minted pseudonym, which cannot match anybody and needs
// no comparison, because holding the link is proof of control over the mailbox.
func TestAcceptingAsSomebodyElseIsRefusedExplicitly(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{knownAccount: true})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}

	_, err = h.accept(issued.Token, acceptor) // not knownSubject
	if err == nil {
		t.Fatal("an invitation addressed to one account was bound to another; the wrong " +
			"person is now in the workspace and the right one still cannot get in")
	}
	if got := errs.ReasonOf(err); got != errs.AccessDenied {
		t.Errorf("refused with %s, want ACCESS_DENIED: the fix is to sign in as the right "+
			"account, which the caller can act on and cannot guess", got)
	}
	if !strings.Contains(err.Error(), "sign in") {
		t.Errorf("the message does not say what to do: %v", err)
	}

	// And the invited account CAN accept, which is what proves the refusal above
	// is about identity rather than about everything failing.
	if _, err := h.accept(issued.Token, knownSubject); err != nil {
		t.Fatalf("the invited account could not accept its own invitation: %v", err)
	}
}

// A STRANGER'S INVITATION IS ACCEPTED BY WHOEVER HOLDS THE LINK.
//
// The new-user path. The invitation names a minted pseudonym; by the time the
// person registers, identity has minted them a different one — so a pseudonym
// comparison would refuse every new-user acceptance in the system.
func TestAStrangerAcceptsUnderTheirOwnPseudonym(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{knownAccount: false})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}

	result, err := h.accept(issued.Token, acceptor)
	if err != nil {
		t.Fatalf("a newly registered invitee could not accept: %v\nThe invitation names a "+
			"minted pseudonym and their account names another; comparing the two refuses "+
			"every new-user acceptance", err)
	}

	membership, err := h.memberships.Load(context.Background(),
		domain.MembershipStreamKey(h.workspaceID, acceptor))
	if err != nil {
		t.Fatal(err)
	}
	if !membership.Active() {
		t.Fatal("no membership for the accepting account")
	}
	if result.Role != contract.RoleMember {
		t.Errorf("joined as %q", result.Role)
	}
}

// ALREADY A MEMBER IS IDEMPOTENT SUCCESS.
//
// workspace.md §5: the inviter's intent is satisfied. Reporting a conflict would
// make a second click of one link look like a failure.
func TestAcceptingWhenAlreadyAMemberSucceeds(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}

	// Join by another route first.
	membership, err := h.memberships.Load(context.Background(),
		domain.MembershipStreamKey(h.workspaceID, acceptor))
	if err != nil {
		t.Fatal(err)
	}
	if err := membership.Join(h.workspaceID, testOrg, acceptor,
		contract.RoleAdmin, true, time.Unix(1_700_000_000, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := h.memberships.Save(context.Background(),
		domain.MembershipStreamKey(h.workspaceID, acceptor), membership,
		"seed-member", eventsourcing.Metadata{}); err != nil {
		t.Fatal(err)
	}

	result, err := h.accept(issued.Token, acceptor)
	if err != nil {
		t.Fatalf("accepting as an existing member failed: %v", err)
	}
	if !result.AlreadyMember {
		t.Error("the result does not say the caller was already a member")
	}
	if result.Role != contract.RoleAdmin {
		t.Errorf("the reported role is %q, want the role they ALREADY hold; an invitation "+
			"must not silently demote somebody who is already an admin", result.Role)
	}
	if len(h.tokens.spent) != 1 {
		t.Error("the link was left live for an invitation whose intent is already satisfied")
	}
}

// ---------------------------------------------------------------------------
// the seat, across two blind paths
// ---------------------------------------------------------------------------

// THE SEAT AN INVITATION TOOK CARRIES OVER TO THE MEMBERSHIP.
//
// Nothing more is reserved at acceptance, which is the whole point of charging
// at issue: the person was already counted, and counting them again would mean
// the limit binds twice for one join.
func TestAcceptanceReservesNoSecondSeat(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if !issued.SeatConsumed {
		t.Fatal("precondition: issuing took no seat")
	}
	before := len(h.reserver.reserved)

	if _, err := h.accept(issued.Token, acceptor); err != nil {
		t.Fatal(err)
	}
	if got := len(h.reserver.reserved) - before; got != 0 {
		t.Fatalf("acceptance reserved %d more seats; the invitation already paid for this "+
			"person, so the limit would bind twice for one join", got)
	}
}

// A SEAT ALREADY HELD IS NOT CHARGED AGAIN, even when both paths are blind to
// each other.
//
// This is the hole invitations opened. A PENDING invitation holds a seat and
// creates no membership row, so `WorkspaceCount` — which counts memberships —
// answers zero for somebody who is already being paid for. The invite path and
// the direct-add path each ask that question, each get zero, and each reserve.
//
// The store is what closes it: a per-person limit already held is the same seat,
// reported as consumed-nothing rather than taken again.
func TestASeatHeldByAPendingInvitationIsNotChargedTwice(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})

	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if !issued.SeatConsumed {
		t.Fatal("precondition: issuing took no seat")
	}

	// The SAME person, reserved again through the other path. The membership
	// count is still zero — the invitation created no membership — so the
	// conditional check is blind here by construction.
	h.reserver.held["seats.member:"+issued.InvitationID] = true
	seats, err := app.NewSeats(app.SeatsDeps{
		Reserver: h.reserver, Members: &countingMembers{n: 0},
	})
	if err != nil {
		t.Fatal(err)
	}

	before := len(h.reserver.reserved)
	_, consumed, err := seats.ReserveForJoin(context.Background(), testOrg,
		h.issuedEvent(t).SubjectID, contract.RoleMember)
	if err != nil {
		t.Fatalf("reserving for somebody who already holds a seat failed: %v", err)
	}
	if consumed {
		t.Fatal("a second seat was charged for one person: the invitation holds one and " +
			"this took another. The organization pays twice, silently, in the direction " +
			"they notice last")
	}
	if got := len(h.reserver.reserved) - before; got != 0 {
		t.Errorf("the pool grew by %d for a person who already held a seat", got)
	}
}

// ---------------------------------------------------------------------------
// revoke, decline, resend
// ---------------------------------------------------------------------------

func (h *inviteHarness) revoke(invitationID string) (app.RevokeInvitationResult, error) {
	return h.invitations.Revoke(context.Background(), app.RevokeInvitationCommand{
		OrgID: testOrg, WorkspaceID: h.workspaceID, InvitationID: invitationID,
		RevokedBy: founder, IdempotencyKey: "key-revoke-" + invitationID,
	})
}

// REVOKING RETURNS THE SEAT AND KILLS THE LINK.
//
// Both matter and they fail differently. A revocation that left the seat held
// charges for somebody who will never arrive; one that left the link live is not
// a revocation at all.
func TestRevokingReturnsTheSeatAndKillsTheLink(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if !issued.SeatConsumed {
		t.Fatal("precondition: issuing took no seat")
	}

	result, err := h.revoke(issued.InvitationID)
	if err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if !result.SeatReleased {
		t.Error("the seat was not returned; the organization keeps paying for somebody " +
			"who will never arrive")
	}
	if len(h.reserver.released) != 1 || h.reserver.released[0] != "seats.member" {
		t.Errorf("released %v, want one member seat", h.reserver.released)
	}
	if len(h.tokens.revoked) == 0 {
		t.Error("the link was not dropped")
	}

	// And the link genuinely cannot be redeemed, which is the property the two
	// assertions above are proxies for.
	if _, err := h.accept(issued.Token, acceptor); err == nil {
		t.Fatal("a revoked invitation was accepted")
	}

	if inv := h.loadInvitation(t, issued.InvitationID); inv.Status() != domain.InvitationRevoked {
		t.Errorf("the invitation is %s, want revoked", inv.Status())
	}
}

// REVOKING RELEASES NOTHING WHEN NOTHING WAS TAKEN.
//
// The invitee was already in the organization at issue time, so the invitation
// never held a seat — and handing one back would inflate the allowance by one
// every time an invitation to an existing member is withdrawn.
func TestRevokingAnInvitationThatTookNoSeatReleasesNone(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{knownAccount: true, existingWS: 2})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if issued.SeatConsumed {
		t.Fatal("precondition: issuing took a seat")
	}

	result, err := h.revoke(issued.InvitationID)
	if err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if result.SeatReleased {
		t.Fatal("a seat was returned for an invitation that never took one; the pool grows " +
			"by one every time an invitation to an existing member is withdrawn")
	}
	if len(h.reserver.released) != 0 {
		t.Errorf("released %v", h.reserver.released)
	}
}

// AN INVITATION OF ANOTHER WORKSPACE CANNOT BE TOUCHED.
//
// The authz gate checked `admin` on the workspace the REQUEST named. Nothing
// checks that the INVITATION belongs to it — an id is just a string — so without
// this an admin of one workspace could revoke another's invitation and release a
// seat from an organization they have nothing to do with.
func TestAnInvitationOfAnotherWorkspaceIsNotFound(t *testing.T) {
	// Both settlement paths are covered here rather than in two tests, because
	// they share one guard and a test per path would let the guard be removed
	// from one of them with the other still green.
	h := newInviteHarness(t, inviteOpts{})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}

	_, err = h.invitations.Revoke(context.Background(), app.RevokeInvitationCommand{
		OrgID: testOrg, WorkspaceID: "ws_01ARZ3NDEKTSV4RRFFQ69G5FAZ",
		InvitationID: issued.InvitationID, RevokedBy: founder,
		IdempotencyKey: "key-wrong-ws",
	})
	if err == nil {
		t.Fatal("an invitation was revoked through a workspace it does not belong to")
	}
	if got := errs.ReasonOf(err); got != errs.NotFound {
		t.Errorf("refused with %s, want NOT_FOUND: distinguishing 'not yours' from 'no "+
			"such invitation' confirms the id exists (ADR-036)", got)
	}

	// A RESEND is checked too, and it is the more dangerous of the two: a
	// revocation through the wrong workspace releases somebody else's seat, but a
	// resend MINTS A LIVE CREDENTIAL for an invitation the caller has no standing
	// over — and mails it to an address they never chose.
	if _, err := h.invitations.Resend(context.Background(), app.ResendInvitationCommand{
		OrgID: testOrg, WorkspaceID: "ws_01ARZ3NDEKTSV4RRFFQ69G5FAZ",
		InvitationID: issued.InvitationID, IdempotencyKey: "key-resend-wrong-ws",
	}); err == nil {
		t.Fatal("an invitation was resent through a workspace it does not belong to, " +
			"minting a live link for an invitation the caller has no standing over")
	}
	if _, err := h.invitations.Resend(context.Background(), app.ResendInvitationCommand{
		OrgID: "org_01ARZ3NDEKTSV4RRFFQ69G5FAZ", WorkspaceID: h.workspaceID,
		InvitationID: issued.InvitationID, IdempotencyKey: "key-resend-wrong-org",
	}); err == nil {
		t.Fatal("an invitation was resent from another organization's scope")
	}

	_, err = h.invitations.Revoke(context.Background(), app.RevokeInvitationCommand{
		OrgID: "org_01ARZ3NDEKTSV4RRFFQ69G5FAZ", WorkspaceID: h.workspaceID,
		InvitationID: issued.InvitationID, RevokedBy: founder,
		IdempotencyKey: "key-wrong-org",
	})
	if err == nil {
		t.Fatal("an invitation was revoked from another organization's scope")
	}
}

// A SETTLED INVITATION CANNOT BE REVOKED AGAIN.
//
// The double-release: each settlement records SeatReleased and this path acts on
// it, so a second revocation returns a second seat for one hold.
func TestRevokingTwiceIsRefused(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.revoke(issued.InvitationID); err != nil {
		t.Fatal(err)
	}

	_, err = h.revoke(issued.InvitationID)
	if err == nil {
		t.Fatal("an invitation was revoked twice, returning two seats for one hold")
	}
	if got := errs.ReasonOf(err); got != errs.Conflict {
		t.Errorf("refused with %s, want CONFLICT: an administrator who named this "+
			"invitation is entitled to know it is already settled", got)
	}
	if len(h.reserver.released) != 1 {
		t.Errorf("released %v seats across two revocations", h.reserver.released)
	}
}

// DECLINING NEEDS ONLY THE TOKEN.
//
// The person declining may have no account. Requiring one would hold the seat
// until expiry for everybody who is not interested, which is the case a decline
// exists to shorten.
func TestDecliningNeedsOnlyTheToken(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}

	if err := h.invitations.Decline(context.Background(), app.DeclineInvitationCommand{
		Token: issued.Token, IdempotencyKey: "key-decline",
	}); err != nil {
		t.Fatalf("declining: %v", err)
	}

	inv := h.loadInvitation(t, issued.InvitationID)
	if inv.Status() != domain.InvitationDeclined {
		t.Errorf("the invitation is %s, want declined — distinct from revoked, because "+
			"re-inviting somebody who said no is a decision a human should make "+
			"deliberately", inv.Status())
	}
	if len(h.reserver.released) != 1 {
		t.Errorf("released %v, want the seat back", h.reserver.released)
	}
	if _, err := h.accept(issued.Token, acceptor); err == nil {
		t.Fatal("a declined invitation was accepted")
	}
}

// A SUSPENDED ORGANIZATION CANNOT BLOCK A DECLINE.
//
// The one place on these paths that skips the subscription check. Refusing would
// hold the seat until expiry for somebody who has already said no — and the
// person saying no has no way to influence whether the organization pays its
// bill.
func TestDecliningWorksWhileTheOrganizationIsSuspended(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}

	// Accepting is refused once suspended; declining is not. Both are asserted
	// against ONE harness so the difference is the check and not the fixture.
	suspended := newInviteHarness(t, inviteOpts{
		suspended: errs.OrgSuspendedf("this organization is suspended"),
	})
	suspendedIssue, err := suspended.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := suspended.accept(suspendedIssue.Token, acceptor); err == nil {
		t.Fatal("precondition: acceptance was not refused, so this proves nothing")
	}
	if err := suspended.invitations.Decline(context.Background(), app.DeclineInvitationCommand{
		Token: suspendedIssue.Token, IdempotencyKey: "key-decline-suspended",
	}); err != nil {
		t.Fatalf("a suspended organization blocked a decline: %v\nThe seat is then held "+
			"until expiry for somebody who has already said no", err)
	}
	_ = issued
}

// A DECLINE REVEALS NOTHING.
//
// Every refusal on this path is NOT_FOUND, including "already declined". An
// unauthenticated caller learns nothing from the difference, and a caller
// holding a guess learns nothing from a live one.
func TestDecliningRevealsNothing(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.invitations.Decline(context.Background(), app.DeclineInvitationCommand{
		Token: issued.Token, IdempotencyKey: "key-d1",
	}); err != nil {
		t.Fatal(err)
	}

	for name, token := range map[string]string{
		"already declined": issued.Token,
		"never existed":    strings.Repeat("A", 43),
		"empty":            "",
	} {
		t.Run(name, func(t *testing.T) {
			err := h.invitations.Decline(context.Background(), app.DeclineInvitationCommand{
				Token: token, IdempotencyKey: "key-d-" + name,
			})
			if err == nil {
				t.Fatal("accepted it")
			}
			if got := errs.ReasonOf(err); got != errs.NotFound {
				t.Errorf("refused with %s, want NOT_FOUND for every case", got)
			}
		})
	}
}

// A RESEND LEAVES EXACTLY ONE LIVE LINK.
//
// This is "the old token stays dead" (workspace.md §5). Two live credentials for
// one invitation means either can be redeemed, and a resend is precisely when a
// second copy of the mail is in flight.
func TestResendingKillsTheOldLink(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}

	resent, err := h.invitations.Resend(context.Background(), app.ResendInvitationCommand{
		OrgID: testOrg, WorkspaceID: h.workspaceID,
		InvitationID: issued.InvitationID, IdempotencyKey: "key-resend",
	})
	if err != nil {
		t.Fatalf("resending: %v", err)
	}
	if resent.Token == "" || resent.Token == issued.Token {
		t.Fatal("the resend produced no new token, or the same one")
	}
	if len(h.tokens.issued) != 1 {
		t.Fatalf("%d links are live after a resend; either can be redeemed, and one of "+
			"them is in an older mail", len(h.tokens.issued))
	}

	// The OLD link is dead...
	if _, err := h.accept(issued.Token, acceptor); err == nil {
		t.Fatal("the old link still works, so a resent invitation has two live credentials")
	}
	// ...and the new one works.
	if _, err := h.accept(resent.Token, acceptor); err != nil {
		t.Fatalf("the new link does not work, so a resend destroys the invitation: %v", err)
	}
}

// A RESEND EXTENDS THE WINDOW AND TAKES NO SECOND SEAT.
//
// Same invitation: same id, same seat, same authorisation. Re-inviting instead
// would take a second seat for one person and lose the link to the original.
func TestResendingExtendsTheWindowAndCostsNothing(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	before := len(h.reserver.reserved)

	// A day passes, which is what makes the extension observable: the new window
	// is measured from now, so a resend at the same instant lands where the old
	// one did.
	h.clock.advance(24 * time.Hour)

	resent, err := h.invitations.Resend(context.Background(), app.ResendInvitationCommand{
		OrgID: testOrg, WorkspaceID: h.workspaceID,
		InvitationID: issued.InvitationID, IdempotencyKey: "key-resend2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resent.ExpiresAt.After(issued.ExpiresAt) {
		t.Errorf("the window did not move: %s then %s. A link that arrived after the "+
			"original window closed is useless", issued.ExpiresAt, resent.ExpiresAt)
	}
	if got := len(h.reserver.reserved) - before; got != 0 {
		t.Errorf("the resend reserved %d more seats for one person", got)
	}
	if inv := h.loadInvitation(t, issued.InvitationID); inv.InvitationID() != issued.InvitationID {
		t.Error("the resend created a different invitation")
	}
}

// A SETTLED INVITATION CANNOT BE RESENT.
//
// Resending one would put a live credential back on an invitation that was
// revoked, declined or already redeemed — "the old token stays dead" read
// backwards.
func TestResendingASettledInvitationIsRefused(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.revoke(issued.InvitationID); err != nil {
		t.Fatal(err)
	}

	_, err = h.invitations.Resend(context.Background(), app.ResendInvitationCommand{
		OrgID: testOrg, WorkspaceID: h.workspaceID,
		InvitationID: issued.InvitationID, IdempotencyKey: "key-resend3",
	})
	if err == nil {
		t.Fatal("a revoked invitation was resent, putting a live credential back on an " +
			"invitation that was deliberately withdrawn")
	}
	if len(h.tokens.issued) != 0 {
		t.Errorf("%d links are live for a revoked invitation", len(h.tokens.issued))
	}
}
