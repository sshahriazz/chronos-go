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

func (f *fakeTokens) Consume(context.Context, []byte, time.Time) (string, string, error) {
	return "", "", app.ErrInvitationTokenNotFound
}

func (f *fakeTokens) RevokeAll(_ context.Context, invitationID string) (int64, error) {
	f.revoked = append(f.revoked, invitationID)
	return 1, nil
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
}

type inviteOpts struct {
	knownAccount bool
	existingWS   int
	indexErr     error
	dirErr       error
	vaultErr     error
	tokenErr     error
	poolFull     string
}

func newInviteHarness(t *testing.T, o inviteOpts) *inviteHarness {
	t.Helper()
	store := newMemStore()
	now := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

	repo := eventsourcing.NewRepository[*domain.Invitation](
		store, jsonCodec{}, nil, domain.InvitationCategory, domain.NewInvitation)

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

	invitations, err := app.NewInvitations(app.InvitationsDeps{
		Repo: repo, Tokens: tokens, Minter: minter,
		Indexer: fakeIndexer{err: o.indexErr}, Dir: dir,
		Vault: vault, Subjects: subjects, Seats: seats, Now: now,
	})
	if err != nil {
		t.Fatalf("NewInvitations: %v", err)
	}
	return &inviteHarness{
		invitations: invitations, store: store, tokens: tokens,
		vault: vault, subjects: subjects, reserver: reserver,
	}
}

func (h *inviteHarness) issue(role contract.MemberRole) (app.IssueInvitationResult, error) {
	return h.invitations.Issue(context.Background(), app.IssueInvitationCommand{
		OrgID: testOrg, WorkspaceID: "ws_01ARZ3NDEKTSV4RRFFQ69G5FAV", Email: inviteeEmail,
		Role: role, InvitedBy: founder, IdempotencyKey: "key-invite",
	})
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
	if len(h.store.streams) != 0 {
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
	if len(h.store.streams) != 0 {
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
	if len(h.store.streams) == 0 {
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
		Repo: repo, Tokens: &fakeTokens{}, Minter: minter,
		Indexer: fakeIndexer{}, Dir: fakeDirectory{}, Vault: &fakeVault{},
		Subjects: &fakeSubjects{}, Seats: seats, Now: time.Now,
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
		{"no repository", func(d *app.InvitationsDeps) { d.Repo = nil }, "repository"},
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
