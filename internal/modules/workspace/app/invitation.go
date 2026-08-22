package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/secret"
)

// IssueInvitationCommand invites an address into a workspace.
type IssueInvitationCommand struct {
	OrgID       string
	WorkspaceID string

	// Email is the ONLY personal data that crosses this boundary. It reaches the
	// vault and the blind indexer and goes no further: no event, no log line, no
	// projection carries it.
	Email string

	Role      contract.MemberRole
	InvitedBy string

	IdempotencyKey string
}

// IssueInvitationResult is what the caller gets back.
type IssueInvitationResult struct {
	InvitationID string
	Role         contract.MemberRole
	SeatConsumed bool
	ExpiresAt    time.Time

	// Token is the plaintext, returned EXACTLY ONCE and only so the mail can
	// carry it. It must never be logged, stored, or put in a response body — the
	// API layer drops it, and the notification path is the only consumer.
	Token string
}

// Invitations is the invitation use case.
type Invitations struct {
	repo        *eventsourcing.Repository[*domain.Invitation]
	workspaces  *eventsourcing.Repository[*domain.Workspace]
	memberships *eventsourcing.Repository[*domain.Membership]
	appender    eventsourcing.MultiAppender
	schemas     eventsourcing.SchemaVersions
	tokens      InvitationTokenStore
	minter      *secret.Minter
	indexer     EmailIndexer
	dir         Directory
	subs        Subscriptions
	vault       Addresses
	subjects    SubjectMinter
	seats       *Seats
	now         func() time.Time
}

// InvitationsDeps is what Invitations needs.
type InvitationsDeps struct {
	Repo        *eventsourcing.Repository[*domain.Invitation]
	Workspaces  *eventsourcing.Repository[*domain.Workspace]
	Memberships *eventsourcing.Repository[*domain.Membership]
	Appender    eventsourcing.MultiAppender
	Schemas     eventsourcing.SchemaVersions
	Tokens      InvitationTokenStore
	Minter      *secret.Minter
	Indexer     EmailIndexer
	Dir         Directory
	Subs        Subscriptions
	Vault       Addresses
	Subjects    SubjectMinter
	Seats       *Seats
	Now         func() time.Time
}

func NewInvitations(d InvitationsDeps) (*Invitations, error) {
	switch {
	case d.Repo == nil:
		return nil, fmt.Errorf("workspace: an invitation repository is required")
	case d.Workspaces == nil:
		return nil, fmt.Errorf("workspace: a workspace repository is required; acceptance " +
			"revalidates that the workspace is still active, and a link days old must not " +
			"admit somebody to an archived one")
	case d.Memberships == nil:
		return nil, fmt.Errorf("workspace: a membership repository is required; accepting " +
			"an invitation is what creates one")
	case d.Appender == nil:
		return nil, fmt.Errorf("workspace: an appender is required; settling the invitation " +
			"and creating the membership are ONE atomic append, and two appends leave " +
			"either a spent invitation admitting nobody or a live one for somebody who " +
			"has already joined")
	case d.Schemas == nil:
		return nil, fmt.Errorf("workspace: a schema registry is required; an event stored " +
			"without its version cannot be upcast later (ADR-029)")
	case d.Subs == nil:
		return nil, fmt.Errorf("workspace: a subscription check is required; acceptance " +
			"cannot use the interceptor's, because the person clicking the link may not be " +
			"in the organization yet and there is no scope for gate 1 to resolve")
	case d.Tokens == nil:
		return nil, fmt.Errorf("workspace: an invitation token store is required; without " +
			"one an invitation is issued with no credential and can never be redeemed")
	case d.Minter == nil:
		return nil, fmt.Errorf("workspace: a token minter is required")
	case d.Indexer == nil:
		return nil, fmt.Errorf("workspace: a blind indexer is required; without one the " +
			"event would have to carry the address itself (ADR-002)")
	case d.Dir == nil:
		return nil, fmt.Errorf("workspace: a directory is required; an invitation to " +
			"somebody who already has an account must name THEIR pseudonym, or accepting " +
			"it creates a second identity for one person")
	case d.Vault == nil:
		return nil, fmt.Errorf("workspace: a vault is required; the address has to be " +
			"recorded somewhere the mail can resolve it at send time")
	case d.Subjects == nil:
		return nil, fmt.Errorf("workspace: a subject minter is required for invitees with " +
			"no account yet")
	case d.Seats == nil:
		return nil, fmt.Errorf("workspace: seat accounting is required; a seat is taken AT " +
			"ISSUE, and without it 60 pending invitations against 50 seats all look valid")
	case d.Now == nil:
		return nil, fmt.Errorf("workspace: a clock is required")
	}
	return &Invitations{
		repo: d.Repo, workspaces: d.Workspaces, memberships: d.Memberships,
		appender: d.Appender, schemas: d.Schemas,
		tokens: d.Tokens, minter: d.Minter, indexer: d.Indexer,
		dir: d.Dir, subs: d.Subs, vault: d.Vault, subjects: d.Subjects,
		seats: d.Seats, now: d.Now,
	}, nil
}

// Issue invites an address into a workspace.
//
// # The order, and what each step costs if it fails
//
//	index → resolve subject → vault → seat → append → token
//
// The blind index first, because it is pure and validates the address: failing
// later would mean a seat reserved for an address this system will not accept.
//
// The vault BEFORE the append, because the event names a pseudonym and the only
// thing that makes that pseudonym mean anything is the vault entry behind it. An
// event with no entry is an invitation nobody can send, and nothing in the log
// can repair it.
//
// The seat before the append, for the reason Members.Add gives: a recorded
// invitation that no seat backs is a limit that silently does not apply. The
// seat is taken AT ISSUE rather than at acceptance, because otherwise 60 pending
// invitations against 50 seats all look valid and the 51st acceptance fails for
// somebody who did nothing wrong (workspace.md §5).
//
// The token LAST, and it is the one step whose failure is recoverable: the
// invitation exists, holds its seat, and has no live link — which is a resend
// away, and is reported so the caller knows to resend.
func (i *Invitations) Issue(
	ctx context.Context, cmd IssueInvitationCommand,
) (IssueInvitationResult, error) {
	if err := cmd.validate(); err != nil {
		return IssueInvitationResult{}, err
	}
	if err := validRoleOnTheWire(cmd.Role); err != nil {
		return IssueInvitationResult{}, err
	}

	index, err := i.indexer.Of(cmd.Email)
	if err != nil {
		// The address itself never reaches the error. A message quoting it would
		// be logged, and a log line is exactly where an address must not be.
		return IssueInvitationResult{}, errs.ValidationFailedf(
			"that is not an address this system will accept")
	}

	subjectID, known, err := i.dir.SubjectFor(ctx, index)
	if err != nil {
		return IssueInvitationResult{}, errs.Internalf("resolving the invitee").Wrap(err)
	}
	if !known {
		// Nobody by that address yet. The pseudonym exists only to hang the
		// vault entry off — it is NOT an account, and it does not become one:
		// when this person registers, identity mints its own, and the two are
		// reconciled by InvitationAccepted.AcceptedBy rather than by pretending
		// one pseudonym was the other.
		subjectID = i.subjects.NewSubject()
	}

	// Written whether or not the subject is new. For a known account the vault
	// already holds this address under this pseudonym, so it is a no-op write
	// rather than a branch — and a branch here would be the kind that is right
	// until somebody changes their address.
	if err := i.vault.PutEmail(ctx, subjectID, cmd.Email); err != nil {
		return IssueInvitationResult{}, errs.Internalf("recording the invitee's address").Wrap(err)
	}

	now := i.now().UTC()
	invitationID := ids.New[ids.Invitation](now, ids.Entropy()).String()
	expiresAt := now.Add(InvitationTTL)

	// Conditional, exactly as a join is: somebody already in this organization
	// holds a seat, and inviting them into another workspace costs nothing.
	_, consumed, err := i.seats.ReserveForJoin(ctx, cmd.OrgID, subjectID, cmd.Role)
	if err != nil {
		return IssueInvitationResult{}, errs.QuotaExceededf("%s", err)
	}
	release := func() {
		if consumed {
			_, _ = i.seats.ReleaseOnRemoval(ctx, cmd.OrgID, subjectID, cmd.Role, 0)
		}
	}

	inv, err := i.repo.Load(ctx, domain.InvitationStreamKey(invitationID))
	if err != nil {
		release()
		return IssueInvitationResult{}, errs.Internalf("loading the invitation stream").Wrap(err)
	}
	if err := inv.Issue(invitationID, cmd.WorkspaceID, cmd.OrgID, subjectID, string(index),
		cmd.InvitedBy, cmd.Role, consumed, expiresAt, now); err != nil {
		release()
		return IssueInvitationResult{}, errs.ValidationFailedf("%s", err)
	}

	if _, err := i.repo.Save(ctx, domain.InvitationStreamKey(invitationID), inv,
		cmd.IdempotencyKey, eventsourcing.Metadata{
			OrgID: cmd.OrgID, WorkspaceID: cmd.WorkspaceID, OccurredAt: now,
		},
	); err != nil {
		release()
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return IssueInvitationResult{}, errs.Conflictf("this invitation was already issued")
		}
		return IssueInvitationResult{}, errs.Internalf("issuing the invitation").Wrap(err)
	}

	result := IssueInvitationResult{
		InvitationID: invitationID, Role: cmd.Role,
		SeatConsumed: consumed, ExpiresAt: expiresAt,
	}

	minted, err := i.minter.Mint(PurposeInvitation, now)
	if err != nil {
		// The invitation EXISTS and holds its seat. Reported as a partial
		// success rather than a failure, because telling the caller it failed
		// would have them issue a second one — a second seat, a second pending
		// invitation, for one person.
		return result, errs.Internalf("the invitation was issued but no link could be " +
			"minted for it; resend to produce one")
	}
	if err := i.tokens.Issue(ctx, minted.Digest, invitationID, cmd.OrgID, minted.ExpiresAt); err != nil {
		return result, errs.Internalf("the invitation was issued but its link could not be " +
			"stored; resend to produce one").Wrap(err)
	}

	result.Token = minted.Plaintext
	return result, nil
}

func (c IssueInvitationCommand) validate() error {
	switch {
	case c.OrgID == "":
		return errs.Internalf("no organization reached the invite handler; gate 1 resolved none")
	case c.WorkspaceID == "":
		return errs.ValidationFailedf("a workspace is required")
	case c.Email == "":
		return errs.ValidationFailedf("an address is required")
	case c.InvitedBy == "":
		return errs.Internalf("no authenticated subject reached the invite handler")
	case c.IdempotencyKey == "":
		return errs.ValidationFailedf(
			"an Idempotency-Key is required on every mutating request")
	}
	return nil
}

// AcceptInvitationCommand redeems an invitation link.
type AcceptInvitationCommand struct {
	// Token is the plaintext from the link. It is hashed here and compared as a
	// digest; the plaintext never reaches a store or a log.
	Token string

	// AcceptedBy is the authenticated caller. Not a field the request can name —
	// the API layer reads it from the session, for the reason selfCheck's subject
	// is safe.
	AcceptedBy string

	IdempotencyKey string
}

// AcceptInvitationResult is what the caller gets back.
type AcceptInvitationResult struct {
	WorkspaceID string
	OrgID       string
	Role        contract.MemberRole

	// AlreadyMember is the idempotent path: the caller was already in the
	// workspace, so nothing changed and nothing was charged.
	AlreadyMember bool
}

// Accept redeems an invitation.
//
// # Every check is revalidated HERE, not trusted from issue time
//
// workspace.md §5 lists them, and the reason they cannot be trusted is that days
// pass between issue and acceptance: an organization goes past due, a workspace
// is archived, a seat pool fills up, an invitation is revoked. Trusting the
// issue-time decision would let a link admit somebody to a tenant that has since
// stopped paying.
//
// # The order, and why the token is looked up twice
//
// Lookup → checks → consume → append. The token is READ first and SPENT last,
// so a transient refusal — a briefly past-due organization, a momentarily full
// pool — leaves the link alive to retry. Consuming first would burn it for a
// failure the recipient did nothing to cause, and only a resend could repair it.
//
// Single use is unaffected: Consume is one atomic DELETE ... RETURNING, so two
// simultaneous clicks still resolve to exactly one winner.
func (i *Invitations) Accept(
	ctx context.Context, cmd AcceptInvitationCommand,
) (AcceptInvitationResult, error) {
	switch {
	case cmd.Token == "":
		return AcceptInvitationResult{}, errs.NotFoundf("not found")
	case cmd.AcceptedBy == "":
		return AcceptInvitationResult{}, errs.Internalf("no authenticated subject reached " +
			"the accept handler")
	case cmd.IdempotencyKey == "":
		return AcceptInvitationResult{}, errs.ValidationFailedf(
			"an Idempotency-Key is required on every mutating request")
	}

	now := i.now().UTC()
	digest := secret.Digest(PurposeInvitation, cmd.Token)

	// CHECK 1: the token is valid, unexpired and unspent.
	//
	// One answer for all three, and the same answer a wrong token gets:
	// distinguishing them tells somebody holding a guessed value that they
	// guessed a real one, and tells anybody with an old mail whether the
	// organization still exists.
	invitationID, orgID, err := i.tokens.Lookup(ctx, digest, now)
	if err != nil {
		return AcceptInvitationResult{}, errs.NotFoundf("not found")
	}

	// CHECK 2: the organization's subscription still permits growth.
	//
	// ORG_SUSPENDED and not NOT_FOUND, because by this point the caller has
	// presented a valid credential for this organization — they are entitled to
	// know why they cannot join, and "not found" would send them back to an
	// inviter who can see the invitation is fine.
	if err := i.subs.PermitJoin(ctx, orgID); err != nil {
		return AcceptInvitationResult{}, err
	}

	inv, err := i.repo.Load(ctx, domain.InvitationStreamKey(invitationID))
	if err != nil {
		return AcceptInvitationResult{}, errs.Internalf("loading the invitation").Wrap(err)
	}
	if !inv.Exists() || !inv.Pending() || inv.Expired(now) {
		// A live token for a settled invitation should not exist — every
		// settlement revokes the digests — so reaching here means the two stores
		// disagree. NOT_FOUND either way: the caller learns nothing from which
		// of the two refused them.
		return AcceptInvitationResult{}, errs.NotFoundf("not found")
	}

	// CHECK 3: the workspace is still active.
	//
	// From the AGGREGATE and not a projection, because a projection lags and
	// this decision admits somebody to a tenant. It is loaded anyway when the
	// role is admin, so the cost is one read on the other paths.
	ws, err := i.workspaces.Load(ctx, domain.StreamKey(inv.WorkspaceID()))
	if err != nil {
		return AcceptInvitationResult{}, errs.Internalf("loading the workspace").Wrap(err)
	}
	if ws.Status() != domain.StatusActive {
		// NOT_FOUND, because an archived workspace is one the caller has no
		// standing to learn about: they are not a member, and telling them it
		// exists but is archived is an existence oracle (ADR-036).
		return AcceptInvitationResult{}, errs.NotFoundf("not found")
	}

	// CHECK 4: the caller is the person this was sent to.
	//
	// Only when the invitation names a real account. An invitation to somebody
	// with no account names a MINTED pseudonym, which is not an account and
	// cannot match anybody — and needs no comparison, because holding the link
	// is proof of control over the mailbox it was sent to.
	//
	// This is the footgun workspace.md §5 calls out: a forwarded link, or a
	// shared machine, silently binding the invitation to whoever happened to be
	// signed in. It is refused EXPLICITLY rather than quietly, because the fix —
	// sign in as the right person — is one the caller can act on and cannot
	// guess.
	invitedIsAccount, err := i.dir.IsAccount(ctx, inv.SubjectID())
	if err != nil {
		return AcceptInvitationResult{}, errs.Internalf("resolving the invitee").Wrap(err)
	}
	if invitedIsAccount && inv.SubjectID() != cmd.AcceptedBy {
		return AcceptInvitationResult{}, errs.AccessDeniedf(
			"this invitation was sent to a different account; sign in as that account to " +
				"accept it")
	}

	// Already in? Idempotent success. The inviter's intent is satisfied, and
	// reporting a conflict would make a second click of one link look like a
	// failure.
	membershipKey := domain.MembershipStreamKey(inv.WorkspaceID(), cmd.AcceptedBy)
	membership, err := i.memberships.Load(ctx, membershipKey)
	if err != nil {
		return AcceptInvitationResult{}, errs.Internalf("loading the membership").Wrap(err)
	}
	if membership.Exists() && membership.Active() {
		// The token is spent anyway, so the invitation cannot be redeemed twice
		// by somebody else, and the pending invitation is settled below by the
		// same append.
		if _, _, err := i.tokens.Consume(ctx, digest, now); err != nil {
			return AcceptInvitationResult{}, errs.NotFoundf("not found")
		}
		return AcceptInvitationResult{
			WorkspaceID: inv.WorkspaceID(), OrgID: orgID,
			Role: membership.Role(), AlreadyMember: true,
		}, nil
	}

	// CHECK 5: the seat the invitation reserved is still held.
	//
	// The invitation recorded whether ISSUING took one. If it did, that seat
	// carries over to the membership and nothing more is reserved — which is the
	// whole point of charging at issue. If it did NOT, the invitee was already in
	// the organization at issue time and may not be now, so the question is asked
	// again.
	seatConsumed := inv.SeatConsumed()
	if !seatConsumed {
		_, seatConsumed, err = i.seats.ReserveForJoin(ctx, orgID, cmd.AcceptedBy, inv.Role())
		if err != nil {
			return AcceptInvitationResult{}, errs.QuotaExceededf("%s", err)
		}
	}

	// SPEND the token. Last of the checks and first of the writes: from here on
	// nothing may fail in a way a retry would fix, because a retry has no link.
	if _, _, err := i.tokens.Consume(ctx, digest, now); err != nil {
		// Somebody else won the race, or it expired between the lookup and here.
		return AcceptInvitationResult{}, errs.NotFoundf("not found")
	}

	if err := i.appendAcceptance(ctx, inv, membership, cmd, orgID, seatConsumed, now); err != nil {
		return AcceptInvitationResult{}, err
	}

	return AcceptInvitationResult{
		WorkspaceID: inv.WorkspaceID(), OrgID: orgID, Role: inv.Role(),
	}, nil
}

// appendAcceptance settles the invitation and creates the membership in ONE
// atomic append.
//
// Two streams, and they cannot be two appends. An invitation accepted with no
// membership behind it spends a seat and a token and admits nobody; a membership
// with the invitation still pending leaves a live invitation for somebody who
// has already joined, which a second person could not redeem — the token is
// gone — but which the expiry workflow would later "release a seat" for, taking
// back the seat the new member is sitting in.
func (i *Invitations) appendAcceptance(
	ctx context.Context, inv *domain.Invitation, membership *domain.Membership,
	cmd AcceptInvitationCommand, orgID string, seatConsumed bool, now time.Time,
) error {
	if err := inv.Accept(cmd.AcceptedBy, now); err != nil {
		return errs.ValidationFailedf("%s", err)
	}
	if err := membership.Join(inv.WorkspaceID(), orgID, cmd.AcceptedBy,
		inv.Role(), seatConsumed, now); err != nil {
		return errs.ValidationFailedf("%s", err)
	}

	invStream, err := eventsourcing.NewStreamID(domain.InvitationCategory,
		domain.InvitationStreamKey(inv.InvitationID()))
	if err != nil {
		return errs.Internalf("invitation stream").Wrap(err)
	}
	memberStream, err := eventsourcing.NewStreamID(domain.MembershipCategory,
		domain.MembershipStreamKey(inv.WorkspaceID(), cmd.AcceptedBy))
	if err != nil {
		return errs.Internalf("membership stream").Wrap(err)
	}

	meta := eventsourcing.Metadata{
		OrgID: orgID, WorkspaceID: inv.WorkspaceID(), OccurredAt: now,
	}

	if _, err := i.appender.AppendToMany(ctx, []eventsourcing.StreamAppend{
		{
			Stream: invStream,
			// The revision the aggregate was loaded at. A concurrent settlement —
			// a revocation racing an acceptance — is refused here rather than
			// producing an invitation that is both.
			Expected: eventsourcing.AtRevision(inv.Version()),
			Events:   i.pending(inv.Uncommitted(), cmd.IdempotencyKey, meta),
		},
		{
			Stream:   memberStream,
			Expected: eventsourcing.NoStream(),
			Events: i.pending(membership.Uncommitted(),
				cmd.IdempotencyKey+":member", meta),
		},
	}); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return errs.Conflictf("this invitation changed while it was being accepted")
		}
		return errs.Internalf("accepting the invitation").Wrap(err)
	}
	return nil
}

// pending stamps a set of recorded events for an append.
func (i *Invitations) pending(
	events []eventsourcing.Event, key string, meta eventsourcing.Metadata,
) []eventsourcing.PendingEvent {
	out := make([]eventsourcing.PendingEvent, 0, len(events))
	for n, e := range events {
		out = append(out, eventsourcing.PendingEvent{
			ID:    eventsourcing.DeriveEventID(key, n),
			Event: e,
			Meta:  eventsourcing.StampSchemaVersion(meta, i.schemas, e.EventType()),
		})
	}
	return out
}
