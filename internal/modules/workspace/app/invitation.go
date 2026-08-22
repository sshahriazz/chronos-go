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
}

// Invitations is the invitation use case.
type Invitations struct {
	repo        *eventsourcing.Repository[*domain.Invitation]
	workspaces  *eventsourcing.Repository[*domain.Workspace]
	memberships *eventsourcing.Repository[*domain.Membership]
	appender    eventsourcing.MultiAppender
	schemas     eventsourcing.SchemaVersions
	tokens      InvitationTokenStore
	indexer     EmailIndexer
	dir         Directory
	subs        Subscriptions
	vault       Addresses
	subjects    SubjectMinter
	seats       *Seats
	now         func() time.Time

	// settlements is the closing half, shared with the worker's sweep so both
	// take the decision through one code path.
	settlements *Settlements
}

// InvitationsDeps is what Invitations needs.
type InvitationsDeps struct {
	Repo        *eventsourcing.Repository[*domain.Invitation]
	Workspaces  *eventsourcing.Repository[*domain.Workspace]
	Memberships *eventsourcing.Repository[*domain.Membership]
	Appender    eventsourcing.MultiAppender
	Schemas     eventsourcing.SchemaVersions
	Tokens      InvitationTokenStore
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
	inv := &Invitations{
		repo: d.Repo, workspaces: d.Workspaces, memberships: d.Memberships,
		appender: d.Appender, schemas: d.Schemas,
		tokens: d.Tokens, indexer: d.Indexer,
		dir: d.Dir, subs: d.Subs, vault: d.Vault, subjects: d.Subjects,
		seats: d.Seats, now: d.Now,
	}
	settlements, err := NewSettlements(SettlementsDeps{
		Repo: d.Repo, Tokens: d.Tokens, Seats: d.Seats, Now: d.Now,
	})
	if err != nil {
		return nil, err
	}
	inv.settlements = settlements
	return inv, nil
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

	// NO TOKEN IS MINTED HERE. The reactor that consumes InvitationIssued mints
	// it, because whoever SENDS the mail must hold the plaintext at the moment
	// it is minted and nothing that survives this request can recover it
	// afterwards — see InvitationIssuer.
	//
	// The cost is stated rather than hidden: this returns BEFORE any link
	// exists, so an admin who resends one second later is asking about a link
	// that may not have been issued yet. It is safe in either order because
	// every issuance voids what came before, so whichever lands second is the
	// one that survives and there is never more than one live link.
	return IssueInvitationResult{
		InvitationID: invitationID, Role: cmd.Role,
		SeatConsumed: consumed, ExpiresAt: expiresAt,
	}, nil
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

// Settlements is the half of the invitation lifecycle that CLOSES one.
//
// Split out because the worker legitimately needs it and cannot build the rest:
// expiring an invitation touches the stream, the token store and the seat pool
// and nothing else, while issuing one needs a blind indexer, an account
// directory and the vault — none of which the worker has, and none of which
// expiry has any business being able to reach.
//
// The narrower type is also the point rather than a side effect. A sweep holding
// the full use case could issue and accept as well as expire.
type Settlements struct {
	repo   *eventsourcing.Repository[*domain.Invitation]
	tokens InvitationTokenStore
	seats  *Seats
	now    func() time.Time
}

// SettlementsDeps is what Settlements needs.
type SettlementsDeps struct {
	Repo   *eventsourcing.Repository[*domain.Invitation]
	Tokens InvitationTokenStore
	Seats  *Seats
	Now    func() time.Time
}

func NewSettlements(d SettlementsDeps) (*Settlements, error) {
	switch {
	case d.Repo == nil:
		return nil, fmt.Errorf("workspace: an invitation repository is required")
	case d.Tokens == nil:
		return nil, fmt.Errorf("workspace: a token store is required; a settlement that " +
			"could not drop the link would leave one live for an invitation that is closed")
	case d.Seats == nil:
		return nil, fmt.Errorf("workspace: seat accounting is required; a settlement that " +
			"cannot release is a seat held for somebody who will never arrive")
	case d.Now == nil:
		return nil, fmt.Errorf("workspace: a clock is required")
	}
	return &Settlements{repo: d.Repo, tokens: d.Tokens, seats: d.Seats, now: d.Now}, nil
}

// RevokeInvitationCommand withdraws an outstanding invitation.
type RevokeInvitationCommand struct {
	OrgID       string
	WorkspaceID string

	InvitationID string

	// RevokedBy is the administrator who withdrew it, empty when the revocation
	// was a consequence rather than a decision.
	RevokedBy string

	IdempotencyKey string
}

// RevokeInvitationResult reports what the withdrawal returned.
type RevokeInvitationResult struct{ SeatReleased bool }

// Revoke withdraws an outstanding invitation.
//
// # The order, and why the append comes first
//
// Append, then kill the links, then return the seat. Every step after the append
// is idempotent and retriable, and none of them can fail in a way that grants
// anything: the invitation is already settled, so a live link left behind cannot
// be redeemed — Accept refuses anything that is not Pending.
//
// The reverse order is what would hurt. Returning the seat before the append
// means a failed append leaves a seat back in the pool for an invitation that is
// still outstanding, and the organization can then over-issue: the pool grows by
// one for every revocation that did not finish. Under-releasing is a customer
// paying for something gone, which an audit finds and a support ticket fixes;
// over-releasing is a limit that silently does not apply.
func (i *Invitations) Revoke(
	ctx context.Context, cmd RevokeInvitationCommand,
) (RevokeInvitationResult, error) {
	inv, err := i.settlements.settle(ctx, cmd.OrgID, cmd.WorkspaceID, cmd.InvitationID, cmd.IdempotencyKey,
		func(inv *domain.Invitation, now time.Time) error {
			return inv.Revoke(cmd.RevokedBy, now)
		})
	if err != nil {
		return RevokeInvitationResult{}, err
	}
	return RevokeInvitationResult{SeatReleased: inv.SeatConsumed()}, nil
}

// DeclineInvitationCommand refuses an invitation.
type DeclineInvitationCommand struct {
	// Token is the plaintext from the link, and the ONLY authorization. The
	// person declining may have no account at all.
	Token string

	IdempotencyKey string
}

// Decline refuses an invitation.
//
// Everything it can do is a release: a seat goes back and a link dies. There is
// no privilege for a stolen token to escalate, which is what makes an
// unauthenticated caller safe here and not on the acceptance path.
func (i *Invitations) Decline(ctx context.Context, cmd DeclineInvitationCommand) error {
	if cmd.IdempotencyKey == "" {
		return errs.ValidationFailedf("an Idempotency-Key is required on every mutating request")
	}
	if cmd.Token == "" {
		return errs.NotFoundf("not found")
	}

	now := i.now().UTC()
	digest := secret.Digest(PurposeInvitation, cmd.Token)

	invitationID, orgID, err := i.tokens.Lookup(ctx, digest, now)
	if err != nil {
		return errs.NotFoundf("not found")
	}

	inv, err := i.repo.Load(ctx, domain.InvitationStreamKey(invitationID))
	if err != nil {
		return errs.Internalf("loading the invitation").Wrap(err)
	}

	// NO subscription check, deliberately, and it is the one place on these
	// paths that skips one. A suspended organization must still be able to have
	// its invitations declined: refusing would hold the seat until expiry for
	// somebody who has already said no, and the person saying no has no way to
	// influence whether the organization pays its bill.
	if _, err := i.settlements.settleLoaded(ctx, inv, orgID, inv.WorkspaceID(), cmd.IdempotencyKey,
		func(inv *domain.Invitation, now time.Time) error { return inv.Decline(now) }); err != nil {
		// NOT_FOUND for everything, including a settled invitation. An
		// unauthenticated caller learns nothing from the difference between "you
		// already declined" and "there is no such invitation".
		return errs.NotFoundf("not found")
	}
	return nil
}

// ResendInvitationCommand issues a fresh link for an outstanding invitation.
type ResendInvitationCommand struct {
	OrgID       string
	WorkspaceID string

	InvitationID string

	IdempotencyKey string
}

// ResendInvitationResult reports the new window.
type ResendInvitationResult struct {
	ExpiresAt time.Time
}

// Resend issues a fresh link and extends the window.
//
// # The old link dies FIRST
//
// Every outstanding digest is dropped before the new one is stored, so exactly
// one link is live afterwards. The order is the whole of "the old token stays
// dead": storing the new one first leaves a window — however short — in which
// two credentials redeem one invitation, and a resend is precisely when a second
// copy of the mail is in flight.
//
// The cost of this order is the harmless one. If the process dies between the
// two, the invitation has NO live link: it still holds its seat, and another
// resend produces one. That is a support request; two live links is a second
// person joining.
func (i *Invitations) Resend(
	ctx context.Context, cmd ResendInvitationCommand,
) (ResendInvitationResult, error) {
	switch {
	case cmd.OrgID == "":
		return ResendInvitationResult{}, errs.Internalf("no organization reached the resend " +
			"handler; gate 1 resolved none")
	case cmd.InvitationID == "":
		return ResendInvitationResult{}, errs.ValidationFailedf("an invitation is required")
	case cmd.IdempotencyKey == "":
		return ResendInvitationResult{}, errs.ValidationFailedf(
			"an Idempotency-Key is required on every mutating request")
	}

	now := i.now().UTC()
	inv, err := i.repo.Load(ctx, domain.InvitationStreamKey(cmd.InvitationID))
	if err != nil {
		return ResendInvitationResult{}, errs.Internalf("loading the invitation").Wrap(err)
	}
	if err := i.settlements.belongsHere(inv, cmd.OrgID, cmd.WorkspaceID); err != nil {
		return ResendInvitationResult{}, err
	}

	expiresAt := now.Add(InvitationTTL)
	if err := inv.RotateToken(expiresAt, now); err != nil {
		return ResendInvitationResult{}, errs.Conflictf("%s", err)
	}

	// AGAIN, no minting here. The reactor consumes InvitationTokenRotated and
	// mints — voiding the previous link first, which is what makes "the old
	// token stays dead" a property of the issuer rather than of this ordering.
	if _, err := i.repo.Save(ctx, domain.InvitationStreamKey(cmd.InvitationID), inv,
		cmd.IdempotencyKey, eventsourcing.Metadata{
			OrgID: cmd.OrgID, WorkspaceID: inv.WorkspaceID(), OccurredAt: now,
		},
	); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return ResendInvitationResult{}, errs.Conflictf("this invitation changed concurrently")
		}
		return ResendInvitationResult{}, errs.Internalf("recording the resend").Wrap(err)
	}

	return ResendInvitationResult{ExpiresAt: expiresAt}, nil
}

// settle loads an invitation an ADMINISTRATOR named and applies a terminal
// transition to it.
func (s *Settlements) settle(
	ctx context.Context, orgID, workspaceID, invitationID, key string,
	apply func(*domain.Invitation, time.Time) error,
) (*domain.Invitation, error) {
	switch {
	case orgID == "":
		return nil, errs.Internalf("no organization reached the handler; gate 1 resolved none")
	case invitationID == "":
		return nil, errs.ValidationFailedf("an invitation is required")
	case key == "":
		return nil, errs.ValidationFailedf(
			"an Idempotency-Key is required on every mutating request")
	}

	inv, err := s.repo.Load(ctx, domain.InvitationStreamKey(invitationID))
	if err != nil {
		return nil, errs.Internalf("loading the invitation").Wrap(err)
	}
	if err := s.belongsHere(inv, orgID, workspaceID); err != nil {
		return nil, err
	}
	return s.settleLoaded(ctx, inv, orgID, workspaceID, key, apply)
}

// settleLoaded applies a terminal transition and cleans up after it.
//
// Append, then kill the links, then return the seat — see Revoke for why that
// order and not the reverse.
func (s *Settlements) settleLoaded(
	ctx context.Context, inv *domain.Invitation, orgID, workspaceID, key string,
	apply func(*domain.Invitation, time.Time) error,
) (*domain.Invitation, error) {
	now := s.now().UTC()
	seatConsumed := inv.SeatConsumed()
	role := inv.Role()
	subjectID := inv.SubjectID()

	if err := apply(inv, now); err != nil {
		// CONFLICT and not NOT_FOUND: an administrator who named this invitation
		// is entitled to know it has already been settled, and "not found" would
		// send them looking for a typo.
		return nil, errs.Conflictf("%s", err)
	}

	if _, err := s.repo.Save(ctx, domain.InvitationStreamKey(inv.InvitationID()), inv, key,
		eventsourcing.Metadata{OrgID: orgID, WorkspaceID: workspaceID, OccurredAt: now},
	); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return nil, errs.Conflictf("this invitation changed concurrently")
		}
		return nil, errs.Internalf("settling the invitation").Wrap(err)
	}

	// The link dies. After the append, because the append is what makes it
	// unredeemable — a live digest for a settled invitation is refused by
	// Accept, so this is defence in depth rather than the control itself.
	if _, err := s.tokens.RevokeAll(ctx, inv.InvitationID()); err != nil {
		return inv, errs.Internalf("the invitation was settled but its link was not " +
			"dropped; it cannot be redeemed, because acceptance refuses anything that is " +
			"not pending").Wrap(err)
	}

	// The seat comes back last, and only if one was taken. Releasing one that
	// was never taken inflates the allowance every time it happens.
	if seatConsumed {
		if _, err := s.seats.ReleaseOnRemoval(ctx, orgID, subjectID, role, 0); err != nil {
			return inv, errs.Internalf("the invitation was settled but its seat was not " +
				"returned; the organization is paying for somebody who will not arrive").
				Wrap(err)
		}
	}
	return inv, nil
}

// belongsHere refuses an invitation that is not the caller's to touch.
//
// The authz gate checked `admin` on the WORKSPACE the request named. Nothing
// checked that the INVITATION belongs to that workspace — an id is just a
// string, and an admin of one workspace naming another's invitation would
// otherwise revoke it and release a seat from an organization they have nothing
// to do with.
//
// NOT_FOUND, never a message that distinguishes "no such invitation" from "not
// yours": both would confirm an id exists (ADR-036).
func (s *Settlements) belongsHere(inv *domain.Invitation, orgID, workspaceID string) error {
	if !inv.Exists() || inv.OrgID() != orgID {
		return errs.NotFoundf("not found")
	}
	if workspaceID != "" && inv.WorkspaceID() != workspaceID {
		return errs.NotFoundf("not found")
	}
	return nil
}

// Expire closes an invitation whose window has run out and returns its seat.
//
// Reports whether it actually expired one. FALSE is a normal answer and not an
// error: the caller is a sweep working from a projection, and by the time it
// reaches here the invitation may have been accepted, revoked, declined — or
// RESENT, which moves the deadline past the one the row was selected on.
//
// The domain refuses to expire early, and that refusal is what makes a stale row
// harmless. This is the layer that turns it into "nothing to do" rather than a
// failure, because a sweep that counted every lagging row as an error would
// report a healthy system as broken every time somebody pressed resend.
//
// # No subscription check, deliberately
//
// Expiry RELEASES a seat. A suspended organization must still get its seats back
// — refusing here would hold them for as long as the suspension lasts, which
// bills a customer for invitations that can no longer be accepted by anyone.
func (s *Settlements) Expire(ctx context.Context, invitationID string) (bool, error) {
	if invitationID == "" {
		return false, errs.ValidationFailedf("an invitation is required")
	}

	inv, err := s.repo.Load(ctx, domain.InvitationStreamKey(invitationID))
	if err != nil {
		return false, errs.Internalf("loading the invitation").Wrap(err)
	}
	if !inv.Exists() || !inv.Pending() {
		return false, nil
	}

	now := s.now().UTC()
	if !inv.Expired(now) {
		// Resent since the row was read. Not an error, and emphatically not an
		// expiry: the link in somebody's inbox is live, and closing the
		// invitation would kill it and take back a seat that is still needed.
		return false, nil
	}

	// A DERIVED idempotency key, so a retried sweep pass produces byte-identical
	// event ids and the store refuses the redelivery rather than appending a
	// second expiry — which would release a second seat for one hold.
	//
	// Keyed on the DEADLINE rather than on the pass, because two passes closing
	// the same invitation are the same work while a resend followed by a later
	// expiry is not.
	key := "expire:" + invitationID + ":" + inv.ExpiresAt().UTC().Format(time.RFC3339Nano)

	if _, err := s.settleLoaded(ctx, inv, inv.OrgID(), inv.WorkspaceID(), key,
		func(inv *domain.Invitation, at time.Time) error { return inv.Expire(at) }); err != nil {
		return false, err
	}
	return true, nil
}

// InvitationState is what a timer needs to decide what to do next.
//
// Read from the AGGREGATE, never the projection: the per-invitation workflow
// wakes to decide whether to remind, expire or stop, and a projection that lags
// would have it remind about an invitation somebody already accepted.
type InvitationState struct {
	Exists      bool
	Pending     bool
	OrgID       string
	WorkspaceID string
	SubjectID   string
	ExpiresAt   time.Time
}

// State reports where an invitation currently is.
//
// The window is the interesting field. A resend MOVES it, so anything sleeping
// until a deadline has to re-read rather than trust the one it was started with
// — otherwise a resent invitation is expired at its original deadline while a
// live link sits in somebody's inbox.
func (s *Settlements) State(ctx context.Context, invitationID string) (InvitationState, error) {
	if invitationID == "" {
		return InvitationState{}, errs.ValidationFailedf("an invitation is required")
	}
	inv, err := s.repo.Load(ctx, domain.InvitationStreamKey(invitationID))
	if err != nil {
		return InvitationState{}, errs.Internalf("loading the invitation").Wrap(err)
	}
	return InvitationState{
		Exists:      inv.Exists(),
		Pending:     inv.Pending(),
		OrgID:       inv.OrgID(),
		WorkspaceID: inv.WorkspaceID(),
		SubjectID:   inv.SubjectID(),
		ExpiresAt:   inv.ExpiresAt(),
	}, nil
}
