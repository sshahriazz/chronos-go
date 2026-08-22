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
	repo     *eventsourcing.Repository[*domain.Invitation]
	tokens   InvitationTokenStore
	minter   *secret.Minter
	indexer  EmailIndexer
	dir      Directory
	vault    Addresses
	subjects SubjectMinter
	seats    *Seats
	now      func() time.Time
}

// InvitationsDeps is what Invitations needs.
type InvitationsDeps struct {
	Repo     *eventsourcing.Repository[*domain.Invitation]
	Tokens   InvitationTokenStore
	Minter   *secret.Minter
	Indexer  EmailIndexer
	Dir      Directory
	Vault    Addresses
	Subjects SubjectMinter
	Seats    *Seats
	Now      func() time.Time
}

func NewInvitations(d InvitationsDeps) (*Invitations, error) {
	switch {
	case d.Repo == nil:
		return nil, fmt.Errorf("workspace: an invitation repository is required")
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
		repo: d.Repo, tokens: d.Tokens, minter: d.Minter, indexer: d.Indexer,
		dir: d.Dir, vault: d.Vault, subjects: d.Subjects, seats: d.Seats, now: d.Now,
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
