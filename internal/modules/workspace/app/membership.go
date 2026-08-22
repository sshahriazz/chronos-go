package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// AddMemberCommand puts an account into a workspace.
type AddMemberCommand struct {
	OrgID       string
	WorkspaceID string
	SubjectID   string
	Role        contract.MemberRole

	IdempotencyKey string
}

// AddMemberResult reports what the join cost.
type AddMemberResult struct {
	Role         contract.MemberRole
	SeatConsumed bool
}

// RemoveMemberCommand takes an account out of a workspace.
type RemoveMemberCommand struct {
	OrgID       string
	WorkspaceID string
	SubjectID   string

	IdempotencyKey string
}

// RemoveMemberResult reports what the removal returned.
type RemoveMemberResult struct {
	SeatReleased bool
}

// ChangeRoleCommand promotes or demotes a member.
type ChangeRoleCommand struct {
	OrgID       string
	WorkspaceID string
	SubjectID   string
	Role        contract.MemberRole

	IdempotencyKey string
}

// ChangeRoleResult reports the role now held.
type ChangeRoleResult struct {
	Role contract.MemberRole
}

// Members is the membership use case.
//
// # Two aggregates, deliberately
//
// The Workspace aggregate holds the admin roster, because "never zero admins" is
// an invariant across the whole set and an invariant needs one stream to be
// decided in. Each Membership is its own aggregate, because memberships are
// high-volume and churn — putting thousands of them in the workspace stream
// would make every join contend with every other for the same revision
// (workspace.md §1).
//
// The cost is that a role change involving `admin` touches BOTH, and the order
// below is what keeps that safe.
type Members struct {
	workspaces  *eventsourcing.Repository[*domain.Workspace]
	memberships *eventsourcing.Repository[*domain.Membership]
	seats       *Seats
	counter     OrgMembership
	revoker     authz.Revoker
	now         func() time.Time
}

// MembersDeps is what Members needs.
type MembersDeps struct {
	Workspaces  *eventsourcing.Repository[*domain.Workspace]
	Memberships *eventsourcing.Repository[*domain.Membership]
	Seats       *Seats
	Counter     OrgMembership
	Revoker     authz.Revoker
	Now         func() time.Time
}

func NewMembers(d MembersDeps) (*Members, error) {
	switch {
	case d.Workspaces == nil:
		return nil, fmt.Errorf("workspace: a workspace repository is required; the admin " +
			"roster lives there and the never-zero rule is decided against it")
	case d.Memberships == nil:
		return nil, fmt.Errorf("workspace: a membership repository is required")
	case d.Seats == nil:
		return nil, fmt.Errorf("workspace: seat accounting is required; without it every join " +
			"is free and the plan's seat limit never binds")
	case d.Counter == nil:
		return nil, fmt.Errorf("workspace: an organization membership counter is required; " +
			"whether a removal returns a seat is a question about the ORGANIZATION")
	case d.Revoker == nil:
		return nil, fmt.Errorf("workspace: a revoker is required; without one a removed " +
			"member keeps every permission until a projector catches up, and being late to " +
			"revoke is a security failure rather than a delay (access.md §6.1)")
	case d.Now == nil:
		return nil, fmt.Errorf("workspace: a clock is required")
	}
	return &Members{
		workspaces: d.Workspaces, memberships: d.Memberships,
		seats: d.Seats, counter: d.Counter, revoker: d.Revoker, now: d.Now,
	}, nil
}

// Add puts somebody into a workspace, taking a seat only if they are new to the
// organization.
//
// # The order, and why the seat comes first
//
// Reserve, then append. The reverse would record a join that no seat backs, and
// the seat limit would be over by one with an event saying otherwise — the event
// log is the system of record, so a projection built from it would report a
// membership the entitlement store never authorised.
//
// This way round the failure is the harmless one: if the append fails, the seat
// is released here, and if the process dies first the reservation is committed
// with no membership behind it. That is one seat over-counted until an audit,
// which is recoverable and visible; a membership with no seat is neither.
func (m *Members) Add(ctx context.Context, cmd AddMemberCommand) (AddMemberResult, error) {
	if err := cmd.validate(); err != nil {
		return AddMemberResult{}, err
	}
	if err := validRoleOnTheWire(cmd.Role); err != nil {
		return AddMemberResult{}, err
	}

	now := m.now().UTC()
	key := domain.MembershipStreamKey(cmd.WorkspaceID, cmd.SubjectID)

	membership, err := m.memberships.Load(ctx, key)
	if err != nil {
		return AddMemberResult{}, errs.Internalf("loading the membership stream").Wrap(err)
	}
	if membership.Exists() && membership.Active() {
		// Not a conflict to the caller: adding somebody who is already there is
		// the state they asked for. Reporting CONFLICT would make a retried
		// request look like a failure, and the retry is exactly what an
		// Idempotency-Key exists to make safe.
		return AddMemberResult{Role: membership.Role(), SeatConsumed: false}, nil
	}

	// The reservation id is discarded: ReserveForJoin commits before it
	// returns, so there is no held reservation left for this layer to settle.
	_, consumed, err := m.seats.ReserveForJoin(ctx, cmd.OrgID, cmd.SubjectID, cmd.Role)
	if err != nil {
		return AddMemberResult{}, errs.QuotaExceededf("%s", err)
	}

	// The reservation is already COMMITTED by ReserveForJoin — a held one would
	// lapse on its own, and a committed one will not — so undoing it is a
	// release rather than a cancellation. Best effort by necessity: the request
	// is already failing, and there is nowhere left to report a second failure
	// to. What it must not do is nothing at all, which would leave a seat
	// consumed by a membership that does not exist.
	release := func() {
		if consumed {
			_, _ = m.seats.ReleaseOnRemoval(ctx, cmd.OrgID, cmd.SubjectID, cmd.Role, 0)
		}
	}

	if err := membership.Join(
		cmd.WorkspaceID, cmd.OrgID, cmd.SubjectID, cmd.Role, consumed, now,
	); err != nil {
		release()
		return AddMemberResult{}, errs.ValidationFailedf("%s", err)
	}

	if _, err := m.memberships.Save(ctx, key, membership, cmd.IdempotencyKey,
		eventsourcing.Metadata{
			OrgID: cmd.OrgID, WorkspaceID: cmd.WorkspaceID, OccurredAt: now,
		},
	); err != nil {
		release()
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return AddMemberResult{}, errs.Conflictf("this membership changed concurrently")
		}
		return AddMemberResult{}, errs.Internalf("recording the membership").Wrap(err)
	}

	// The admin roster is the workspace's, because never-zero-admins spans the
	// whole set. Appended AFTER the membership: if this fails the person is a
	// member without the admin grant, which under-permits and is visible. The
	// reverse would leave an admin with no membership, which over-permits.
	if cmd.Role == contract.RoleAdmin {
		if err := m.grantAdmin(ctx, cmd.OrgID, cmd.WorkspaceID, cmd.SubjectID, cmd.IdempotencyKey, now); err != nil {
			return AddMemberResult{Role: cmd.Role, SeatConsumed: consumed}, err
		}
	}

	return AddMemberResult{Role: cmd.Role, SeatConsumed: consumed}, nil
}

// Remove takes somebody out, returning a seat only if this was their last
// membership in the organization.
//
// # The admin roster comes first here
//
// The mirror of Add, for the same reason read the other way. Removing the admin
// grant BEFORE the membership means a failure between them leaves somebody who
// is a member and not an admin — under-permitted and visible. Doing it the other
// way would leave an admin grant on a person who is no longer a member, which
// over-permits and is exactly what a removal was meant to stop.
//
// It is also where the never-zero rule bites: the workspace aggregate refuses to
// remove the last admin, and refusing there means the membership is never
// removed either.
func (m *Members) Remove(ctx context.Context, cmd RemoveMemberCommand) (RemoveMemberResult, error) {
	switch {
	case cmd.OrgID == "":
		return RemoveMemberResult{}, errs.Internalf("no organization reached the remove " +
			"handler; gate 1 resolved none")
	case cmd.WorkspaceID == "":
		return RemoveMemberResult{}, errs.ValidationFailedf("a workspace is required")
	case cmd.SubjectID == "":
		return RemoveMemberResult{}, errs.ValidationFailedf("a subject is required")
	case cmd.IdempotencyKey == "":
		return RemoveMemberResult{}, errs.ValidationFailedf(
			"an Idempotency-Key is required on every mutating request")
	}

	now := m.now().UTC()
	key := domain.MembershipStreamKey(cmd.WorkspaceID, cmd.SubjectID)

	membership, err := m.memberships.Load(ctx, key)
	if err != nil {
		return RemoveMemberResult{}, errs.Internalf("loading the membership stream").Wrap(err)
	}
	if !membership.Exists() || !membership.Active() {
		// Already gone. The same reasoning as Add's already-a-member branch: the
		// caller asked for a state that holds.
		return RemoveMemberResult{SeatReleased: false}, nil
	}

	if membership.Role() == contract.RoleAdmin {
		if err := m.revokeAdmin(ctx, cmd.OrgID, cmd.WorkspaceID, cmd.SubjectID,
			cmd.IdempotencyKey, now); err != nil {
			return RemoveMemberResult{}, err
		}
	}

	// AFTER the removal, not before: "how many are left" is a question about the
	// state this command produces. Counting first would include the membership
	// being removed and answer one too high, so the last member of an
	// organization would keep their seat forever.
	//
	// The projection has not caught up at this point, so the count still
	// includes this membership and one is subtracted. That is a deliberate
	// coupling to a read model in a write path, and it is bounded: the number is
	// used to decide a seat release, and both halves of that decision are
	// recorded in the event, so a rebuild never re-derives it.
	total, err := m.counter.WorkspaceCount(ctx, cmd.OrgID, cmd.SubjectID)
	if err != nil {
		return RemoveMemberResult{}, errs.Internalf("counting remaining memberships").Wrap(err)
	}
	remaining := total - 1
	if remaining < 0 {
		remaining = 0
	}

	released, err := m.seats.ReleaseOnRemoval(ctx, cmd.OrgID, cmd.SubjectID, membership.Role(), remaining)
	if err != nil {
		return RemoveMemberResult{}, errs.Internalf("releasing the seat").Wrap(err)
	}

	if err := membership.Remove(released, now); err != nil {
		return RemoveMemberResult{}, errs.ValidationFailedf("%s", err)
	}
	if _, err := m.memberships.Save(ctx, key, membership, cmd.IdempotencyKey,
		eventsourcing.Metadata{
			OrgID: cmd.OrgID, WorkspaceID: cmd.WorkspaceID, OccurredAt: now,
		},
	); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return RemoveMemberResult{}, errs.Conflictf("this membership changed concurrently")
		}
		return RemoveMemberResult{}, errs.Internalf("recording the removal").Wrap(err)
	}

	if err := m.revoke(ctx, cmd.WorkspaceID, cmd.SubjectID, membership.Role()); err != nil {
		return RemoveMemberResult{SeatReleased: released}, err
	}

	return RemoveMemberResult{SeatReleased: released}, nil
}

// revoke lays the tombstones that make a removal take effect NOW.
//
// # Why after the append and not before
//
// Both orderings have a window and they fail differently. Tombstone first means
// a removal that then fails to append leaves the person denied with no event
// that says why — an over-denial produced by a request that did not happen, and
// nothing here can clear it, because clearing is the projector's verb by design
// (ADR-045). Append first means they keep access for as long as this function
// takes, which is one round trip, against the seconds-to-minutes of projector
// lag the tombstone exists to cover.
//
// A failure here is REPORTED rather than swallowed. The removal is already in
// the log and the caller's retry is idempotent, so retrying re-lays the
// tombstone and the state converges; silence would leave the revocation waiting
// on a projector, which is precisely the thing this is for.
//
// # Which relations
//
// The ones the access projector wrote. A guest holds no tuple at all — a guest
// is structurally the absence of the membership edge (access.md §7.6) — so there
// is nothing to deny ahead of, and laying one would be a denial with no grant
// behind it.
func (m *Members) revoke(
	ctx context.Context, workspaceID, subjectID string, role contract.MemberRole,
) error {
	return m.revokeRelations(ctx, workspaceID, subjectID, relationsHeldBy(role))
}

func (m *Members) revokeRelations(
	ctx context.Context, workspaceID, subjectID string, relations []authz.Relation,
) error {
	for _, relation := range relations {
		q := authz.Query{
			Principal: authz.Principal{Kind: authz.KindUser, ID: subjectID},
			Relation:  relation,
			Resource:  authz.ResourceRef{Type: "workspace", ID: workspaceID},
		}
		if err := m.revoker.Revoke(ctx, q); err != nil {
			return errs.Internalf("the membership was removed but the revocation was not " +
				"recorded, so it takes effect only once the projector catches up").Wrap(err)
		}
	}
	return nil
}

// relationsHeldBy names the tuples a role holds in the access graph.
//
// An admin holds both: `admin` is written from the workspace's admin roster, and
// `member` from the membership itself. Denying only `admin` on a removal would
// leave them able to see the workspace they were just removed from.
//
// A guest holds none — structurally the absence of the membership edge
// (access.md §7.6) — so a guest's removal denies nothing, because there was
// never a tuple for a tombstone to shadow.
func relationsHeldBy(role contract.MemberRole) []authz.Relation {
	switch role {
	case contract.RoleAdmin:
		return []authz.Relation{"admin", "member"}
	case contract.RoleMember:
		return []authz.Relation{"member"}
	default:
		return nil
	}
}

// ChangeRole promotes or demotes an existing member.
//
// A change that crosses seat pools takes the new seat before returning the old
// one (ADR-027), so a promotion into a full pool fails visibly rather than
// leaving the person holding neither. That ordering lives in Seats.MovePools;
// what lives here is the admin roster, which has to move in step.
func (m *Members) ChangeRole(ctx context.Context, cmd ChangeRoleCommand) (ChangeRoleResult, error) {
	switch {
	case cmd.OrgID == "":
		return ChangeRoleResult{}, errs.Internalf("no organization reached the role handler; " +
			"gate 1 resolved none")
	case cmd.WorkspaceID == "":
		return ChangeRoleResult{}, errs.ValidationFailedf("a workspace is required")
	case cmd.SubjectID == "":
		return ChangeRoleResult{}, errs.ValidationFailedf("a subject is required")
	case cmd.IdempotencyKey == "":
		return ChangeRoleResult{}, errs.ValidationFailedf(
			"an Idempotency-Key is required on every mutating request")
	}
	if err := validRoleOnTheWire(cmd.Role); err != nil {
		return ChangeRoleResult{}, err
	}

	now := m.now().UTC()
	key := domain.MembershipStreamKey(cmd.WorkspaceID, cmd.SubjectID)

	membership, err := m.memberships.Load(ctx, key)
	if err != nil {
		return ChangeRoleResult{}, errs.Internalf("loading the membership stream").Wrap(err)
	}
	if !membership.Exists() || !membership.Active() {
		return ChangeRoleResult{}, errs.NotFoundf("not found")
	}

	from := membership.Role()
	if from == cmd.Role {
		return ChangeRoleResult{Role: from}, nil
	}

	// Seats before the event, for Add's reason: a recorded role with no seat
	// behind it is a limit that silently does not apply.
	if membership.CrossesPools(cmd.Role) {
		if err := m.seats.MovePools(ctx, cmd.OrgID, cmd.SubjectID, from, cmd.Role); err != nil {
			return ChangeRoleResult{}, errs.QuotaExceededf("%s", err)
		}
	}

	// Demotion out of admin goes through the workspace aggregate first, so the
	// never-zero rule can refuse it. Refusing here means no seat has moved yet
	// on the demotion path — a demotion never crosses pools, since `admin` and
	// `member` draw on the same one.
	if from == contract.RoleAdmin {
		if err := m.revokeAdmin(ctx, cmd.OrgID, cmd.WorkspaceID, cmd.SubjectID,
			cmd.IdempotencyKey, now); err != nil {
			return ChangeRoleResult{}, err
		}
	}

	if err := membership.ChangeRole(cmd.Role, now); err != nil {
		return ChangeRoleResult{}, errs.ValidationFailedf("%s", err)
	}
	if _, err := m.memberships.Save(ctx, key, membership, cmd.IdempotencyKey,
		eventsourcing.Metadata{
			OrgID: cmd.OrgID, WorkspaceID: cmd.WorkspaceID, OccurredAt: now,
		},
	); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return ChangeRoleResult{}, errs.Conflictf("this membership changed concurrently")
		}
		return ChangeRoleResult{}, errs.Internalf("recording the role change").Wrap(err)
	}

	// A DEMOTION is a revocation and gets the same treatment as a removal: the
	// permission has to stop working now, not once a projector notices. Only the
	// relations the new role does not still hold are denied — demoting an admin
	// to a member takes `admin` and leaves `member`, so denying both would lock
	// them out of a workspace they are still in.
	if lost := lostRelations(from, cmd.Role); len(lost) > 0 {
		if err := m.revokeRelations(ctx, cmd.WorkspaceID, cmd.SubjectID, lost); err != nil {
			return ChangeRoleResult{Role: cmd.Role}, err
		}
	}

	if cmd.Role == contract.RoleAdmin {
		if err := m.grantAdmin(ctx, cmd.OrgID, cmd.WorkspaceID, cmd.SubjectID,
			cmd.IdempotencyKey, now); err != nil {
			return ChangeRoleResult{Role: cmd.Role}, err
		}
	}

	return ChangeRoleResult{Role: cmd.Role}, nil
}

// grantAdmin adds somebody to the workspace's admin roster.
func (m *Members) grantAdmin(
	ctx context.Context, orgID, workspaceID, subjectID, key string, now time.Time,
) error {
	ws, err := m.workspaces.Load(ctx, domain.StreamKey(workspaceID))
	if err != nil {
		return errs.Internalf("loading the workspace").Wrap(err)
	}
	if err := ws.AddAdmin(subjectID, now); err != nil {
		return errs.ValidationFailedf("%s", err)
	}
	// A DERIVED key, because the membership append already claimed the caller's
	// one. Reusing it would make the second append look like a replay of the
	// first and be refused, so a join that grants admin would record the
	// membership and silently never grant anything.
	if _, err := m.workspaces.Save(ctx, domain.StreamKey(workspaceID), ws, key+":admin",
		eventsourcing.Metadata{OrgID: orgID, WorkspaceID: workspaceID, OccurredAt: now},
	); err != nil {
		return errs.Internalf("granting workspace admin").Wrap(err)
	}
	return nil
}

// revokeAdmin removes somebody from the workspace's admin roster.
func (m *Members) revokeAdmin(
	ctx context.Context, orgID, workspaceID, subjectID, key string, now time.Time,
) error {
	ws, err := m.workspaces.Load(ctx, domain.StreamKey(workspaceID))
	if err != nil {
		return errs.Internalf("loading the workspace").Wrap(err)
	}
	if err := ws.RemoveAdmin(subjectID, now); err != nil {
		// The never-zero rule. CONFLICT and not VALIDATION_FAILED: the request
		// is well formed and the caller is permitted, and it is the current
		// state that says no.
		return errs.Conflictf("%s", err)
	}
	if _, err := m.workspaces.Save(ctx, domain.StreamKey(workspaceID), ws, key+":unadmin",
		eventsourcing.Metadata{OrgID: orgID, WorkspaceID: workspaceID, OccurredAt: now},
	); err != nil {
		return errs.Internalf("revoking workspace admin").Wrap(err)
	}
	return nil
}

func (c AddMemberCommand) validate() error {
	switch {
	case c.OrgID == "":
		return errs.Internalf("no organization reached the add-member handler; gate 1 " +
			"resolved none")
	case c.WorkspaceID == "":
		return errs.ValidationFailedf("a workspace is required")
	case c.SubjectID == "":
		return errs.ValidationFailedf("a subject is required")
	case c.IdempotencyKey == "":
		return errs.ValidationFailedf(
			"an Idempotency-Key is required on every mutating request")
	}
	return nil
}

// validRoleOnTheWire refuses a role the schema should already have refused.
//
// protovalidate bounds the field to the three names, so reaching here with
// anything else means the RPC was called another way. The aggregate refuses it
// too; this is the layer that turns the refusal into INVALID_ARGUMENT rather
// than letting a seat be reserved against a pool named by an unknown role.
func validRoleOnTheWire(r contract.MemberRole) error {
	switch r {
	case contract.RoleAdmin, contract.RoleMember, contract.RoleGuest:
		return nil
	default:
		return errs.ValidationFailedf("%q is not a role", string(r))
	}
}

// lostRelations is what a role change takes away.
//
// Set subtraction rather than a table of cases, because the table is the part
// that goes wrong: every new role would need a row for every other role, and the
// row nobody added is a permission that quietly survives its own revocation.
func lostRelations(from, to contract.MemberRole) []authz.Relation {
	kept := map[authz.Relation]bool{}
	for _, r := range relationsHeldBy(to) {
		kept[r] = true
	}
	var lost []authz.Relation
	for _, r := range relationsHeldBy(from) {
		if !kept[r] {
			lost = append(lost, r)
		}
	}
	return lost
}
