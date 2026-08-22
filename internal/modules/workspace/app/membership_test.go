package app_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

const (
	testOrg = "org_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	founder = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAA"
	joiner  = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAB"
)

// ---------------------------------------------------------------------------
// the smallest event store that can hold two aggregates
// ---------------------------------------------------------------------------

type memStore struct {
	streams map[eventsourcing.StreamID][]eventsourcing.RecordedEvent
}

func newMemStore() *memStore {
	return &memStore{streams: map[eventsourcing.StreamID][]eventsourcing.RecordedEvent{}}
}

func (m *memStore) Append(
	_ context.Context, stream eventsourcing.StreamID,
	expected eventsourcing.ExpectedRevision, events []eventsourcing.PendingEvent,
) (eventsourcing.AppendResult, error) {
	existing := m.streams[stream]
	if rev, ok := expected.Exact(); ok && rev != eventsourcing.Revision(len(existing))-1 {
		return eventsourcing.AppendResult{}, eventsourcing.ErrWrongExpectedRevision
	}
	for _, pe := range events {
		payload, err := codec.Marshal(pe.Event)
		if err != nil {
			return eventsourcing.AppendResult{}, err
		}
		existing = append(existing, eventsourcing.RecordedEvent{
			ID: pe.ID, Type: pe.Event.EventType(), Stream: stream,
			Revision: eventsourcing.Revision(len(existing)), Payload: payload,
		})
	}
	m.streams[stream] = existing
	return eventsourcing.AppendResult{Revision: eventsourcing.Revision(len(existing) - 1)}, nil
}

func (m *memStore) ReadStream(
	_ context.Context, stream eventsourcing.StreamID, from eventsourcing.Revision,
) ([]eventsourcing.RecordedEvent, error) {
	all, ok := m.streams[stream]
	if !ok {
		return nil, eventsourcing.ErrStreamNotFound
	}
	if int(from) >= len(all) {
		return nil, nil
	}
	return all[from:], nil
}

// AppendToMany is the atomic multi-stream append the creation path needs.
//
// Every precondition is checked BEFORE anything is written, which is the whole
// property: a workspace must never exist without the membership appended beside
// it.
func (m *memStore) AppendToMany(
	ctx context.Context, appends []eventsourcing.StreamAppend,
) ([]eventsourcing.AppendResult, error) {
	for _, a := range appends {
		existing := m.streams[a.Stream]
		if rev, ok := a.Expected.Exact(); ok && rev != eventsourcing.Revision(len(existing))-1 {
			return nil, eventsourcing.ErrWrongExpectedRevision
		}
		if a.Expected.IsNoStream() && len(existing) > 0 {
			return nil, eventsourcing.ErrWrongExpectedRevision
		}
	}
	out := make([]eventsourcing.AppendResult, 0, len(appends))
	for _, a := range appends {
		res, err := m.Append(ctx, a.Stream, eventsourcing.AnyRevision(), a.Events)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// noSchemas reports no version for anything, which StampSchemaVersion treats as
// "leave it alone". The registry is asserted elsewhere; this file is about
// membership.
type noSchemas struct{}

func (noSchemas) CurrentVersion(string) (int, bool) { return 0, false }

// fakeQuota accepts every commit. Gate 4's reservation is proved by the
// integration suite; here it only has to not be nil.
type fakeQuota struct{ commits int }

func (f *fakeQuota) Commit(context.Context, string) error { f.commits++; return nil }

// jsonCodec decodes by event type, which is all a repository replay needs.
type jsonCodec struct{}

func (jsonCodec) Marshal(e eventsourcing.Event) ([]byte, error) { return codec.Marshal(e) }

func (jsonCodec) Unmarshal(eventType string, payload []byte) (eventsourcing.Event, error) {
	// Tolerant, like the real codec: an event read back from the log may carry
	// members this build does not know (ADR-047).
	switch eventType {
	case (&contract.WorkspaceCreated{}).EventType():
		return decode[contract.WorkspaceCreated](payload)
	case (&contract.WorkspaceRenamed{}).EventType():
		return decode[contract.WorkspaceRenamed](payload)
	case (&contract.WorkspaceArchived{}).EventType():
		return decode[contract.WorkspaceArchived](payload)
	case (&contract.WorkspaceRestored{}).EventType():
		return decode[contract.WorkspaceRestored](payload)
	case (&contract.WorkspaceAdminAdded{}).EventType():
		return decode[contract.WorkspaceAdminAdded](payload)
	case (&contract.WorkspaceAdminRemoved{}).EventType():
		return decode[contract.WorkspaceAdminRemoved](payload)
	case (&contract.MemberJoined{}).EventType():
		return decode[contract.MemberJoined](payload)
	case (&contract.MemberRoleChanged{}).EventType():
		return decode[contract.MemberRoleChanged](payload)
	case (&contract.MemberRemoved{}).EventType():
		return decode[contract.MemberRemoved](payload)
	case (&contract.InvitationIssued{}).EventType():
		return decode[contract.InvitationIssued](payload)
	case (&contract.InvitationTokenRotated{}).EventType():
		return decode[contract.InvitationTokenRotated](payload)
	case (&contract.InvitationAccepted{}).EventType():
		return decode[contract.InvitationAccepted](payload)
	case (&contract.InvitationRevoked{}).EventType():
		return decode[contract.InvitationRevoked](payload)
	case (&contract.InvitationDeclined{}).EventType():
		return decode[contract.InvitationDeclined](payload)
	case (&contract.InvitationExpired{}).EventType():
		return decode[contract.InvitationExpired](payload)
	case (&contract.InvitationUndeliverable{}).EventType():
		return decode[contract.InvitationUndeliverable](payload)
	case (&contract.TeamCreated{}).EventType():
		return decode[contract.TeamCreated](payload)
	case (&contract.TeamRenamed{}).EventType():
		return decode[contract.TeamRenamed](payload)
	case (&contract.TeamMaintainerAdded{}).EventType():
		return decode[contract.TeamMaintainerAdded](payload)
	case (&contract.TeamMaintainerRemoved{}).EventType():
		return decode[contract.TeamMaintainerRemoved](payload)
	case (&contract.TeamDeleted{}).EventType():
		return decode[contract.TeamDeleted](payload)
	case (&contract.TeamMemberAdded{}).EventType():
		return decode[contract.TeamMemberAdded](payload)
	case (&contract.TeamMemberRemoved{}).EventType():
		return decode[contract.TeamMemberRemoved](payload)
	default:
		// A HARD ERROR, matching the real codec. Returning (nil, nil) makes an
		// unregistered type replay as though it never happened — which is how an
		// archived workspace rebuilt as active, and the test that should have
		// caught it passed instead.
		return nil, fmt.Errorf("test codec: %q is not registered", eventType)
	}
}

func decode[T any, P interface {
	*T
	eventsourcing.Event
}](payload []byte) (eventsourcing.Event, error) {
	v, err := codec.Tolerant[T](payload)
	if err != nil {
		return nil, err
	}
	return P(&v), nil
}

func (jsonCodec) MarshalMetadata(eventsourcing.Metadata) ([]byte, error) { return nil, nil }

func (jsonCodec) UnmarshalMetadata([]byte) (eventsourcing.Metadata, error) {
	return eventsourcing.Metadata{}, nil
}

// ---------------------------------------------------------------------------
// fakes
// ---------------------------------------------------------------------------

// fakeRevoker records the tombstones a command laid.
type fakeRevoker struct {
	laid []authz.Query
	err  error
}

func (f *fakeRevoker) Revoke(_ context.Context, q authz.Query) error {
	if f.err != nil {
		return f.err
	}
	f.laid = append(f.laid, q)
	return nil
}

// countingMembers is fakeMembers with a mutable count, so a test can model the
// person's memberships changing between calls.
type countingMembers struct{ n int }

func (c *countingMembers) WorkspaceCount(context.Context, string, string) (int, error) {
	return c.n, nil
}

type harness struct {
	members     *app.Members
	revoker     *fakeRevoker
	reserver    *fakeReserver
	counter     *countingMembers
	store       *memStore
	workspaceID string

	// baseSeats is what creating the workspace already reserved. The creator is
	// a member and takes a seat like anybody else, so every assertion below is
	// about the DELTA — an absolute count would silently be measuring the
	// founder.
	baseSeats int
}

// seatsSince is what has been reserved since the workspace was created.
func (h *harness) seatsSince() []string { return h.reserver.reserved[h.baseSeats:] }

// newHarness builds the use case over a real repository and a live workspace.
//
// The workspace is created through its own aggregate rather than by writing a
// row, because the admin roster this test is about is rebuilt from the log: a
// fabricated starting state would test a shape the system never produces.
func newHarness(t *testing.T, existingMemberships int) *harness {
	t.Helper()
	store := newMemStore()
	now := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

	workspaces := eventsourcing.NewRepository[*domain.Workspace](
		store, jsonCodec{}, nil, domain.Category, domain.NewWorkspace)
	memberships := eventsourcing.NewRepository[*domain.Membership](
		store, jsonCodec{}, nil, domain.MembershipCategory, domain.NewMembership)

	reserver := newFakeReserver()
	counter := &countingMembers{n: existingMemberships}
	seats, err := app.NewSeats(app.SeatsDeps{Reserver: reserver, Members: counter})
	if err != nil {
		t.Fatal(err)
	}
	revoker := &fakeRevoker{}

	// The workspace is opened through the REAL use case, not by writing its
	// events. The creator's membership is appended atomically there, and a
	// fabricated starting state would skip exactly the thing under test — which
	// is how the creator came to have no membership aggregate in the first place.
	creation, err := app.NewCreation(app.CreationDeps{
		Repo: workspaces, Appender: store, Schemas: noSchemas{},
		Quota: &fakeQuota{}, Seats: seats, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := creation.Create(context.Background(), app.CreateCommand{
		OrgID: testOrg, Name: "Engineering", CreatedBy: founder,
		ReservationID: "res_workspaces", IdempotencyKey: "key-create",
	})
	if err != nil {
		t.Fatalf("creating the workspace: %v", err)
	}
	workspaceID := created.WorkspaceID

	members, err := app.NewMembers(app.MembersDeps{
		Workspaces: workspaces, Memberships: memberships,
		Seats: seats, Counter: counter, Revoker: revoker, Now: now,
	})
	if err != nil {
		t.Fatalf("NewMembers: %v", err)
	}
	return &harness{
		members: members, revoker: revoker, reserver: reserver,
		counter: counter, store: store, workspaceID: workspaceID,
		baseSeats: len(reserver.reserved),
	}
}

func (h *harness) add(t *testing.T, subject string, role contract.MemberRole) app.AddMemberResult {
	t.Helper()
	res, err := h.members.Add(context.Background(), app.AddMemberCommand{
		OrgID: testOrg, WorkspaceID: h.workspaceID, SubjectID: subject, Role: role,
		IdempotencyKey: "key-add-" + subject,
	})
	if err != nil {
		t.Fatalf("adding %s as %s: %v", subject, role, err)
	}
	return res
}

// ---------------------------------------------------------------------------
// the assertions
// ---------------------------------------------------------------------------

// A REMOVAL LAYS A TOMBSTONE, so the revocation takes effect before the
// projector has seen it.
//
// This is the half of ADR-045 that had no caller at all until now. The
// tombstone machinery was complete — the Guard consults them, the confirming
// writer clears them — and nothing in the system ever laid one, so every
// revocation waited on projector lag.
//
// Being late to GRANT costs somebody a moment of not seeing their own new
// access. Being late to REVOKE is a security failure (access.md §6.1), and it is
// invisible: the removal succeeds, the event is in the log, the API returns 200,
// and the person keeps working.
func TestARemovalRevokesImmediately(t *testing.T) {
	h := newHarness(t, 1)
	h.add(t, joiner, contract.RoleMember)
	h.counter.n = 2 // the founder and the joiner

	if _, err := h.members.Remove(context.Background(), app.RemoveMemberCommand{
		OrgID: testOrg, WorkspaceID: h.workspaceID, SubjectID: joiner,
		IdempotencyKey: "key-remove",
	}); err != nil {
		t.Fatalf("removing: %v", err)
	}

	if len(h.revoker.laid) == 0 {
		t.Fatal("no tombstone was laid, so the removed member keeps every permission until " +
			"a projector catches up — and nothing reports that they still have it")
	}
	q := h.revoker.laid[0]
	if q.Relation != "member" {
		t.Errorf("revoked %q, want the membership relation", q.Relation)
	}
	if q.Principal.ID != joiner {
		t.Errorf("revoked %s, want %s — a tombstone on the wrong subject denies an "+
			"innocent person and leaves the removed one working", q.Principal.ID, joiner)
	}
	if q.Resource.Type != "workspace" || q.Resource.ID != h.workspaceID {
		t.Errorf("revoked on %s:%s, want workspace:%s", q.Resource.Type, q.Resource.ID, h.workspaceID)
	}
}

// An ADMIN's removal denies BOTH edges.
//
// An admin holds `admin` from the workspace's roster and `member` from the
// membership. Denying only `admin` leaves them able to see the workspace they
// were just removed from — which is the exact shape of a revocation that looks
// like it worked.
func TestRemovingAnAdminRevokesBothEdges(t *testing.T) {
	h := newHarness(t, 1)
	h.add(t, joiner, contract.RoleAdmin)
	h.counter.n = 2

	if _, err := h.members.Remove(context.Background(), app.RemoveMemberCommand{
		OrgID: testOrg, WorkspaceID: h.workspaceID, SubjectID: joiner,
		IdempotencyKey: "key-remove-admin",
	}); err != nil {
		t.Fatalf("removing an admin: %v", err)
	}

	got := map[authz.Relation]bool{}
	for _, q := range h.revoker.laid {
		got[q.Relation] = true
	}
	if !got["admin"] || !got["member"] {
		t.Fatalf("laid %v; an admin holds both edges, and denying only one leaves them "+
			"able to see the workspace they were removed from", h.revoker.laid)
	}
}

// A GUEST's removal denies nothing, because a guest held no tuple.
//
// The mirror of the rule above, and it fails the other way: a tombstone with no
// tuple behind it is a denial that can only be cleared by a confirmation the
// projector will never send, because there is nothing for it to delete. It would
// then sit until its TTL — and reaching the TTL is supposed to be an alert.
func TestRemovingAGuestLaysNoTombstone(t *testing.T) {
	h := newHarness(t, 1)
	h.add(t, joiner, contract.RoleGuest)
	h.counter.n = 2

	if _, err := h.members.Remove(context.Background(), app.RemoveMemberCommand{
		OrgID: testOrg, WorkspaceID: h.workspaceID, SubjectID: joiner,
		IdempotencyKey: "key-remove-guest",
	}); err != nil {
		t.Fatalf("removing a guest: %v", err)
	}

	if len(h.revoker.laid) != 0 {
		t.Fatalf("laid %v for a guest, who is structurally the ABSENCE of the membership "+
			"edge (access.md §7.6); the projector has nothing to delete, so nothing will "+
			"ever confirm it and it survives to its TTL", h.revoker.laid)
	}
}

// A DEMOTION denies only what it takes away.
//
// Demoting an admin to a member removes `admin` and keeps `member`. Denying both
// would lock them out of a workspace they are still in — a revocation that
// over-fires, which is as wrong as one that under-fires and much harder to
// explain.
func TestADemotionRevokesOnlyWhatItTakes(t *testing.T) {
	h := newHarness(t, 1)
	h.add(t, joiner, contract.RoleAdmin)

	if _, err := h.members.ChangeRole(context.Background(), app.ChangeRoleCommand{
		OrgID: testOrg, WorkspaceID: h.workspaceID, SubjectID: joiner,
		Role: contract.RoleMember, IdempotencyKey: "key-demote",
	}); err != nil {
		t.Fatalf("demoting: %v", err)
	}

	if len(h.revoker.laid) != 1 {
		t.Fatalf("laid %v, want exactly the admin edge", h.revoker.laid)
	}
	if h.revoker.laid[0].Relation != "admin" {
		t.Fatalf("revoked %q; they are still a member, so denying `member` locks them out "+
			"of a workspace they are still in", h.revoker.laid[0].Relation)
	}
}

// A PROMOTION revokes nothing.
func TestAPromotionRevokesNothing(t *testing.T) {
	h := newHarness(t, 1)
	h.add(t, joiner, contract.RoleMember)

	if _, err := h.members.ChangeRole(context.Background(), app.ChangeRoleCommand{
		OrgID: testOrg, WorkspaceID: h.workspaceID, SubjectID: joiner,
		Role: contract.RoleAdmin, IdempotencyKey: "key-promote",
	}); err != nil {
		t.Fatalf("promoting: %v", err)
	}
	if len(h.revoker.laid) != 0 {
		t.Fatalf("a promotion laid %v; it grants, and denying anything here would take "+
			"away access the person still has", h.revoker.laid)
	}
}

// THE LAST ADMIN CANNOT BE REMOVED.
//
// A workspace with no admin is unadministrable, and no event from outside can
// fix it: there is nobody left who may add one. The aggregate refuses, and
// because the roster is touched BEFORE the membership, refusing there means the
// membership is never removed either.
func TestTheLastAdminCannotLeave(t *testing.T) {
	h := newHarness(t, 1)

	_, err := h.members.Remove(context.Background(), app.RemoveMemberCommand{
		OrgID: testOrg, WorkspaceID: h.workspaceID, SubjectID: founder,
		IdempotencyKey: "key-last-admin",
	})
	if err == nil {
		t.Fatal("the last admin was removed; the workspace now has nobody who may add one, " +
			"and no request from outside can repair it")
	}
	if got := errs.ReasonOf(err); got != errs.Conflict {
		t.Errorf("refused with %s, want CONFLICT: the request is well formed and the "+
			"caller is permitted, and it is the current state that says no", got)
	}
	if len(h.revoker.laid) != 0 {
		t.Errorf("laid %v for a removal that was refused; the person is still an admin and "+
			"is now denied", h.revoker.laid)
	}
}

// A SECOND ADMIN MAKES THE FIRST REMOVABLE, which is what proves the rule above
// refuses for the right reason rather than refusing every removal.
func TestAnAdminCanLeaveOnceThereIsAnother(t *testing.T) {
	h := newHarness(t, 1)
	h.add(t, joiner, contract.RoleAdmin)
	h.counter.n = 2

	if _, err := h.members.Remove(context.Background(), app.RemoveMemberCommand{
		OrgID: testOrg, WorkspaceID: h.workspaceID, SubjectID: founder,
		IdempotencyKey: "key-founder-leaves",
	}); err != nil {
		t.Fatalf("an admin could not leave a workspace with two: %v", err)
	}
}

// A SEAT IS PER PERSON PER ORGANIZATION, through the RPC and not just through
// Seats.
//
// seats_test proves the rule in isolation. This proves the use case actually
// asks: a Members that never called ReserveForJoin would pass every assertion in
// that file and charge nothing for anybody.
func TestJoiningConsumesASeatOnlyWhenNewToTheOrganization(t *testing.T) {
	t.Run("somebody new takes a seat", func(t *testing.T) {
		h := newHarness(t, 0)
		res := h.add(t, joiner, contract.RoleMember)
		if !res.SeatConsumed {
			t.Fatal("no seat was taken for somebody new to the organization, so the plan's " +
				"seat limit never binds and the customer is under-charged")
		}
		if got := h.seatsSince(); len(got) != 1 || got[0] != "seats.member" {
			t.Fatalf("reserved %v, want one member seat", got)
		}
	})

	t.Run("their second workspace is free", func(t *testing.T) {
		h := newHarness(t, 3) // already in three workspaces of this organization
		res := h.add(t, joiner, contract.RoleMember)
		if res.SeatConsumed {
			t.Fatal("a seat was taken for somebody already in the organization; five " +
				"workspaces would cost five seats and over-charge the customer 5x " +
				"(workspace.md §2)")
		}
		if got := h.seatsSince(); len(got) != 0 {
			t.Fatalf("reserved %v for a person who already holds a seat", got)
		}
	})
}

// A SEAT COMES BACK ONLY WHEN THE PERSON LEAVES THE ORGANIZATION.
//
// The half of the rule that leaks revenue if inverted: releasing on every
// removal hands back a seat the person still holds, and the pool then grows by
// one for every workspace they were ever in.
func TestARemovalReleasesASeatOnlyOnTheLastMembership(t *testing.T) {
	t.Run("still in another workspace keeps the seat", func(t *testing.T) {
		h := newHarness(t, 1)
		h.add(t, joiner, contract.RoleMember)
		h.counter.n = 2 // this workspace plus one more

		res, err := h.members.Remove(context.Background(), app.RemoveMemberCommand{
			OrgID: testOrg, WorkspaceID: h.workspaceID, SubjectID: joiner,
			IdempotencyKey: "key-r1",
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.SeatReleased {
			t.Fatal("a seat was returned for somebody still in another workspace of the " +
				"same organization; they still hold it, and the pool has just grown by one")
		}
	})

	t.Run("the last one returns it", func(t *testing.T) {
		h := newHarness(t, 0)
		h.add(t, joiner, contract.RoleMember)
		h.counter.n = 1 // only this one

		res, err := h.members.Remove(context.Background(), app.RemoveMemberCommand{
			OrgID: testOrg, WorkspaceID: h.workspaceID, SubjectID: joiner,
			IdempotencyKey: "key-r2",
		})
		if err != nil {
			t.Fatal(err)
		}
		if !res.SeatReleased {
			t.Fatal("the seat was not returned when the person left the organization " +
				"entirely, so it is consumed forever by somebody who is gone")
		}
	})
}

// ADDING SOMEBODY TWICE IS NOT A FAILURE, and takes no second seat.
//
// The retry an Idempotency-Key exists to make safe. A version that refused would
// turn every retried request into an error the caller cannot distinguish from a
// real one.
func TestAddingAnExistingMemberIsANoOp(t *testing.T) {
	h := newHarness(t, 0)
	first := h.add(t, joiner, contract.RoleMember)
	if !first.SeatConsumed {
		t.Fatal("precondition: the first join took no seat, so the second proves nothing")
	}

	second, err := h.members.Add(context.Background(), app.AddMemberCommand{
		OrgID: testOrg, WorkspaceID: h.workspaceID, SubjectID: joiner,
		Role: contract.RoleMember, IdempotencyKey: "key-add-again",
	})
	if err != nil {
		t.Fatalf("re-adding an existing member failed: %v", err)
	}
	if second.SeatConsumed {
		t.Error("the second add took another seat")
	}
	if got := h.seatsSince(); len(got) != 1 {
		t.Errorf("reserved %v across two adds of one person", got)
	}
}

// A FAILED TOMBSTONE IS REPORTED, never swallowed.
//
// The removal is already in the log by then, so silence would leave the caller
// believing the revocation is immediate when it is waiting on a projector.
// Reporting it makes the caller retry, and the retry is idempotent.
func TestAFailedRevocationIsReported(t *testing.T) {
	h := newHarness(t, 1)
	h.add(t, joiner, contract.RoleMember)
	h.counter.n = 2
	h.revoker.err = errUnavailable{}

	_, err := h.members.Remove(context.Background(), app.RemoveMemberCommand{
		OrgID: testOrg, WorkspaceID: h.workspaceID, SubjectID: joiner,
		IdempotencyKey: "key-revoke-fails",
	})
	if err == nil {
		t.Fatal("a tombstone that could not be laid was reported as success; the caller " +
			"believes the revocation is immediate when it is waiting on a projector")
	}
	if !strings.Contains(err.Error(), "projector") {
		t.Errorf("the error does not say what actually happened: %v", err)
	}
}

type errUnavailable struct{}

func (errUnavailable) Error() string { return "valkey: unreachable" }

// EVERY DEPENDENCY IS REQUIRED, and the revoker most of all.
//
// Optional would mean a deployment could lose immediate revocation silently, and
// discover it only as a removed member who kept working.
func TestMembersRefusesAnIncompleteWiring(t *testing.T) {
	store := newMemStore()
	workspaces := eventsourcing.NewRepository[*domain.Workspace](
		store, jsonCodec{}, nil, domain.Category, domain.NewWorkspace)
	memberships := eventsourcing.NewRepository[*domain.Membership](
		store, jsonCodec{}, nil, domain.MembershipCategory, domain.NewMembership)
	counter := &countingMembers{}
	seats, err := app.NewSeats(app.SeatsDeps{Reserver: newFakeReserver(), Members: counter})
	if err != nil {
		t.Fatal(err)
	}
	full := app.MembersDeps{
		Workspaces: workspaces, Memberships: memberships, Seats: seats,
		Counter: counter, Revoker: &fakeRevoker{}, Now: time.Now,
	}
	if _, err := app.NewMembers(full); err != nil {
		t.Fatalf("precondition: a complete wiring was refused, so every case below would "+
			"pass for the wrong reason: %v", err)
	}

	tests := []struct {
		name string
		mut  func(*app.MembersDeps)
		want string
	}{
		{"no workspaces", func(d *app.MembersDeps) { d.Workspaces = nil }, "workspace repository"},
		{"no memberships", func(d *app.MembersDeps) { d.Memberships = nil }, "membership repository"},
		{"no seats", func(d *app.MembersDeps) { d.Seats = nil }, "seat accounting"},
		{"no counter", func(d *app.MembersDeps) { d.Counter = nil }, "counter"},
		{"no revoker", func(d *app.MembersDeps) { d.Revoker = nil }, "revoker"},
		{"no clock", func(d *app.MembersDeps) { d.Now = nil }, "clock"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := full
			tt.mut(&d)
			_, err := app.NewMembers(d)
			if err == nil {
				t.Fatalf("constructed with %s; the failure would surface at request time "+
					"as a nil dereference or as a rule that silently does not apply", tt.name)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("refused for the wrong reason: %v", err)
			}
		})
	}
}

// THE CREATOR IS A MEMBER, in the membership stream and not only in
// `WorkspaceCreated`.
//
// This is the hole the member RPCs uncovered. `WorkspaceCreated` named the first
// admin and nothing carried that into the membership category, so the creator
// had no Membership aggregate — and every operation that reads one silently did
// the wrong thing:
//
//   - removing them was a no-op that returned 200
//   - changing their role was NOT_FOUND
//   - their membership consumed no seat, so the first member of every
//     workspace was free
//
// None of those produce an error, a log line or a failing check. The first two
// look like the request worked; the third looks like the plan is generous.
func TestTheCreatorIsARealMember(t *testing.T) {
	h := newHarness(t, 0)

	memberships := eventsourcing.NewRepository[*domain.Membership](
		h.store, jsonCodec{}, nil, domain.MembershipCategory, domain.NewMembership)

	m, err := memberships.Load(context.Background(),
		domain.MembershipStreamKey(h.workspaceID, founder))
	if err != nil {
		t.Fatal(err)
	}
	if !m.Exists() || !m.Active() {
		t.Fatal("the creator has no membership aggregate: removing them is a no-op that " +
			"reports success, changing their role is NOT_FOUND, and their seat was free")
	}
	if m.Role() != contract.RoleAdmin {
		t.Errorf("the creator joined as %q, want admin", m.Role())
	}
	if !m.SeatConsumed() {
		t.Error("the creator's membership took no seat, so the first member of every " +
			"workspace is free and the plan's seat limit is off by one per workspace")
	}
}

// THE WORKSPACE AND THE MEMBERSHIP ARE ONE APPEND.
//
// Two appends would make the failure worse than the bug they fix: a workspace
// that exists with no membership behind it, which nothing retries and nothing
// detects. The precondition is `NoStream` on both, so a redelivered creation is
// refused rather than producing a second membership.
func TestCreatingAWorkspaceIsAtomic(t *testing.T) {
	h := newHarness(t, 0)

	var wsStreams, memberStreams int
	for stream := range h.store.streams {
		switch {
		case strings.HasPrefix(string(stream), string(domain.Category)+"-"):
			wsStreams++
		case strings.HasPrefix(string(stream), string(domain.MembershipCategory)+"-"):
			memberStreams++
		}
	}
	if wsStreams != 1 || memberStreams != 1 {
		t.Fatalf("one creation produced %d workspace streams and %d membership streams; "+
			"they are meant to be one atomic append", wsStreams, memberStreams)
	}
}

// THE CREATOR CAN BE REMOVED once somebody else administers the workspace.
//
// The end-to-end consequence of the two above, and the assertion that would have
// caught the hole from the outside: before the creator had a membership, this
// call returned success and changed nothing at all.
func TestTheCreatorCanActuallyBeRemoved(t *testing.T) {
	h := newHarness(t, 1)
	h.add(t, joiner, contract.RoleAdmin)
	h.counter.n = 2

	if _, err := h.members.Remove(context.Background(), app.RemoveMemberCommand{
		OrgID: testOrg, WorkspaceID: h.workspaceID, SubjectID: founder,
		IdempotencyKey: "key-remove-creator",
	}); err != nil {
		t.Fatalf("removing the creator: %v", err)
	}

	memberships := eventsourcing.NewRepository[*domain.Membership](
		h.store, jsonCodec{}, nil, domain.MembershipCategory, domain.NewMembership)
	m, err := memberships.Load(context.Background(),
		domain.MembershipStreamKey(h.workspaceID, founder))
	if err != nil {
		t.Fatal(err)
	}
	if m.Active() {
		t.Fatal("the creator is still an active member after being removed; the call " +
			"reported success and changed nothing")
	}
	if len(h.revoker.laid) == 0 {
		t.Error("no tombstone was laid for the removed creator")
	}
}
