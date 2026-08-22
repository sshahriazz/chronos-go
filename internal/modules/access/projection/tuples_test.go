package projection

import (
	"context"
	"testing"
	"time"

	workspacecontract "github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// recordingWriter captures what would reach OpenFGA.
type recordingWriter struct {
	written []authz.Tuple
	deleted []authz.Tuple
}

func (w *recordingWriter) Write(_ context.Context, ts []authz.Tuple) error {
	w.written = append(w.written, ts...)
	return nil
}

func (w *recordingWriter) Delete(_ context.Context, ts []authz.Tuple) error {
	w.deleted = append(w.deleted, ts...)
	return nil
}

// oneEventCodec decodes the single event under test, so each assertion is about
// the projector's dispatch and not about registration.
//
// Tolerant, like the real codec on this path: an event read from the log may
// carry members this build does not know (ADR-047).
type oneEventCodec struct {
	decode func([]byte) (eventsourcing.Event, error)
}

func decoder[T any, P interface {
	*T
	eventsourcing.Event
}]() func([]byte) (eventsourcing.Event, error) {
	return func(payload []byte) (eventsourcing.Event, error) {
		v, err := codec.Tolerant[T](payload)
		if err != nil {
			return nil, err
		}
		return P(&v), nil
	}
}

func (c oneEventCodec) Unmarshal(_ string, payload []byte) (eventsourcing.Event, error) {
	return c.decode(payload)
}

func (c oneEventCodec) Marshal(eventsourcing.Event) ([]byte, error) { return nil, nil }

func (c oneEventCodec) MarshalMetadata(eventsourcing.Metadata) ([]byte, error) { return nil, nil }

func (c oneEventCodec) UnmarshalMetadata([]byte) (eventsourcing.Metadata, error) {
	return eventsourcing.Metadata{}, nil
}

const (
	wsID   = "ws_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	subjID = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV"
)

func react(t *testing.T, e eventsourcing.Event, decode func([]byte) (eventsourcing.Event, error)) *recordingWriter {
	t.Helper()
	payload, err := codec.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	w := &recordingWriter{}
	tuples, err := NewTuples(w, oneEventCodec{decode: decode})
	if err != nil {
		t.Fatal(err)
	}
	if err := tuples.React(context.Background(), eventsourcing.Envelope{
		Type: e.EventType(), Payload: payload,
	}); err != nil {
		t.Fatalf("reacting to %s: %v", e.EventType(), err)
	}
	return w
}

func memberTuple(relation authz.Relation) authz.Tuple {
	return authz.Tuple{
		Subject:  authz.Subject{Principal: authz.Principal{Kind: authz.KindUser, ID: subjID}},
		Relation: relation,
		Resource: authz.ResourceRef{Type: "workspace", ID: wsID},
	}
}

// A join GRANTS, and its absence is completely silent.
//
// This is the failure mode the module's own docs name: nothing is granted, gate
// 2 asks OpenFGA, OpenFGA answers from a graph with no membership edge, and
// every request is DENIED — which is the correct direction to fail and therefore
// produces no error, no parked event and no log line. A member simply cannot see
// the workspace they were added to.
//
// It was unreachable until this commit for a reason worth recording: the
// subscription filter named `workspace-` and `organization-` only, and
// memberships live in their own stream category, so every one of these events
// was filtered out before React ever saw it.
func TestAJoinGrantsMembership(t *testing.T) {
	tests := []struct {
		name  string
		role  workspacecontract.MemberRole
		grant bool
		why   string
	}{
		{
			name: "a member gets the membership edge", role: workspacecontract.RoleMember,
			grant: true,
			why:   "without it they cannot see the workspace they were just added to",
		},
		{
			name: "an admin gets it too", role: workspacecontract.RoleAdmin,
			grant: true,
			why: "the `admin` edge comes from the workspace's own stream, and the use case " +
				"orders the two appends so a failure leaves a member without admin rather " +
				"than an admin without membership",
		},
		{
			name: "a GUEST gets nothing", role: workspacecontract.RoleGuest,
			grant: false,
			why: "a guest is structurally the absence of the membership edge " +
				"(access.md §7.6), not a role with deny rules",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := react(t, &workspacecontract.MemberJoined{
				WorkspaceID: wsID, OrgID: "org_x", SubjectID: subjID,
				Role: tt.role, JoinedAt: time.Unix(0, 0).UTC(),
			}, decoder[workspacecontract.MemberJoined]())

			if tt.grant {
				if len(w.written) != 1 || w.written[0] != memberTuple("member") {
					t.Fatalf("wrote %v, want exactly the membership edge — %s", w.written, tt.why)
				}
				return
			}
			if len(w.written) != 0 {
				t.Fatalf("wrote %v for a guest — %s", w.written, tt.why)
			}
		})
	}
}

// A removal REVOKES, and this delete is what confirms the tombstone.
//
// The handler lays a tombstone so the denial is immediate; the tombstone is then
// cleared only by a confirmed deletion, never by a timer (ADR-045). If this
// handler is missing, the tuple survives, the tombstone survives with it, and
// the revocation reaches its TTL — an over-denial arriving an hour after its
// cause, which reads as a permissions bug rather than as the missing handler it
// is.
func TestARemovalRevokesMembership(t *testing.T) {
	w := react(t, &workspacecontract.MemberRemoved{
		WorkspaceID: wsID, OrgID: "org_x", SubjectID: subjID,
		Role: workspacecontract.RoleMember, RemovedAt: time.Unix(0, 0).UTC(),
	}, decoder[workspacecontract.MemberRemoved]())

	if len(w.deleted) != 1 || w.deleted[0] != memberTuple("member") {
		t.Fatalf("deleted %v, want exactly the membership edge; leaving it in place keeps "+
			"the tombstone alive until its TTL", w.deleted)
	}
	if len(w.written) != 0 {
		t.Errorf("a removal wrote %v", w.written)
	}
}

// A role change never leaves the person holding the union of both roles.
//
// Delete then write, in that order. Both orders converge, but the reverse holds
// the union for one round trip — and a promotion is far more common than a
// demotion, so the union is the permissive direction.
func TestAPromotionOutOfGuestGrantsMembership(t *testing.T) {
	w := react(t, &workspacecontract.MemberRoleChanged{
		WorkspaceID: wsID, OrgID: "org_x", SubjectID: subjID,
		From: workspacecontract.RoleGuest, To: workspacecontract.RoleMember,
		ChangedAt: time.Unix(0, 0).UTC(),
	}, decoder[workspacecontract.MemberRoleChanged]())

	if len(w.written) != 1 || w.written[0] != memberTuple("member") {
		t.Fatalf("wrote %v, want the membership edge a guest never had", w.written)
	}
	if len(w.deleted) != 0 {
		t.Errorf("deleted %v for a guest, who held no tuple to delete", w.deleted)
	}
}

// The mirror: a demotion TO guest takes the edge away.
func TestADemotionToGuestRevokesMembership(t *testing.T) {
	w := react(t, &workspacecontract.MemberRoleChanged{
		WorkspaceID: wsID, OrgID: "org_x", SubjectID: subjID,
		From: workspacecontract.RoleMember, To: workspacecontract.RoleGuest,
		ChangedAt: time.Unix(0, 0).UTC(),
	}, decoder[workspacecontract.MemberRoleChanged]())

	if len(w.deleted) != 1 || w.deleted[0] != memberTuple("member") {
		t.Fatalf("deleted %v, want the membership edge; a demoted guest that keeps it is a "+
			"guest with a member's view", w.deleted)
	}
	if len(w.written) != 0 {
		t.Errorf("wrote %v for a guest", w.written)
	}
}

// The subscription filter has to name the membership category.
//
// Asserted separately from the handlers because it fails INDEPENDENTLY of them:
// every handler above can be correct and still never run, which is what happened
// before this commit. A filter is not visible in any handler test, and a
// reactor that matches nothing looks exactly like a quiet system.
func TestTheFilterCoversMembershipStreams(t *testing.T) {
	tuples, err := NewTuples(&recordingWriter{}, oneEventCodec{})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, p := range tuples.Filter().StreamPrefixes {
		if p == "membership-" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the filter is %v and does not include membership streams, so every join, "+
			"role change and removal is skipped before React sees it — and skipped grants "+
			"deny, which is what a healthy graph looks like from outside",
			tuples.Filter().StreamPrefixes)
	}
}
