package projection_test

import (
	"context"
	"strings"
	"testing"
	"time"

	notificationdb "github.com/chronos/chronos-go/gen/sqlc/notification"
	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	identitycontract "github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/notification/contract"
	"github.com/chronos/chronos-go/internal/modules/notification/projection"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	platformprojection "github.com/chronos/chronos-go/internal/platform/projection"
)

// A projection under test, with the statement its erasure handler must queue.
type erasable struct {
	name      string
	build     func(eventsourcing.Codec) projectionUnderTest
	statement string
	table     string
}

// projectionUnderTest is the intersection of the kernel's Projection and the
// registration lookup each of this module's projections exposes for exactly
// this test.
type projectionUnderTest interface {
	Filter() eventsourcing.SubscriptionFilter
	Handles(eventType string) bool
	Apply(ctx context.Context, w db.Writer, env platformprojection.Envelope) error
}

func erasables() []erasable {
	return []erasable{
		{
			name:      "feed",
			build:     func(c eventsourcing.Codec) projectionUnderTest { return projection.NewFeed(c) },
			statement: notificationdb.DeleteFeedOfSubject,
			table:     "notification_feed",
		},
		{
			name: "push subscriptions",
			build: func(c eventsourcing.Codec) projectionUnderTest {
				return projection.NewPushSubscriptions(c)
			},
			statement: notificationdb.DeletePushSubscriptionsOfSubject,
			table:     "push_subscription",
		},
		{
			name: "channel preferences",
			build: func(c eventsourcing.Codec) projectionUnderTest {
				return projection.NewPreferences(c)
			},
			statement: notificationdb.DeleteChannelPreferencesOfSubject,
			table:     "notification_preference",
		},
	}
}

// Every notification projection subscribes to the erasure it says it handles.
//
// A unit test rather than an integration one, and for the reason identity's
// account projection gives: this asks whether the handler is REGISTERED and
// whether the subscription would ever DELIVER it, which is exactly the class of
// defect this repository has shipped repeatedly — code that is built, tested,
// and wired into nothing. No database can answer it.
//
// The two halves are independent decisions and both have to hold. Before this
// change all three of these projections filtered on `StreamPrefixes:
// {"notification-"}`, and `identity.UserErased.v1` is appended to a `user-`
// stream: a handler registered under that filter would have been correct,
// covered by its own passing test, and never once invoked in production.
func TestEveryNotificationProjectionSubscribesToTheErasureItHandles(t *testing.T) {
	erased := (&identitycontract.UserErased{}).EventType()

	for _, p := range erasables() {
		t.Run(p.name, func(t *testing.T) {
			// nil codec: Handles is a registration lookup and never decodes.
			subject := p.build(nil)

			if !subject.Handles(erased) {
				t.Fatalf("the %s projection ignores %s, so an erased subject keeps its rows "+
					"in %s forever", p.name, erased, p.table)
			}

			f := subject.Filter()
			if err := f.Validate(); err != nil {
				t.Fatalf("the %s projection's filter is invalid: %v", p.name, err)
			}
			if !delivers(f, erased) {
				t.Fatalf("the %s projection handles %s but its filter %+v never delivers it; "+
					"the handler would be dead code and %s would keep the rows",
					p.name, erased, f, p.table)
			}
		})
	}
}

// Widening the filter must not have narrowed it.
//
// The filter moved from stream prefixes to event-type prefixes to fit the
// erasure alongside this module's own events — a KurrentDB filter matches
// streams or types and never both. That is a rewrite of the selector, not an
// addition to it, and a rewrite is where a module's own events get dropped: the
// projection would then look healthy, keep its checkpoint moving, and simply
// stop projecting.
func TestTheWidenedFilterStillDeliversEveryEventTheModulePublishes(t *testing.T) {
	published := []eventsourcing.Event{
		&contract.NotificationCreated{}, &contract.NotificationRead{},
		&contract.PushSubscribed{}, &contract.PushSubscriptionExpired{},
		&contract.PushSent{}, &contract.ChannelPreferenceSet{},
	}

	for _, p := range erasables() {
		t.Run(p.name, func(t *testing.T) {
			f := p.build(nil).Filter()
			for _, e := range published {
				if !delivers(f, e.EventType()) {
					t.Errorf("the %s projection's filter %+v drops %s, which this module "+
						"publishes", p.name, f, e.EventType())
				}
			}
		})
	}
}

// The scope statement has to be queued BEFORE the delete, or the delete removes
// nothing.
//
// All three tables carry row security keyed on `org_id`, and `UserErased` names
// no organization — an account is a fact about a person, so the projector's
// batch carries no `app.org_id` at all. Measured against the running server
// before migration 00052: the DELETE reported `DELETE 0`, the batch committed,
// the checkpoint advanced, and the row was still readable afterwards under its
// owning organization.
//
// So the order is load-bearing, and asserting it is the only cheap way to keep
// it. Statements are queued into one pipelined batch and execute in the order
// they were queued; a policy reads the setting as it stands when the statement
// runs, so a scope queued after its delete grants nothing to anything.
func TestTheErasureHandlerNamesTheSubjectBeforeItDeletesAnything(t *testing.T) {
	codec := newCodec(t)
	env := erasureEnvelope(t, codec, "sub_erased", time.Now().UTC())

	for _, p := range erasables() {
		t.Run(p.name, func(t *testing.T) {
			w := &recorder{}
			if err := p.build(codec).Apply(context.Background(), w, env); err != nil {
				t.Fatalf("applying %s: %v", env.Type, err)
			}

			scope := w.indexOf(notificationdb.ScopeErasedSubject)
			del := w.indexOf(p.statement)
			switch {
			case del < 0:
				t.Fatalf("the %s projection queued no delete for an erased subject; "+
					"%s keeps its rows", p.name, p.table)
			case scope < 0:
				t.Fatalf("the %s projection deleted without naming the erased subject; "+
					"under row security that statement removes nothing and reports no error",
					p.name)
			case scope > del:
				t.Fatalf("the %s projection named the subject AFTER its delete (%d > %d); "+
					"the policy is evaluated when the delete runs, so it would remove nothing",
					p.name, scope, del)
			}

			for _, i := range []int{scope, del} {
				if got := w.args[i]; len(got) != 1 || got[0] != "sub_erased" {
					t.Errorf("statement %d was queued with %v, want exactly the erased "+
						"subject", i, got)
				}
			}
		})
	}
}

// An erasure that names nobody must stop the projection rather than commit.
//
// The empty string is not a subject: the scope statement would grant nothing,
// the delete would match nothing, and the checkpoint would advance past an
// erasure this module silently failed to perform. Retrying re-reads the same
// bytes, so it does not resolve itself — which is the point. A stopped
// projection is visible; a checkpoint past an unperformed erasure is not.
func TestAnErasureNamingNoSubjectStopsTheProjection(t *testing.T) {
	codec := newCodec(t)
	env := erasureEnvelope(t, codec, "", time.Now().UTC())

	for _, p := range erasables() {
		t.Run(p.name, func(t *testing.T) {
			w := &recorder{}
			err := p.build(codec).Apply(context.Background(), w, env)
			if err == nil {
				t.Fatalf("the %s projection accepted an erasure naming no subject and "+
					"queued %d statements; nothing would have been erased and nothing "+
					"would have said so", p.name, len(w.sql))
			}
			if !strings.Contains(err.Error(), "no subject") {
				t.Errorf("the error is %q, which does not say what was wrong with the "+
					"event", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------

// recorder is a db.Writer that keeps what was queued, in order.
type recorder struct {
	sql  []string
	args [][]any
}

var _ db.Writer = (*recorder)(nil)

func (r *recorder) Exec(sql string, args ...any) {
	r.sql = append(r.sql, sql)
	r.args = append(r.args, args)
}

// indexOf reports where a statement was queued, or -1.
func (r *recorder) indexOf(sql string) int {
	for i, s := range r.sql {
		if s == sql {
			return i
		}
	}
	return -1
}

// delivers reports whether a filter would carry an event type to a subscriber.
//
// It implements the ONE dimension the filters under test select on. A filter
// that selected on streams instead would have to be checked against a stream
// name, which is exactly the distinction this test exists to hold: the type is
// what the module can name from identity's contract, and the stream category is
// not.
func delivers(f eventsourcing.SubscriptionFilter, eventType string) bool {
	for _, p := range f.EventTypePrefixes {
		if strings.HasPrefix(eventType, p) {
			return true
		}
	}
	for _, t := range f.EventTypes {
		if t == eventType {
			return true
		}
	}
	return false
}

func newCodec(t *testing.T) *eventcodec.JSON {
	t.Helper()
	c := eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())
	eventcodec.Register[identitycontract.UserErased](c)
	return c
}

// erasureEnvelope builds what the projector would hand Apply.
//
// The metadata is deliberately EMPTY of tenant, because that is what identity
// appends: `Metadata{OccurredAt, SubjectIDs}` and nothing else
// (identity/app/erasure.go). An envelope carrying an org here would test a
// system that does not exist.
func erasureEnvelope(
	t *testing.T, codec *eventcodec.JSON, subjectID string, at time.Time,
) platformprojection.Envelope {
	t.Helper()
	e := &identitycontract.UserErased{SubjectID: subjectID, ErasedAt: at}
	payload, err := codec.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return platformprojection.Envelope{
		Type:    e.EventType(),
		Stream:  eventsourcing.StreamID("user-usr_erased"),
		Meta:    eventsourcing.Metadata{OccurredAt: at, SubjectIDs: []string{subjectID}},
		Payload: payload,
	}
}
