//go:build integration

package kurrentdb_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	kurrentadapter "github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	"github.com/chronos/chronos-go/internal/modules/organization"
	orgcontract "github.com/chronos/chronos-go/internal/modules/organization/contract"
	orgdomain "github.com/chronos/chronos-go/internal/modules/organization/domain"
	operatorevents "github.com/chronos/chronos-go/internal/operator/adapter/kurrentdb"
	"github.com/chronos/chronos-go/internal/operator/app"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// These test the claim operator.md §7 makes, which is the one worth testing:
//
//	"Operator writes go through the same domain commands as everything else —
//	 they emit the same events and honour the same invariants. There is no
//	 privileged back-channel that skips domain rules, because that back-channel
//	 is exactly what corrupts state that then cannot be replayed."
//
// A unit test with a stubbed repository would prove the use case calls
// something. These prove the event that lands on the TENANT'S OWN STREAM is the
// tenant's own event, that the tenant's own state machine refused what it
// should, and that two operators racing one organization do not both win.

// TestAnOperatorSuspensionIsAnOrdinaryTenantEvent is §7's claim, asserted on
// what actually lands in the log.
//
// It matters because everything downstream is keyed off that event and nothing
// re-checks: the projections, `organization.suspended` mailing every member,
// gate 3 refusing writes. An operator-flavoured event would have silently
// bypassed all three while the operator plane's own audit log looked complete.
func TestAnOperatorSuspensionIsAnOrdinaryTenantEvent(t *testing.T) {
	h := newHarness(t)
	orgID := h.provisionedOrg(t)

	changed, err := h.writer.Suspend(t.Context(), orgID, orgcontract.OperatorAction, h.now)
	if err != nil {
		t.Fatalf("suspending: %v", err)
	}
	if !changed {
		t.Fatal("the suspension reported no change")
	}

	events := h.replay(t, orgID)
	last, ok := events[len(events)-1].(*orgcontract.OrganizationSuspended)
	if !ok {
		t.Fatalf("the last event on the ORGANIZATION's stream is %T.\n\n"+
			"operator.md §7: operator writes emit the SAME events as everything else. "+
			"An operator-specific type here would bypass every consumer of "+
			"OrganizationSuspended — the projections, the mail to every member, and "+
			"gate 3 — while the operator plane's own audit log looked complete.",
			events[len(events)-1])
	}
	if last.OrgID != orgID {
		t.Errorf("the event names %q, not %q", last.OrgID, orgID)
	}
	if last.Reason != orgcontract.OperatorAction {
		t.Errorf("reason = %q, want %q", last.Reason, orgcontract.OperatorAction)
	}

	// And the ORGANIZATION agrees it is suspended, which is the fold rather
	// than the append.
	if got := h.status(t, orgID); got != orgdomain.StatusSuspended {
		t.Errorf("the organization is %q after an operator suspension", got)
	}
}

// TestReinstatementIsTheOrdinaryActivation.
//
// There is no reinstate-specific command, deliberately: a suspension lifted and
// a trial converting both land in Active, and an operator-only path would be a
// second way to reach one state — which is how two paths drift until they
// disagree about what Active means.
func TestReinstatementIsTheOrdinaryActivation(t *testing.T) {
	h := newHarness(t)
	orgID := h.provisionedOrg(t)

	if _, err := h.writer.Suspend(t.Context(), orgID, orgcontract.OperatorAction, h.now); err != nil {
		t.Fatalf("suspending: %v", err)
	}

	changed, err := h.writer.Reinstate(t.Context(), orgID, h.now.Add(time.Minute))
	if err != nil {
		t.Fatalf("reinstating: %v", err)
	}
	if !changed {
		t.Fatal("the reinstatement reported no change")
	}

	events := h.replay(t, orgID)
	if _, ok := events[len(events)-1].(*orgcontract.OrganizationActivated); !ok {
		t.Fatalf("reinstating appended %T, not OrganizationActivated",
			events[len(events)-1])
	}
	if got := h.status(t, orgID); got != orgdomain.StatusActive {
		t.Errorf("the organization is %q after a reinstatement", got)
	}
}

// TestTheStateMachineRefusesTheOperatorToo is the invariant half of §7's claim.
//
// "Honour the same invariants" is the part that would be easy to lose: an
// operator path that loaded a projection, or that appended without folding,
// would let a CLOSED organization be suspended — and the append would succeed,
// because nothing downstream re-checks a transition the aggregate was supposed
// to refuse.
func TestTheStateMachineRefusesTheOperatorToo(t *testing.T) {
	h := newHarness(t)
	orgID := h.provisionedOrg(t)

	// Close it, through the ordinary command.
	h.command(t, orgID, func(agg *orgdomain.Organization) error {
		return agg.Close(h.now)
	})

	_, err := h.writer.Suspend(t.Context(), orgID, orgcontract.OperatorAction, h.now.Add(time.Minute))
	if err == nil {
		t.Fatal("an operator suspended a CLOSED organization; the state machine did not " +
			"refuse the operator plane, which means the operator path is not going " +
			"through it")
	}
	if !errors.Is(err, app.ErrIllegalTransition) {
		t.Errorf("refused for the wrong reason: %v", err)
	}

	// And nothing was appended.
	events := h.replay(t, orgID)
	if _, ok := events[len(events)-1].(*orgcontract.OrganizationClosed); !ok {
		t.Errorf("a refused suspension still appended %T", events[len(events)-1])
	}
}

// TestSuspendingAnOrganizationThatDoesNotExistIsRefused.
//
// A missing stream is not an error to the repository — it returns a new
// aggregate, which is what lets create and modify share a path. Suspending
// nothing must not quietly succeed and leave an audit entry claiming a customer
// was switched off.
func TestSuspendingAnOrganizationThatDoesNotExistIsRefused(t *testing.T) {
	h := newHarness(t)
	absent := "org_" + ids.New[ids.Org](time.Now(), ids.Entropy()).String()[4:]

	_, err := h.writer.Suspend(t.Context(), absent, orgcontract.OperatorAction, h.now)
	if !errors.Is(err, app.ErrNoSuchOrganization) {
		t.Fatalf("suspending a nonexistent organization gave %v, want ErrNoSuchOrganization", err)
	}
}

// TestSuspendingTwiceIsIdempotent.
//
// The second call is a success that changed nothing — the aggregate's state
// machine refuses suspended → suspended, and the adapter reports that as
// `changed: false` rather than as a failure. A second click must not be an
// error, and it must not append a second event either.
func TestSuspendingTwiceIsIdempotent(t *testing.T) {
	h := newHarness(t)
	orgID := h.provisionedOrg(t)

	if _, err := h.writer.Suspend(t.Context(), orgID, orgcontract.OperatorAction, h.now); err != nil {
		t.Fatalf("suspending: %v", err)
	}
	before := len(h.replay(t, orgID))

	changed, err := h.writer.Suspend(t.Context(), orgID, orgcontract.OperatorAction, h.now)
	switch {
	case err == nil && changed:
		t.Fatal("a second suspension reported a change")
	case err != nil && !errors.Is(err, app.ErrIllegalTransition):
		t.Fatalf("a second suspension failed unexpectedly: %v", err)
	}

	if after := len(h.replay(t, orgID)); after != before {
		t.Errorf("a second suspension appended %d event(s)", after-before)
	}
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type harness struct {
	store  *kurrentadapter.Store
	codec  *eventcodec.JSON
	repo   *eventsourcing.Repository[*orgdomain.Organization]
	writer *operatorevents.Organizations
	now    time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	upcasters := eventsourcing.NewUpcasterRegistry()
	codec := eventcodec.NewJSON(upcasters)
	organization.RegisterEvents(codec)
	organization.RegisterSchemas(upcasters)

	client, err := kurrentadapter.Dial(envOr("KURRENTDB_CONNECTION_STRING",
		"kurrentdb://localhost:2113?tls=false"))
	if err != nil {
		t.Fatalf("kurrentdb: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	store := kurrentadapter.NewStore(client, codec)
	now := time.Now().UTC().Truncate(time.Microsecond)

	writer, err := operatorevents.NewOrganizations(store, codec, upcasters, func() time.Time { return now })
	if err != nil {
		t.Fatalf("building the organization writer: %v", err)
	}

	return &harness{
		store: store,
		codec: codec,
		repo: eventsourcing.NewRepository(store, codec, upcasters,
			orgdomain.Category, orgdomain.NewOrganization),
		writer: writer,
		now:    now,
	}
}

// provisionedOrg creates an organization and walks it to Active, through the
// ordinary commands — so the fixture cannot be in a state the domain would
// refuse to produce.
func (h *harness) provisionedOrg(t *testing.T) string {
	t.Helper()
	orgID := "org_" + ids.New[ids.Org](time.Now(), ids.Entropy()).String()[4:]

	h.command(t, orgID, func(agg *orgdomain.Organization) error {
		return agg.Create(orgID, "Kettle & Sons", "kettle-"+orgID[4:12], "subj_owner", h.now)
	})
	h.command(t, orgID, func(agg *orgdomain.Organization) error {
		return agg.StartTrial("cus_test", "sub_test", h.now.Add(14*24*time.Hour), h.now)
	})
	h.command(t, orgID, func(agg *orgdomain.Organization) error {
		return agg.Activate(h.now)
	})
	return orgID
}

func (h *harness) command(t *testing.T, orgID string, apply func(*orgdomain.Organization) error) {
	t.Helper()
	agg, err := h.repo.Load(t.Context(), orgdomain.StreamKey(orgID))
	if err != nil {
		t.Fatalf("loading %s: %v", orgID, err)
	}
	if err := apply(agg); err != nil {
		t.Fatalf("applying a command to %s: %v", orgID, err)
	}
	key := ids.New[ids.Event](time.Now(), ids.Entropy()).String()
	if _, err := h.repo.Save(t.Context(), orgdomain.StreamKey(orgID), agg, key,
		eventsourcing.Metadata{OrgID: orgID}); err != nil {
		t.Fatalf("saving %s: %v", orgID, err)
	}
}

// replay reads the organization's stream back, which is what makes these tests
// about the LOG rather than about the in-memory aggregate.
func (h *harness) replay(t *testing.T, orgID string) []eventsourcing.Event {
	t.Helper()
	stream, err := eventsourcing.NewStreamID(orgdomain.Category, orgdomain.StreamKey(orgID))
	if err != nil {
		t.Fatalf("stream id: %v", err)
	}
	recorded, err := h.store.ReadStream(t.Context(), stream, 0)
	if err != nil {
		t.Fatalf("reading %s: %v", stream, err)
	}
	if len(recorded) == 0 {
		t.Fatalf("%s is empty", stream)
	}
	out := make([]eventsourcing.Event, 0, len(recorded))
	for _, r := range recorded {
		ev, decErr := h.codec.Unmarshal(r.Type, r.Payload)
		if decErr != nil {
			t.Fatalf("decoding %s: %v", r.Type, decErr)
		}
		out = append(out, ev)
	}
	return out
}

func (h *harness) status(t *testing.T, orgID string) orgdomain.Status {
	t.Helper()
	agg, err := h.repo.Load(t.Context(), orgdomain.StreamKey(orgID))
	if err != nil {
		t.Fatalf("loading %s: %v", orgID, err)
	}
	return agg.Status()
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

var _ = fmt.Sprintf
var _ = context.Background
