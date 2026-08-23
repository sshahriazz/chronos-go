package reactor_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	compliancereactor "github.com/chronos/chronos-go/internal/modules/compliance/reactor"
	identitycontract "github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/workflow"
)

const workflowName = "chronos.compliance.Erasure.v1"

type recordingStarter struct {
	started []workflow.Start
	err     error
}

func (r *recordingStarter) Start(
	_ context.Context, s workflow.Start,
) (workflow.Run, error) {
	r.started = append(r.started, s)
	if r.err != nil {
		return workflow.Run{}, r.err
	}
	return workflow.Run{ID: s.ID}, nil
}

func testCodec(t *testing.T) *eventcodec.JSON {
	t.Helper()
	codec := eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())
	eventcodec.Register[identitycontract.UserDeletionRequested](codec)
	eventcodec.Register[identitycontract.UserDeletionCancelled](codec)
	return codec
}

func requestEnvelope(t *testing.T, subjectID string) eventsourcing.Envelope {
	t.Helper()
	event := &identitycontract.UserDeletionRequested{
		SubjectID:    subjectID,
		ActorID:      subjectID,
		ScheduledFor: time.Now().Add(30 * 24 * time.Hour).UTC(),
		RequestedAt:  time.Now().UTC(),
	}
	payload, err := testCodec(t).Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return eventsourcing.Envelope{
		Type: event.EventType(), Payload: payload,
	}
}

func newReactor(t *testing.T, starter compliancereactor.Starter) *compliancereactor.Erasure {
	t.Helper()
	r, err := compliancereactor.NewErasure(starter, workflowName, testCodec(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A REQUEST STARTS THE CLOCK.
//
// Without this the request is recorded, a date is mailed to the person, and
// nothing ever runs — an unmet legal obligation whose only trace is an event
// nobody consumed.
func TestARequestStartsTheClock(t *testing.T) {
	starter := &recordingStarter{}
	const subject = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV"

	if err := newReactor(t, starter).React(
		context.Background(), requestEnvelope(t, subject)); err != nil {
		t.Fatal(err)
	}
	if len(starter.started) != 1 {
		t.Fatalf("started %d workflows, want 1", len(starter.started))
	}
	started := starter.started[0]
	if started.Name != workflowName {
		t.Errorf("started %q, want %q", started.Name, workflowName)
	}
	args, ok := started.Input.(compliancereactor.ErasureArgs)
	if !ok {
		t.Fatalf("input is %T", started.Input)
	}
	if args.SubjectID != subject {
		t.Errorf("started for %q, want %q", args.SubjectID, subject)
	}
}

// THE WORKFLOW ID IS KEYED ON THE SUBJECT, NOT THE EVENT.
//
// A redelivery must find the clock already running rather than starting a
// second. Two clocks on one account race, and the loser erases after the winner
// has already been cancelled — which is the cancel button failing in the one way
// nobody can detect until the account is gone.
func TestARedeliveryDoesNotStartASecondClock(t *testing.T) {
	starter := &recordingStarter{}
	const subject = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	r := newReactor(t, starter)

	for range 3 {
		if err := r.React(context.Background(), requestEnvelope(t, subject)); err != nil {
			t.Fatal(err)
		}
	}

	ids := map[string]bool{}
	for _, s := range starter.started {
		ids[s.ID] = true
	}
	if len(ids) != 1 {
		t.Fatalf("three deliveries produced %d distinct workflow ids: %v; two clocks on one "+
			"account race, and the loser erases after the winner was cancelled", len(ids), ids)
	}
}

// AN ALREADY-RUNNING CLOCK IS NOT A FAILURE.
//
// The ordinary case for a redelivery. Treating it as an error would park an
// event whose work is already in hand.
func TestAnAlreadyStartedClockIsAccepted(t *testing.T) {
	starter := &recordingStarter{err: workflow.ErrAlreadyStarted}

	if err := newReactor(t, starter).React(
		context.Background(), requestEnvelope(t, "subj_x")); err != nil {
		t.Fatalf("an already-running clock was reported as a failure: %v", err)
	}
}

// A FAILED START IS RETRIED.
//
// Anything else loses the request silently.
func TestAFailedStartIsReported(t *testing.T) {
	starter := &recordingStarter{err: errors.New("temporal: unavailable")}

	if err := newReactor(t, starter).React(
		context.Background(), requestEnvelope(t, "subj_x")); err == nil {
		t.Fatal("a failed start was acked; the request is lost and nothing retries")
	}
}

// AN EVENT WITH NO SUBJECT IS POISON.
//
// Retrying re-reads the same bytes, and an empty subject reaching the workflow
// starts a run that can only ever fail.
func TestARequestWithNoSubjectIsPoison(t *testing.T) {
	starter := &recordingStarter{}

	err := newReactor(t, starter).React(context.Background(), requestEnvelope(t, ""))
	if !errors.Is(err, eventsourcing.ErrPoison) {
		t.Fatalf("returned %v, want ErrPoison", err)
	}
	if len(starter.started) != 0 {
		t.Error("a workflow was started for an empty subject")
	}
}

// AN UNRELATED EVENT STARTS NOTHING.
//
// The filter can over-deliver, and a group can predate a filter change. Acting
// on whatever arrives would put erasure clocks on unrelated subjects.
func TestAnUnrelatedEventStartsNothing(t *testing.T) {
	starter := &recordingStarter{}

	cancelled := &identitycontract.UserDeletionCancelled{SubjectID: "subj_x"}
	payload, err := testCodec(t).Marshal(cancelled)
	if err != nil {
		t.Fatal(err)
	}
	if err := newReactor(t, starter).React(context.Background(), eventsourcing.Envelope{
		Type: cancelled.EventType(), Payload: payload,
	}); err != nil {
		t.Fatalf("an over-delivered event errored: %v", err)
	}
	if len(starter.started) != 0 {
		t.Fatal("a cancellation started an erasure clock")
	}
}

// AN INCOMPLETE WIRING IS REFUSED.
func TestTheErasureReactorRefusesAnIncompleteWiring(t *testing.T) {
	codec := testCodec(t)

	if _, err := compliancereactor.NewErasure(nil, workflowName, codec); err == nil {
		t.Error("a reactor with no starter was accepted; it would consume every deletion " +
			"request and drop it")
	}
	if _, err := compliancereactor.NewErasure(&recordingStarter{}, "", codec); err == nil {
		t.Error("a reactor with no workflow name was accepted; it starts nothing")
	}
	if _, err := compliancereactor.NewErasure(&recordingStarter{}, workflowName, nil); err == nil {
		t.Error("a reactor with no codec was accepted; every request parks")
	}
}
