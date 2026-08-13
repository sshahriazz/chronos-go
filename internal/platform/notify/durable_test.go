package notify_test

import (
	"context"
	"errors"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/workflow"
)

// spyStarter records what the reactor asked to be started.
type spyStarter struct {
	starts []workflow.Start
	err    error
}

func (s *spyStarter) Start(_ context.Context, w workflow.Start) (workflow.Run, error) {
	s.starts = append(s.starts, w)
	if s.err != nil {
		return workflow.Run{}, s.err
	}
	return workflow.Run{ID: w.ID, RunID: "run_1"}, nil
}

// reactWith runs one event through a reactor built with the given options and
// reports what the transport saw and what was started.
func reactWith(t *testing.T, opts ...notify.ReactorOption) (*spyTransport, error) {
	t.Helper()

	cat := notify.NewCatalogue()
	notify.On[passwordChanged](cat, notify.Spec{
		Template: "identity.password_changed",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, nil)

	email := &spyTransport{ch: notify.ChannelEmail}
	d := notify.NewDispatcher(notify.Deps{
		Vault: vault{}, Transports: []notify.Transport{email}, Log: quiet(),
	})
	r := notify.NewEventReactor("notifications", cat, catCodec{},
		notify.SubjectAudiences{}, d, opts...)

	return email, r.React(context.Background(), orgEnvelope("org_A"))
}

// Without a starter the reactor delivers inline — what a deployment with
// TEMPORAL_ENABLED=false does, and it must still send.
func TestWithoutWorkflowsTheReactorDeliversInline(t *testing.T) {
	email, err := reactWith(t)
	if err != nil {
		t.Fatalf("react: %v", err)
	}
	if email.calls != 1 {
		t.Fatalf("delivered %d times inline, want 1", email.calls)
	}
}

// With one, delivery becomes durable: the reactor starts a workflow and does
// NOT send inline. Sending both ways would double every notification.
func TestWithWorkflowsTheReactorStartsOneRunPerRecipient(t *testing.T) {
	spy := &spyStarter{}
	email, err := reactWith(t, notify.WithWorkflows(spy))
	if err != nil {
		t.Fatalf("react: %v", err)
	}
	if email.calls != 0 {
		t.Fatalf("delivered %d times inline AND started a workflow; every notification "+
			"would be sent twice", email.calls)
	}
	if len(spy.starts) != 1 {
		t.Fatalf("started %d workflows, want 1", len(spy.starts))
	}

	start := spy.starts[0]
	if start.Name != notify.SendNotificationWorkflow {
		t.Errorf("started %q, want %q", start.Name, notify.SendNotificationWorkflow)
	}
	// DERIVED from the event, so a redelivery names the same run rather than
	// starting a second one — which for mail is a second email. Stability is
	// asserted separately; here it only has to exist.
	if start.ID == "" {
		t.Error("the workflow was started with no id, so nothing can refuse a duplicate")
	}

	in, ok := start.Input.(notify.SendNotificationInput)
	if !ok {
		t.Fatalf("workflow input is %T, want SendNotificationInput", start.Input)
	}
	if in.Template != "identity.password_changed" {
		t.Errorf("template %q", in.Template)
	}
	if in.SubjectID == "" {
		t.Error("the workflow carries no subject, so the activity cannot resolve anyone")
	}
	if in.IdempotencyKey != start.ID {
		t.Errorf("the idempotency key %q and the workflow id %q disagree; a redelivery "+
			"would dedupe at one layer and not the other", in.IdempotencyKey, start.ID)
	}
}

// The workflow id must be stable across redeliveries — that is the whole
// idempotency argument. Two reactions to the SAME event must name the same run.
func TestTheWorkflowIDIsStableAcrossRedeliveries(t *testing.T) {
	spy := &spyStarter{}
	if _, err := reactWith(t, notify.WithWorkflows(spy)); err != nil {
		t.Fatalf("react: %v", err)
	}
	if _, err := reactWith(t, notify.WithWorkflows(spy)); err != nil {
		t.Fatalf("react: %v", err)
	}
	if len(spy.starts) != 2 {
		t.Fatalf("started %d workflows, want 2 attempts", len(spy.starts))
	}
	if spy.starts[0].ID != spy.starts[1].ID {
		t.Errorf("a redelivery asked for a different run: %q then %q — the service could "+
			"not refuse it, and the effect would happen twice",
			spy.starts[0].ID, spy.starts[1].ID)
	}
}

// A refusal is SUCCESS: the run is already going or already went, which is what
// this call wanted. Treating it as an error would park an event whose
// notification was delivered perfectly.
func TestAnAlreadyStartedRunIsNotAFailure(t *testing.T) {
	spy := &spyStarter{err: workflow.ErrAlreadyStarted}
	if _, err := reactWith(t, notify.WithWorkflows(spy)); err != nil {
		t.Fatalf("a duplicate start must be success, got %v", err)
	}
}

// A start that genuinely failed must be RETURNED: the subscription redelivers,
// rather than acking a notification nobody will ever send.
func TestAFailedStartAsksForRedelivery(t *testing.T) {
	spy := &spyStarter{err: workflow.ErrUnavailable}
	_, err := reactWith(t, notify.WithWorkflows(spy))
	if err == nil {
		t.Fatal("a failed start was swallowed; the notification is lost with no signal")
	}
	if errors.Is(err, eventsourcing.ErrPoison) {
		t.Error("an unavailable service parked the event; it is retryable, not poison")
	}
}

// Workflow input is written to durable, replicated history — so the event-log
// rule applies unchanged: pseudonyms only, and the address is resolved from the
// vault inside the activity.
func TestWorkflowInputCarriesNoPersonalData(t *testing.T) {
	in := notify.InputFor(notify.Notification{
		Template: "identity.password_changed",
		Class:    notify.Security,
		OrgID:    "org_A",
		Recipient: notify.Recipient{
			SubjectID: "sub_1",
			OrgID:     "org_A",
			Address:   "someone@example.com",
			Name:      "Someone Real",
		},
	})
	if in.SubjectID != "sub_1" {
		t.Errorf("subject %q", in.SubjectID)
	}
	// The reduction is the point: there is no field on the input that could
	// carry either of these into history.
	if got := in.Notification().Recipient; got.Address != "" || got.Name != "" {
		t.Errorf("personal data survived the round trip into workflow history: %+v", got)
	}
}
