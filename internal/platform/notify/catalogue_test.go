package notify_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

// ---------------------------------------------------------------------------
// test events
// ---------------------------------------------------------------------------

type passwordChanged struct{ Device, City string }
type sessionCreated struct{ Device string }
type telemetryRecorded struct{ N int }
type projectionStopped struct{ Projection, Reason string }

func (*passwordChanged) EventType() string   { return "identity.PasswordChanged.v1" }
func (*sessionCreated) EventType() string    { return "identity.SessionCreated.v1" }
func (*telemetryRecorded) EventType() string { return "identity.TelemetryRecorded.v1" }
func (*projectionStopped) EventType() string { return "system.ProjectionStopped.v1" }

// ---------------------------------------------------------------------------
// the property this exists for
// ---------------------------------------------------------------------------

// A new event type must not be able to reach production without someone
// deciding whether it notifies. "No catalogue entry" would otherwise mean
// "nobody is told, and nothing says so".
func TestUndecidedEventTypeIsAFailure(t *testing.T) {
	cat := notify.NewCatalogue()
	notify.On[passwordChanged](cat, notify.Spec{
		Template: "identity.password_changed",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, nil)

	// sessionCreated was added to the codec and forgotten here. Derived from
	// the type rather than typed as a literal, so a rename cannot make this
	// test pass against a name that no longer exists.
	known := []string{
		eventsourcing.TypeOf[passwordChanged](),
		eventsourcing.TypeOf[sessionCreated](),
	}

	err := cat.Verify(known)
	if err == nil {
		t.Fatal("an event type with no notification decision must fail verification — " +
			"this is the check that stops a security event shipping with nobody told")
	}
	if !strings.Contains(err.Error(), eventsourcing.TypeOf[sessionCreated]()) {
		t.Errorf("the error must name the undecided type, got: %v", err)
	}
}

// Deciding NOT to notify is a valid decision, and must be recorded as one.
func TestSilentIsAValidDecision(t *testing.T) {
	cat := notify.NewCatalogue()
	notify.On[passwordChanged](cat, notify.Spec{
		Template: "identity.password_changed",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, nil)
	notify.Silent[telemetryRecorded](cat, "internal counter; of no interest to anyone")

	known := []string{"identity.PasswordChanged.v1", "identity.TelemetryRecorded.v1"}
	if err := cat.Verify(known); err != nil {
		t.Fatalf("a declared-silent event must satisfy verification: %v", err)
	}

	reason, ok := cat.IsSilent("identity.TelemetryRecorded.v1")
	if !ok || reason == "" {
		t.Error("the reason for silence must be retrievable; absence alone is not a decision")
	}
}

func TestSilentRequiresAReason(t *testing.T) {
	cat := notify.NewCatalogue()
	defer func() {
		if recover() == nil {
			t.Fatal("declaring an event silent without a reason must panic at wiring time")
		}
	}()
	notify.Silent[telemetryRecorded](cat, "")
}

// A renamed or retired event leaves its notification behind, pointing at
// something that can no longer arrive.
func TestOrphanedEntriesAreReported(t *testing.T) {
	cat := notify.NewCatalogue()
	notify.On[passwordChanged](cat, notify.Spec{
		Template: "identity.password_changed",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, nil)

	orphans := cat.Orphans([]string{"identity.SomethingElse.v1"})
	if len(orphans) != 1 || orphans[0] != "identity.PasswordChanged.v1" {
		t.Fatalf("expected the stale entry to be reported, got %v", orphans)
	}
}

func TestDuplicateRegistrationPanics(t *testing.T) {
	cat := notify.NewCatalogue()
	spec := notify.Spec{
		Template: "identity.password_changed",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}
	notify.On[passwordChanged](cat, spec, nil)

	defer func() {
		if recover() == nil {
			t.Fatal("registering one event twice must panic: it would notify twice")
		}
	}()
	notify.On[passwordChanged](cat, spec, nil)
}

func TestSilentAndNotifyingAreMutuallyExclusive(t *testing.T) {
	cat := notify.NewCatalogue()
	notify.Silent[passwordChanged](cat, "decided against")

	defer func() {
		if recover() == nil {
			t.Fatal("an event declared silent must not then be given a notification")
		}
	}()
	notify.On[passwordChanged](cat, notify.Spec{
		Template: "x", Class: notify.Security, Audience: notify.AudienceSubject,
	}, nil)
}

// ---------------------------------------------------------------------------
// class and audience must agree
// ---------------------------------------------------------------------------

func TestOperatorClassAndAudienceMustMatch(t *testing.T) {
	t.Run("operator class with a tenant audience", func(t *testing.T) {
		cat := notify.NewCatalogue()
		defer func() {
			if recover() == nil {
				t.Fatal("operator wording addressed to a tenant must be rejected")
			}
		}()
		notify.On[projectionStopped](cat, notify.Spec{
			Template: "operator.alert", Class: notify.Operator, Audience: notify.AudienceSubject,
		}, nil)
	})

	t.Run("operator audience with a tenant class", func(t *testing.T) {
		cat := notify.NewCatalogue()
		defer func() {
			if recover() == nil {
				t.Fatal("tenant wording sent to operators must be rejected")
			}
		}()
		notify.On[projectionStopped](cat, notify.Spec{
			Template: "identity.welcome", Class: notify.Security, Audience: notify.AudienceOperator,
		}, nil)
	})
}

func TestAudienceIsRequired(t *testing.T) {
	cat := notify.NewCatalogue()
	defer func() {
		if recover() == nil {
			t.Fatal("a notification with no audience must be rejected: who receives it cannot be implicit")
		}
	}()
	notify.On[passwordChanged](cat, notify.Spec{
		Template: "identity.password_changed", Class: notify.Security,
	}, nil)
}

// ---------------------------------------------------------------------------
// the reactor drives entirely from the catalogue
// ---------------------------------------------------------------------------

func TestReactorDispatchesFromTheCatalogue(t *testing.T) {
	cat := notify.NewCatalogue()
	notify.On[passwordChanged](cat, notify.Spec{
		Template: "identity.password_changed",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, func(e *passwordChanged) map[string]any {
		return map[string]any{"Device": e.Device, "Location": e.City}
	})

	email := &spyTransport{ch: notify.ChannelEmail}
	d := notify.NewDispatcher(notify.Deps{
		Vault: vault{}, Transports: []notify.Transport{email}, Log: quiet(),
	})
	r := notify.NewEventReactor("notifications", cat, catCodec{}, notify.SubjectAudiences{}, d)

	err := r.React(context.Background(), envelope("identity.PasswordChanged.v1", "sub_1"))
	if err != nil {
		t.Fatalf("react: %v", err)
	}
	if email.calls != 1 {
		t.Fatalf("delivered %d times, want 1", email.calls)
	}
	if got := email.last.Data["Device"]; got != "Firefox" {
		t.Errorf("template data came out as %v, want Firefox", got)
	}
	if email.last.Class != notify.Security {
		t.Errorf("class %v, want security — it must come from the catalogue", email.last.Class)
	}
}

// An event with no entry is not an error: Verify is what guarantees it was
// decided about, so reaching here means it was decided against.
func TestReactorIgnoresUndecidedEvents(t *testing.T) {
	cat := notify.NewCatalogue()
	email := &spyTransport{ch: notify.ChannelEmail}
	d := notify.NewDispatcher(notify.Deps{
		Vault: vault{}, Transports: []notify.Transport{email}, Log: quiet(),
	})
	r := notify.NewEventReactor("notifications", cat, catCodec{}, notify.SubjectAudiences{}, d)

	if err := r.React(context.Background(), envelope("identity.PasswordChanged.v1", "s")); err != nil {
		t.Fatalf("an unmapped event must be ignored, not fail: %v", err)
	}
	if email.calls != 0 {
		t.Fatal("delivered a notification for an event with no catalogue entry")
	}
}

// An audience nothing can resolve must be PARKED, not skipped: skipping is the
// silent hole this design exists to remove.
func TestUnresolvableAudienceIsParked(t *testing.T) {
	cat := notify.NewCatalogue()
	notify.On[projectionStopped](cat, notify.Spec{
		Template: "operator.alert",
		Class:    notify.Operator,
		Audience: notify.AudienceOperator,
	}, nil)

	d := notify.NewDispatcher(notify.Deps{Vault: vault{}, Log: quiet()})
	// No operator recipients configured.
	r := notify.NewEventReactor("notifications", cat, catCodec{}, notify.SubjectAudiences{}, d)

	err := r.React(context.Background(), envelope("system.ProjectionStopped.v1", ""))
	if !errors.Is(err, eventsourcing.ErrPoison) {
		t.Fatalf("an unresolvable audience must be parked so the gap is visible, got %v", err)
	}
}

// Two people notified by one event must not deduplicate against each other.
func TestEachRecipientGetsADistinctIdempotencyKey(t *testing.T) {
	cat := notify.NewCatalogue()
	notify.On[passwordChanged](cat, notify.Spec{
		Template: "identity.password_changed",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, nil)

	email := &recordingTransport{ch: notify.ChannelEmail}
	d := notify.NewDispatcher(notify.Deps{
		Vault: vault{}, Transports: []notify.Transport{email}, Log: quiet(),
	})
	r := notify.NewEventReactor("notifications", cat, catCodec{}, notify.SubjectAudiences{}, d)

	env := envelope("identity.PasswordChanged.v1", "sub_1", "sub_2")
	if err := r.React(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if len(email.keys) != 2 {
		t.Fatalf("delivered %d notifications for 2 subjects", len(email.keys))
	}
	if email.keys[0] == email.keys[1] {
		t.Fatalf("both recipients share the idempotency key %q; the second would be "+
			"suppressed as a duplicate and never told", email.keys[0])
	}
}

// The subscription filter must cover exactly the catalogue's events.
func TestFilterCoversTheCatalogue(t *testing.T) {
	cat := notify.NewCatalogue()
	notify.On[passwordChanged](cat, notify.Spec{
		Template: "identity.password_changed", Class: notify.Security, Audience: notify.AudienceSubject,
	}, nil)
	notify.Silent[telemetryRecorded](cat, "internal counter")

	r := notify.NewEventReactor("notifications", cat, catCodec{}, notify.SubjectAudiences{}, nil)
	prefixes := r.Filter().EventTypePrefixes
	if len(prefixes) != 1 || prefixes[0] != "identity.PasswordChanged.v1" {
		t.Fatalf("filter is %v; it must name exactly the notifying events", prefixes)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func envelope(eventType string, subjects ...string) eventsourcing.Envelope {
	var ids []string
	for _, s := range subjects {
		if s != "" {
			ids = append(ids, s)
		}
	}
	return eventsourcing.Envelope{
		Type:    eventType,
		Stream:  "identity-u1",
		Payload: []byte(`{"Device":"Firefox","City":"Berlin"}`),
		Meta: eventsourcing.Metadata{
			SubjectIDs: ids,
			OccurredAt: time.Date(2026, 3, 14, 9, 26, 0, 0, time.UTC),
		},
	}
}

type catCodec struct{}

func (catCodec) Marshal(eventsourcing.Event) ([]byte, error) { return nil, nil }

func (catCodec) Unmarshal(t string, _ []byte) (eventsourcing.Event, error) {
	switch t {
	case "identity.PasswordChanged.v1":
		return &passwordChanged{Device: "Firefox", City: "Berlin"}, nil
	case "system.ProjectionStopped.v1":
		return &projectionStopped{Projection: "identity_users"}, nil
	}
	return nil, errors.New("unknown type")
}

func (catCodec) MarshalMetadata(eventsourcing.Metadata) ([]byte, error) { return nil, nil }
func (catCodec) UnmarshalMetadata([]byte) (eventsourcing.Metadata, error) {
	return eventsourcing.Metadata{}, nil
}

type recordingTransport struct {
	ch   notify.Channel
	keys []string
}

func (r *recordingTransport) Channel() notify.Channel { return r.ch }

func (r *recordingTransport) Deliver(_ context.Context, n notify.Notification) error {
	r.keys = append(r.keys, n.IdempotencyKey)
	return nil
}
