package reactor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/modules/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/workflow"
)

const (
	testSubject = "subj_01H8XG5N2QK7VB3C9WPYZR4TFN"
	testEventID = "evt_01H8XG5N2QK7VB3C9WPYZR4TFP"
)

var testNow = time.Date(2026, 3, 14, 9, 26, 0, 0, time.UTC)

// ---------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------

// stubIssuer answers with a distinct token per call, so a test can tell one
// delivery's credential from another's.
type stubIssuer struct {
	calls    []string
	err      error
	issued   []Verification
	ttl      time.Duration
	fixedFPr string
}

func (s *stubIssuer) IssueVerification(_ context.Context, subjectID string) (Verification, error) {
	s.calls = append(s.calls, subjectID)
	if s.err != nil {
		return Verification{}, s.err
	}
	ttl := s.ttl
	if ttl == 0 {
		ttl = 24 * time.Hour
	}
	fpr := s.fixedFPr
	if fpr == "" {
		fpr = fmt.Sprintf("fingerprint%d", len(s.calls))
	}
	v := Verification{
		Plaintext:   fmt.Sprintf("token-%d", len(s.calls)),
		ExpiresAt:   testNow.Add(ttl),
		TTL:         ttl,
		Fingerprint: fpr,
	}
	s.issued = append(s.issued, v)
	return v, nil
}

type recordingDispatcher struct {
	sent []notify.Notification
	err  error
}

func (d *recordingDispatcher) Dispatch(_ context.Context, n notify.Notification) error {
	d.sent = append(d.sent, n)
	return d.err
}

func (d *recordingDispatcher) last(t *testing.T) notify.Notification {
	t.Helper()
	if len(d.sent) == 0 {
		t.Fatal("nothing was dispatched: the verification link reached nobody")
	}
	return d.sent[len(d.sent)-1]
}

type recordingStarter struct {
	starts []workflow.Start
	err    error
}

func (s *recordingStarter) Start(_ context.Context, st workflow.Start) (workflow.Run, error) {
	s.starts = append(s.starts, st)
	if s.err != nil {
		return workflow.Run{}, s.err
	}
	return workflow.Run{ID: st.ID, RunID: "run-1"}, nil
}

func identityCodec() *eventcodec.JSON {
	codec := eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())
	identity.RegisterEvents(codec)
	return codec
}

// requestedEnvelope is a real EmailVerificationRequested, encoded by the real
// codec — so a change to the event's shape or its registration breaks these
// tests rather than passing against a hand-written JSON literal.
func requestedEnvelope(t *testing.T, subjectID string) eventsourcing.Envelope {
	t.Helper()
	payload, err := identityCodec().Marshal(&contract.EmailVerificationRequested{
		SubjectID:   subjectID,
		Index:       contract.EmailIndex("idx_abc"),
		ExpiresAt:   testNow.Add(24 * time.Hour),
		RequestedAt: testNow,
	})
	if err != nil {
		t.Fatalf("encoding the event: %v", err)
	}
	return eventsourcing.Envelope{
		ID:      ids.MustParse[ids.Event](testEventID),
		Type:    verificationRequestedType,
		Stream:  "identity-usr_1",
		Payload: payload,
		Meta: eventsourcing.Metadata{
			SubjectIDs: []string{subjectID},
			OccurredAt: testNow,
		},
	}
}

func build(t *testing.T, issuer Issuer, d Dispatcher, opts ...Option) *VerificationMail {
	t.Helper()
	r, err := NewVerificationMail(issuer, identityCodec(), d, opts...)
	if err != nil {
		t.Fatalf("wiring the reactor: %v", err)
	}
	return r
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

func TestNewVerificationMailRefusesAMissingDependency(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		issuer   Issuer
		codec    eventsourcing.Codec
		dispatch Dispatcher
	}{
		{"no issuer", nil, identityCodec(), &recordingDispatcher{}},
		{"no codec", &stubIssuer{}, nil, &recordingDispatcher{}},
		{"no dispatcher", &stubIssuer{}, identityCodec(), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewVerificationMail(tt.issuer, tt.codec, tt.dispatch); err == nil {
				t.Error("wiring succeeded with a missing dependency; the reactor would " +
					"consume the event, do nothing, and ack")
			}
		})
	}
}

// The subscription group is permanent, and so is the template name: one is the
// server-side cursor, the other appears in metrics, operator overrides and a
// mail header. A rename is a silent loss of everything not yet delivered.
func TestNamesArePermanent(t *testing.T) {
	t.Parallel()
	if VerificationReactorName != "identity-verification-mail" {
		t.Errorf("the subscription group was renamed to %q; a new group starts at the "+
			"END of the log and abandons every undelivered verification",
			VerificationReactorName)
	}
	if VerificationTemplate != "identity.verify_email" {
		t.Errorf("the template was renamed to %q; the renderer has no such template "+
			"and every verification mail becomes an unknown-template park",
			VerificationTemplate)
	}
	if got := build(t, &stubIssuer{}, &recordingDispatcher{}).Name(); got != VerificationReactorName {
		t.Errorf("Name() is %q, want %q", got, VerificationReactorName)
	}
}

func TestFilterNamesExactlyTheOneEvent(t *testing.T) {
	t.Parallel()
	filter := build(t, &stubIssuer{}, &recordingDispatcher{}).Filter()

	if got := filter.EventTypePrefixes; len(got) != 1 ||
		got[0] != "identity.EmailVerificationRequested.v1" {
		t.Fatalf("filter is %v; an empty or wider filter wakes this group on every "+
			"event in the system, and an empty one subscribes to all of them", got)
	}
	if err := filter.Validate(); err != nil {
		t.Errorf("the filter is not expressible server-side: %v", err)
	}
}

func TestDurableReportsTheWiredPath(t *testing.T) {
	t.Parallel()
	if build(t, &stubIssuer{}, &recordingDispatcher{}).Durable() {
		t.Error("claims durable delivery with no workflow starter wired")
	}
	if !build(t, &stubIssuer{}, &recordingDispatcher{},
		WithWorkflows(&recordingStarter{})).Durable() {
		t.Error("a wired starter is not reported")
	}
}

// ---------------------------------------------------------------------------
// React — the inline path
// ---------------------------------------------------------------------------

func TestReactDispatchesTheVerificationLink(t *testing.T) {
	t.Parallel()
	issuer, dispatcher := &stubIssuer{}, &recordingDispatcher{}

	if err := build(t, issuer, dispatcher).React(
		context.Background(), requestedEnvelope(t, testSubject)); err != nil {
		t.Fatalf("React: %v", err)
	}

	if len(dispatcher.sent) != 1 {
		t.Fatalf("dispatched %d notifications, want 1", len(dispatcher.sent))
	}
	n := dispatcher.last(t)

	if n.Template != VerificationTemplate {
		t.Errorf("template %q, want %q", n.Template, VerificationTemplate)
	}
	if n.Class != notify.Transactional {
		t.Errorf("class %s, want transactional — the person asked for this by "+
			"registering, so no preference may suppress it", n.Class)
	}
	if n.Recipient.SubjectID != testSubject {
		t.Errorf("recipient %q, want the event's subject %q", n.Recipient.SubjectID, testSubject)
	}
	if got := fmt.Sprint(n.Channels); got != fmt.Sprint([]notify.Channel{notify.ChannelEmail}) {
		t.Errorf("channels %v, want email only: the in-app feed would project this "+
			"live credential into a Postgres row and web push would hand it to a "+
			"browser endpoint", n.Channels)
	}
	if got := n.Data["Token"]; got != issuer.issued[0].Plaintext {
		t.Errorf("the notification carries token %v, want the one just issued (%q)",
			got, issuer.issued[0].Plaintext)
	}
	if got := n.Data["ExpiresIn"]; got != "24 hours" {
		t.Errorf("ExpiresIn is %v, want the minted lifetime", got)
	}
	if !n.OccurredAt.Equal(testNow) {
		t.Errorf("OccurredAt %s, want the event's %s", n.OccurredAt, testNow)
	}
}

// ADR-002 at the reactor boundary: the address is resolved from the vault at
// delivery time, so nothing identifying may be attached here — not by the event,
// which carries none, and not by this code.
func TestReactCarriesNoContactDetails(t *testing.T) {
	t.Parallel()
	dispatcher := &recordingDispatcher{}

	if err := build(t, &stubIssuer{}, dispatcher).React(
		context.Background(), requestedEnvelope(t, testSubject)); err != nil {
		t.Fatalf("React: %v", err)
	}
	n := dispatcher.last(t)

	if n.Recipient.Address != "" || n.Recipient.Name != "" {
		t.Errorf("the notification carries contact details (%q / %q); only the vault "+
			"may supply them", n.Recipient.Address, n.Recipient.Name)
	}
	for key := range n.Data {
		switch key {
		case "Token", "ExpiresIn":
		default:
			t.Errorf("template data carries %q; Data is rendered and must hold no "+
				"personal data", key)
		}
	}
}

func TestReactKeysTheDeliveryByEventAndToken(t *testing.T) {
	t.Parallel()
	issuer, dispatcher := &stubIssuer{}, &recordingDispatcher{}

	if err := build(t, issuer, dispatcher).React(
		context.Background(), requestedEnvelope(t, testSubject)); err != nil {
		t.Fatalf("React: %v", err)
	}

	want := testEventID + ":" + issuer.issued[0].Fingerprint
	if got := dispatcher.last(t).IdempotencyKey; got != want {
		t.Errorf("idempotency key %q, want %q — it becomes the Message-ID, so it must "+
			"identify THIS token rather than merely the event that asked for one",
			got, want)
	}
}

// A redelivery mints again, and that is deliberate: the invariant is one LIVE
// token, not one email. What must never happen is two live tokens — spending one
// would leave the other usable — and what must also never happen is the second
// mail carrying the first, revoked token.
func TestRedeliverySendsTheNewTokenAndNotTheRevokedOne(t *testing.T) {
	t.Parallel()
	issuer, dispatcher := &stubIssuer{}, &recordingDispatcher{}
	r := build(t, issuer, dispatcher)
	env := requestedEnvelope(t, testSubject)

	for i := range 2 {
		if err := r.React(context.Background(), env); err != nil {
			t.Fatalf("React #%d: %v", i+1, err)
		}
	}

	if len(issuer.calls) != 2 || len(dispatcher.sent) != 2 {
		t.Fatalf("issued %d and dispatched %d, want 2 and 2", len(issuer.calls), len(dispatcher.sent))
	}
	first, second := dispatcher.sent[0], dispatcher.sent[1]
	if first.Data["Token"] == second.Data["Token"] {
		t.Fatal("both deliveries carry the same token; the second issuance revoked " +
			"the first, so one of these links is dead")
	}
	if second.Data["Token"] != issuer.issued[1].Plaintext {
		t.Error("the second delivery does not carry the most recently issued token — " +
			"the only one still redeemable")
	}
	if first.IdempotencyKey == second.IdempotencyKey {
		t.Error("the two deliveries share a key; deduplicating them would send only " +
			"the mail carrying the now-revoked token")
	}
}

func TestReactReturnsTheIssuersFailure(t *testing.T) {
	t.Parallel()
	issuer := &stubIssuer{err: errors.New("postgres unreachable")}
	dispatcher := &recordingDispatcher{}

	err := build(t, issuer, dispatcher).React(
		context.Background(), requestedEnvelope(t, testSubject))
	if err == nil {
		t.Fatal("a failed issuance was acked; the registration would be told nothing")
	}
	if errors.Is(err, eventsourcing.ErrPoison) {
		t.Error("a store outage was parked; it is transient and must be redelivered")
	}
	if len(dispatcher.sent) != 0 {
		t.Error("dispatched a notification with no token")
	}
}

// A failed send must ask for redelivery. Acking it would leave a live token that
// nobody was ever told about — an account that can never be verified, and an
// address that can never be registered again.
func TestReactReturnsTheDispatchFailure(t *testing.T) {
	t.Parallel()
	dispatcher := &recordingDispatcher{err: errors.New("smtp refused")}

	if err := build(t, &stubIssuer{}, dispatcher).React(
		context.Background(), requestedEnvelope(t, testSubject)); err == nil {
		t.Fatal("a failed delivery reported success")
	}
}

// ---------------------------------------------------------------------------
// React — the durable path
// ---------------------------------------------------------------------------

func TestReactStartsOneWorkflowPerDelivery(t *testing.T) {
	t.Parallel()
	issuer, dispatcher := &stubIssuer{}, &recordingDispatcher{}
	starter := &recordingStarter{}

	if err := build(t, issuer, dispatcher, WithWorkflows(starter)).React(
		context.Background(), requestedEnvelope(t, testSubject)); err != nil {
		t.Fatalf("React: %v", err)
	}

	if len(dispatcher.sent) != 0 {
		t.Error("delivered inline while a workflow starter was wired; the send would " +
			"happen twice, and the reactor would own a retry the workflow already has")
	}
	if len(starter.starts) != 1 {
		t.Fatalf("started %d workflows, want 1", len(starter.starts))
	}
	start := starter.starts[0]

	if start.Name != notify.SendNotificationWorkflow {
		t.Errorf("workflow %q, want %q", start.Name, notify.SendNotificationWorkflow)
	}
	if want := testEventID + ":" + issuer.issued[0].Fingerprint; start.ID != want {
		t.Errorf("workflow id %q, want %q — derived from the event AND the token, so a "+
			"redelivery carrying a fresh token is not refused as a duplicate",
			start.ID, want)
	}
	if err := start.Validate(); err != nil {
		t.Errorf("the start is invalid: %v", err)
	}

	in, ok := start.Input.(notify.SendNotificationInput)
	if !ok {
		t.Fatalf("workflow input is %T, want notify.SendNotificationInput", start.Input)
	}
	if in.SubjectID != testSubject {
		t.Errorf("input subject %q, want %q", in.SubjectID, testSubject)
	}
	if in.Data["Token"] != issuer.issued[0].Plaintext {
		t.Error("the workflow carries no token; the activity would render a dead link")
	}
	// History is durable and replicated. Whatever else it holds, it must not hold
	// an address (ADR-002) — the activity resolves that from the vault.
	if strings.Contains(fmt.Sprintf("%+v", in), "@") {
		t.Errorf("workflow input looks like it carries an address: %+v", in)
	}
}

// Refused as a duplicate is SUCCESS: a run under this id exists, and because the
// id names this token, that run is delivering exactly what this call wanted.
func TestReactTreatsAnAlreadyStartedRunAsDelivered(t *testing.T) {
	t.Parallel()
	starter := &recordingStarter{err: workflow.ErrAlreadyStarted}

	if err := build(t, &stubIssuer{}, &recordingDispatcher{}, WithWorkflows(starter)).React(
		context.Background(), requestedEnvelope(t, testSubject)); err != nil {
		t.Fatalf("an already-running delivery was reported as a failure: %v", err)
	}
}

func TestReactReturnsAFailedStart(t *testing.T) {
	t.Parallel()
	starter := &recordingStarter{err: workflow.ErrUnavailable}

	if err := build(t, &stubIssuer{}, &recordingDispatcher{}, WithWorkflows(starter)).React(
		context.Background(), requestedEnvelope(t, testSubject)); err == nil {
		t.Fatal("a start that did not happen was acked; the token would reach nobody")
	}
}

// ---------------------------------------------------------------------------
// React — events it must not act on
// ---------------------------------------------------------------------------

func TestReactIgnoresAnotherEventType(t *testing.T) {
	t.Parallel()
	issuer, dispatcher := &stubIssuer{}, &recordingDispatcher{}

	env := requestedEnvelope(t, testSubject)
	env.Type = "identity.PasswordChanged.v1"

	if err := build(t, issuer, dispatcher).React(context.Background(), env); err != nil {
		t.Fatalf("React: %v", err)
	}
	if len(issuer.calls) != 0 || len(dispatcher.sent) != 0 {
		t.Error("minted or mailed for an event this reactor does not handle")
	}
}

func TestReactParksWhatCanNeverSucceed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		env  func(*testing.T) eventsourcing.Envelope
	}{
		{
			name: "undecodable payload",
			env: func(t *testing.T) eventsourcing.Envelope {
				env := requestedEnvelope(t, testSubject)
				env.Payload = []byte(`{"SubjectID":`)
				return env
			},
		},
		{
			name: "no subject",
			env: func(t *testing.T) eventsourcing.Envelope {
				return requestedEnvelope(t, "")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			issuer, dispatcher := &stubIssuer{}, &recordingDispatcher{}

			err := build(t, issuer, dispatcher).React(context.Background(), tt.env(t))
			if !errors.Is(err, eventsourcing.ErrPoison) {
				t.Fatalf("error is %v, want poison: retrying re-reads the same bytes, "+
					"and a silent skip is a verification nobody ever receives", err)
			}
			if len(issuer.calls) != 0 || len(dispatcher.sent) != 0 {
				t.Error("minted or mailed for an event that can never be delivered")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Wording
// ---------------------------------------------------------------------------

func TestHumanize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   time.Duration
		want string
	}{
		{"verification ttl", 24 * time.Hour, "24 hours"},
		{"reset ttl", time.Hour, "60 minutes"},
		{"multi-day", 72 * time.Hour, "3 days"},
		{"quarter hour", 15 * time.Minute, "15 minutes"},
		{"sub-minute", 30 * time.Second, "a few minutes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := humanize(tt.in); got != tt.want {
				t.Errorf("humanize(%s) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
