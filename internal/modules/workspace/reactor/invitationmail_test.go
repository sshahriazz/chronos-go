package reactor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/modules/workspace"
	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/workflow"
)

const (
	testInvitation = "inv_01H8XG5N2QK7VB3C9WPYZR4TFN"
	testOrg        = "org_01H8XG5N2QK7VB3C9WPYZR4TFM"
	testWorkspace  = "ws_01H8XG5N2QK7VB3C9WPYZR4TFK"
	testSubject    = "subj_01H8XG5N2QK7VB3C9WPYZR4TFP"
)

var testNow = time.Date(2026, 3, 14, 9, 26, 0, 0, time.UTC)

// ---------------------------------------------------------------------------
// doubles
// ---------------------------------------------------------------------------

// stubIssuer answers with a distinct link per call, so a test can tell one
// delivery's credential from another's.
type stubIssuer struct {
	calls []string
	err   error
	ttl   time.Duration
}

func (s *stubIssuer) IssueLink(_ context.Context, invitationID, orgID string) (Link, error) {
	s.calls = append(s.calls, invitationID+"@"+orgID)
	if s.err != nil {
		return Link{}, s.err
	}
	ttl := s.ttl
	if ttl == 0 {
		ttl = 7 * 24 * time.Hour
	}
	return Link{
		Plaintext:   fmt.Sprintf("token-%d", len(s.calls)),
		TTL:         ttl,
		Fingerprint: fmt.Sprintf("fingerprint%d", len(s.calls)),
	}, nil
}

type stubDispatcher struct {
	sent []notify.Notification
	err  error
}

func (s *stubDispatcher) Dispatch(_ context.Context, n notify.Notification) error {
	if s.err != nil {
		return s.err
	}
	s.sent = append(s.sent, n)
	return nil
}

type stubStarter struct {
	started []workflow.Start
	err     error
}

func (s *stubStarter) Start(_ context.Context, w workflow.Start) (workflow.Run, error) {
	s.started = append(s.started, w)
	if s.err != nil {
		return workflow.Run{}, s.err
	}
	return workflow.Run{ID: w.ID}, nil
}

func testCodec(t *testing.T) *eventcodec.JSON {
	t.Helper()
	upcasters := eventsourcing.NewUpcasterRegistry()
	workspace.RegisterSchemas(upcasters)
	codec := eventcodec.NewJSON(upcasters)
	workspace.RegisterEvents(codec)
	return codec
}

func envelopeFor(t *testing.T, codec *eventcodec.JSON, e eventsourcing.Event) eventsourcing.Envelope {
	t.Helper()
	payload, err := codec.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return eventsourcing.Envelope{
		ID:      ids.New[ids.Event](testNow, ids.Entropy()),
		Type:    e.EventType(),
		Payload: payload,
		Meta: eventsourcing.Metadata{
			OrgID: testOrg, WorkspaceID: testWorkspace, OccurredAt: testNow,
		},
		Live: true,
	}
}

func issuedEnvelope(t *testing.T, codec *eventcodec.JSON) eventsourcing.Envelope {
	t.Helper()
	return envelopeFor(t, codec, &contract.InvitationIssued{
		InvitationID: testInvitation, WorkspaceID: testWorkspace, OrgID: testOrg,
		SubjectID: testSubject, EmailIndex: "idx", InvitedBy: "subj_inviter",
		Role: contract.RoleMember, SeatConsumed: true,
		ExpiresAt: testNow.Add(7 * 24 * time.Hour), IssuedAt: testNow,
	})
}

func newMail(t *testing.T, issuer Issuer, d Dispatcher, opts ...Option) *InvitationMail {
	t.Helper()
	r, err := NewInvitationMail(issuer, testCodec(t), d, opts...)
	if err != nil {
		t.Fatalf("NewInvitationMail: %v", err)
	}
	return r
}

// ---------------------------------------------------------------------------
// the mail
// ---------------------------------------------------------------------------

// AN ISSUED INVITATION MINTS A LINK AND SENDS IT.
//
// Without this reactor the event is consumed by nothing: a seat is spent, the
// invitation sits pending for seven days, and the person it was for never learns
// it exists. There is no error, no parked event and no metric — which is why the
// assertion is that a mail was DISPATCHED rather than that nothing failed.
func TestAnIssuedInvitationIsMailed(t *testing.T) {
	issuer, dispatch := &stubIssuer{}, &stubDispatcher{}
	codec := testCodec(t)
	r := newMail(t, issuer, dispatch)

	if err := r.React(context.Background(), issuedEnvelope(t, codec)); err != nil {
		t.Fatalf("reacting: %v", err)
	}

	if len(issuer.calls) != 1 {
		t.Fatalf("minted %d links, want 1", len(issuer.calls))
	}
	if issuer.calls[0] != testInvitation+"@"+testOrg {
		t.Errorf("minted for %q", issuer.calls[0])
	}
	if len(dispatch.sent) != 1 {
		t.Fatalf("dispatched %d notifications, want 1", len(dispatch.sent))
	}

	n := dispatch.sent[0]
	if n.Template != InvitationTemplate {
		t.Errorf("template %q, want %q", n.Template, InvitationTemplate)
	}
	if n.Data["Token"] != "token-1" {
		t.Errorf("the mail carries %v, not the minted link", n.Data["Token"])
	}
	if n.Recipient.SubjectID != testSubject {
		t.Errorf("addressed to %q, want the invitee", n.Recipient.SubjectID)
	}
}

// A RESEND MAILS TOO.
//
// InvitationTokenRotated is the same job — mail a fresh link — and the reactor
// takes the same path. A filter or a switch that named only the issue would make
// every resend a button that does nothing, which is indistinguishable from a
// mail that was sent and lost.
func TestAResendIsMailed(t *testing.T) {
	issuer, dispatch := &stubIssuer{}, &stubDispatcher{}
	codec := testCodec(t)
	r := newMail(t, issuer, dispatch)

	env := envelopeFor(t, codec, &contract.InvitationTokenRotated{
		InvitationID: testInvitation, WorkspaceID: testWorkspace, OrgID: testOrg,
		SubjectID: testSubject, ExpiresAt: testNow.Add(7 * 24 * time.Hour), RotatedAt: testNow,
	})
	if err := r.React(context.Background(), env); err != nil {
		t.Fatalf("reacting: %v", err)
	}
	if len(dispatch.sent) != 1 {
		t.Fatalf("a resend dispatched %d notifications; the button does nothing and "+
			"nothing says so", len(dispatch.sent))
	}
}

// THE FILTER NAMES BOTH EVENTS AND NOTHING ELSE.
//
// An invitation's stream also carries five settlements. A category-prefix filter
// would wake this reactor for all of them, and it would be one missing branch
// away from mailing a live link when an invitation is REVOKED.
func TestTheFilterNamesOnlyTheTwoSendingEvents(t *testing.T) {
	r := newMail(t, &stubIssuer{}, &stubDispatcher{})
	got := r.Filter().EventTypePrefixes

	want := map[string]bool{
		(&contract.InvitationIssued{}).EventType():       true,
		(&contract.InvitationTokenRotated{}).EventType(): true,
	}
	if len(got) != len(want) {
		t.Fatalf("the filter names %v; anything more wakes this reactor for settlements", got)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("the filter names %q, which is not a sending event", p)
		}
	}
}

// A SETTLEMENT THAT REACHES React MAILS NOTHING.
//
// The filter should stop it, but a group created before the filter existed
// delivers everything on its streams. Reacting to whatever arrives would mail a
// live link for an invitation that was just revoked — the exact opposite of what
// the revocation meant.
func TestASettlementIsIgnored(t *testing.T) {
	issuer, dispatch := &stubIssuer{}, &stubDispatcher{}
	codec := testCodec(t)
	r := newMail(t, issuer, dispatch)

	env := envelopeFor(t, codec, &contract.InvitationRevoked{
		InvitationID: testInvitation, WorkspaceID: testWorkspace, OrgID: testOrg,
		SubjectID: testSubject, RevokedBy: "subj_admin", SeatReleased: true, RevokedAt: testNow,
	})
	if err := r.React(context.Background(), env); err != nil {
		t.Fatalf("an over-delivered settlement was an error rather than a no-op: %v", err)
	}
	if len(issuer.calls) != 0 {
		t.Fatal("a revocation minted a link; the invitation was deliberately withdrawn and " +
			"a fresh credential was just mailed for it")
	}
	if len(dispatch.sent) != 0 {
		t.Fatalf("a revocation dispatched %d notifications", len(dispatch.sent))
	}
}

// THE DELIVERY IS KEYED BY THE LINK, NOT ONLY THE EVENT.
//
// A rerun mints a second link and voids the first, so the two runs carry
// different credentials and are different deliveries. Keying on the event id
// alone makes the second a duplicate — refused as already done — and the only
// mail ever sent is the one carrying the DEAD link.
func TestTheDeliveryKeyChangesWithTheLink(t *testing.T) {
	issuer, dispatch := &stubIssuer{}, &stubDispatcher{}
	codec := testCodec(t)
	r := newMail(t, issuer, dispatch)

	env := issuedEnvelope(t, codec)
	for range 2 {
		if err := r.React(context.Background(), env); err != nil {
			t.Fatal(err)
		}
	}
	if len(dispatch.sent) != 2 {
		t.Fatalf("dispatched %d, want 2", len(dispatch.sent))
	}

	first, second := dispatch.sent[0].IdempotencyKey, dispatch.sent[1].IdempotencyKey
	if first == second {
		t.Fatalf("both runs used the key %q. The second run voided the first run's link, "+
			"so the only mail that is not a duplicate carries a link that no longer works",
			first)
	}
	if !strings.HasPrefix(first, env.ID.String()) {
		t.Errorf("the key %q does not name the event; a rerun that somehow reached the "+
			"same link would then not deduplicate", first)
	}
}

// THE LINK GOES BY EMAIL ONLY.
//
// A security control, not a preference. In-app delivery appends it to the
// notification feed's event stream and projects it into a Postgres row; web push
// hands it to a browser endpoint. Both are durable places a live credential may
// not go — and email is the only channel that can work anyway, since the invitee
// may have no account.
func TestTheLinkGoesByEmailOnly(t *testing.T) {
	dispatch := &stubDispatcher{}
	codec := testCodec(t)
	r := newMail(t, &stubIssuer{}, dispatch)

	if err := r.React(context.Background(), issuedEnvelope(t, codec)); err != nil {
		t.Fatal(err)
	}
	channels := dispatch.sent[0].Channels
	if len(channels) != 1 || channels[0] != notify.ChannelEmail {
		t.Fatalf("the link is delivered over %v; anything but email puts a live credential "+
			"in a durable store", channels)
	}
}

// NO ADDRESS TRAVELS WITH THE NOTIFICATION.
//
// The recipient is a pseudonym and the dispatcher resolves the address from the
// vault immediately before sending, so it never passes through this reactor, the
// event, or a workflow's history (ADR-002).
func TestTheNotificationCarriesNoAddress(t *testing.T) {
	dispatch := &stubDispatcher{}
	codec := testCodec(t)
	r := newMail(t, &stubIssuer{}, dispatch)

	if err := r.React(context.Background(), issuedEnvelope(t, codec)); err != nil {
		t.Fatal(err)
	}
	n := dispatch.sent[0]
	for key, value := range n.Data {
		if s, ok := value.(string); ok && strings.Contains(s, "@") {
			t.Errorf("Data[%q] = %q, which looks like an address", key, s)
		}
	}
	if n.Recipient.SubjectID == "" {
		t.Error("no pseudonym reached the dispatcher, so the vault has nothing to resolve")
	}
}

// A FAILED DELIVERY IS REPORTED, so the event is redelivered.
//
// Acking here leaves a live link nobody was told about and a seat spent on
// somebody who never hears from us. The redelivery's first act is to void that
// orphan, so it lives until the next attempt and at worst until its own expiry.
func TestAFailedDeliveryIsReported(t *testing.T) {
	codec := testCodec(t)
	r := newMail(t, &stubIssuer{}, &stubDispatcher{err: errors.New("smtp: down")})

	if err := r.React(context.Background(), issuedEnvelope(t, codec)); err == nil {
		t.Fatal("a failed delivery was acked; the link is live, the seat is spent, and " +
			"nobody was told")
	}
}

// A FAILED MINT IS REPORTED and dispatches nothing.
func TestAFailedMintDispatchesNothing(t *testing.T) {
	dispatch := &stubDispatcher{}
	codec := testCodec(t)
	r := newMail(t, &stubIssuer{err: errors.New("postgres: down")}, dispatch)

	if err := r.React(context.Background(), issuedEnvelope(t, codec)); err == nil {
		t.Fatal("a failed mint was acked")
	}
	if len(dispatch.sent) != 0 {
		t.Fatal("a mail was sent with no link in it")
	}
}

// AN EVENT NAMING NO SUBJECT IS POISON, not a retry.
//
// Retrying re-reads the same bytes. Parked, it is visible as an invitation that
// never went out; retried forever, it is a queue that never drains and a reactor
// that looks busy.
func TestAnEventWithNoSubjectIsPoison(t *testing.T) {
	codec := testCodec(t)
	r := newMail(t, &stubIssuer{}, &stubDispatcher{})

	env := envelopeFor(t, codec, &contract.InvitationIssued{
		InvitationID: testInvitation, WorkspaceID: testWorkspace, OrgID: testOrg,
		Role: contract.RoleMember, ExpiresAt: testNow.Add(time.Hour), IssuedAt: testNow,
	})
	err := r.React(context.Background(), env)
	if err == nil {
		t.Fatal("an invitation with no subject was mailed to nobody and acked")
	}
	if !errors.Is(err, eventsourcing.ErrPoison) {
		t.Errorf("reported %v; retrying re-reads the same bytes, so this must park", err)
	}
}

// UNDECODABLE BYTES ARE POISON TOO.
func TestUndecodableBytesArePoison(t *testing.T) {
	r := newMail(t, &stubIssuer{}, &stubDispatcher{})

	env := eventsourcing.Envelope{
		ID:      ids.New[ids.Event](testNow, ids.Entropy()),
		Type:    (&contract.InvitationIssued{}).EventType(),
		Payload: []byte("{not json"),
		Meta:    eventsourcing.Metadata{OrgID: testOrg, OccurredAt: testNow},
	}
	err := r.React(context.Background(), env)
	if !errors.Is(err, eventsourcing.ErrPoison) {
		t.Errorf("reported %v; an event that cannot be decoded never will be", err)
	}
}

// ---------------------------------------------------------------------------
// durable delivery
// ---------------------------------------------------------------------------

// WITH A STARTER, DELIVERY GOES THROUGH A WORKFLOW and not inline.
//
// The two are indistinguishable from outside until a transport fails, which is
// why Durable() exists and why this asserts on the starter rather than on
// behaviour.
func TestWithWorkflowsStartsAWorkflow(t *testing.T) {
	starter, dispatch := &stubStarter{}, &stubDispatcher{}
	codec := testCodec(t)
	r := newMail(t, &stubIssuer{}, dispatch, WithWorkflows(starter))

	if !r.Durable() {
		t.Fatal("Durable() is false with a starter wired")
	}
	if err := r.React(context.Background(), issuedEnvelope(t, codec)); err != nil {
		t.Fatal(err)
	}
	if len(starter.started) != 1 {
		t.Fatalf("started %d workflows, want 1", len(starter.started))
	}
	if len(dispatch.sent) != 0 {
		t.Fatal("the mail went out inline AS WELL as through the workflow, so a retry " +
			"sends it twice")
	}
	if starter.started[0].Name != notify.SendNotificationWorkflow {
		t.Errorf("started %q", starter.started[0].Name)
	}
}

// AN ALREADY-STARTED RUN IS SUCCESS.
//
// The id contains the link's fingerprint, so a run under it carries THIS link —
// the work is already running or already done. Treating it as an error parks an
// event whose mail was sent perfectly.
func TestAnAlreadyStartedRunIsNotAnError(t *testing.T) {
	starter := &stubStarter{err: workflow.ErrAlreadyStarted}
	codec := testCodec(t)
	r := newMail(t, &stubIssuer{}, &stubDispatcher{}, WithWorkflows(starter))

	if err := r.React(context.Background(), issuedEnvelope(t, codec)); err != nil {
		t.Fatalf("an already-started run was reported as a failure: %v\nThe event parks "+
			"even though its mail went out", err)
	}
}

// A FAILED START IS REPORTED.
func TestAFailedStartIsReported(t *testing.T) {
	starter := &stubStarter{err: errors.New("temporal: unavailable")}
	codec := testCodec(t)
	r := newMail(t, &stubIssuer{}, &stubDispatcher{}, WithWorkflows(starter))

	if err := r.React(context.Background(), issuedEnvelope(t, codec)); err == nil {
		t.Fatal("a workflow that did not start was acked, so the link is live and nobody " +
			"was told")
	}
}

// ---------------------------------------------------------------------------
// wiring
// ---------------------------------------------------------------------------

// EVERY DEPENDENCY IS REQUIRED.
//
// A nil issuer or dispatcher produces a reactor that consumes the event, does
// nothing, and acks — indistinguishable at runtime from the gap this package
// exists to close.
func TestNewInvitationMailRefusesAMissingDependency(t *testing.T) {
	codec := testCodec(t)
	if _, err := NewInvitationMail(&stubIssuer{}, codec, &stubDispatcher{}); err != nil {
		t.Fatalf("precondition: a complete wiring was refused: %v", err)
	}

	tests := []struct {
		name     string
		issuer   Issuer
		codec    eventsourcing.Codec
		dispatch Dispatcher
	}{
		{"no issuer", nil, codec, &stubDispatcher{}},
		{"no codec", &stubIssuer{}, nil, &stubDispatcher{}},
		{"no dispatcher", &stubIssuer{}, codec, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewInvitationMail(tt.issuer, tt.codec, tt.dispatch); err == nil {
				t.Fatalf("constructed with %s", tt.name)
			}
		})
	}
}

// THE GROUP NAME AND THE TEMPLATE ARE PERMANENT.
//
// Renaming the group creates a fresh one positioned at the END of the log,
// silently abandoning every invitation the old group had not yet mailed
// (ADR-019). The template name appears in metrics, operator overrides and the
// X-Chronos-Template header.
func TestNamesArePermanent(t *testing.T) {
	if InvitationReactorName != "workspace-invitation-mail" {
		t.Errorf("the subscription group is now %q; the old group's unsent backlog is "+
			"abandoned at the end of the log", InvitationReactorName)
	}
	if InvitationTemplate != "workspace.invitation" {
		t.Errorf("the template is now %q; operator overrides and metrics both key on it",
			InvitationTemplate)
	}
	r := newMail(t, &stubIssuer{}, &stubDispatcher{})
	if r.Name() != InvitationReactorName {
		t.Errorf("Name() is %q", r.Name())
	}
}
