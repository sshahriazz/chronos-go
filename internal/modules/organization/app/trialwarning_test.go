package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/organization/app"
	"github.com/chronos/chronos-go/internal/modules/organization/contract"
	"github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// ---------------------------------------------------------------------------
// the smallest event store that can hold one organization, WITH its metadata
// ---------------------------------------------------------------------------
//
// Keeping the metadata is the point of writing one here rather than reusing a
// simpler fake. The property this file exists to prove — that the warning names
// the OWNER, so the mail reaches somebody — lives entirely in Metadata.SubjectIDs,
// and a store that drops metadata makes it unfalsifiable.

type orgStore struct {
	streams  map[eventsourcing.StreamID][]eventsourcing.RecordedEvent
	metas    map[eventsourcing.StreamID][]eventsourcing.Metadata
	appends  int
	failWith error
}

func newOrgStore() *orgStore {
	return &orgStore{
		streams: map[eventsourcing.StreamID][]eventsourcing.RecordedEvent{},
		metas:   map[eventsourcing.StreamID][]eventsourcing.Metadata{},
	}
}

func (s *orgStore) Append(
	_ context.Context, stream eventsourcing.StreamID,
	expected eventsourcing.ExpectedRevision, events []eventsourcing.PendingEvent,
) (eventsourcing.AppendResult, error) {
	if s.failWith != nil {
		return eventsourcing.AppendResult{}, s.failWith
	}
	existing := s.streams[stream]
	if rev, ok := expected.Exact(); ok && rev != eventsourcing.Revision(len(existing))-1 {
		return eventsourcing.AppendResult{}, eventsourcing.ErrWrongExpectedRevision
	}
	s.appends++
	for _, pe := range events {
		payload, err := codec.Marshal(pe.Event)
		if err != nil {
			return eventsourcing.AppendResult{}, err
		}
		existing = append(existing, eventsourcing.RecordedEvent{
			ID: pe.ID, Type: pe.Event.EventType(), Stream: stream,
			Revision: eventsourcing.Revision(len(existing)), Payload: payload,
		})
		s.metas[stream] = append(s.metas[stream], pe.Meta)
	}
	s.streams[stream] = existing
	return eventsourcing.AppendResult{Revision: eventsourcing.Revision(len(existing) - 1)}, nil
}

func (s *orgStore) ReadStream(
	_ context.Context, stream eventsourcing.StreamID, from eventsourcing.Revision,
) ([]eventsourcing.RecordedEvent, error) {
	all, ok := s.streams[stream]
	if !ok {
		return nil, eventsourcing.ErrStreamNotFound
	}
	if int(from) >= len(all) {
		return nil, nil
	}
	return all[from:], nil
}

func (s *orgStore) AppendToMany(
	ctx context.Context, appends []eventsourcing.StreamAppend,
) ([]eventsourcing.AppendResult, error) {
	out := make([]eventsourcing.AppendResult, 0, len(appends))
	for _, a := range appends {
		res, err := s.Append(ctx, a.Stream, a.Expected, a.Events)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// events returns what was appended to one organization's stream.
func (s *orgStore) events(orgID string) []eventsourcing.RecordedEvent {
	return s.streams[eventsourcing.StreamID(domain.Category)+"-"+eventsourcing.StreamID(domain.StreamKey(orgID))]
}

// meta returns the metadata of the nth event on one organization's stream.
func (s *orgStore) meta(orgID string, n int) eventsourcing.Metadata {
	all := s.metas[eventsourcing.StreamID(domain.Category)+"-"+eventsourcing.StreamID(domain.StreamKey(orgID))]
	if n >= len(all) {
		return eventsourcing.Metadata{}
	}
	return all[n]
}

type orgCodec struct{}

func (orgCodec) Marshal(e eventsourcing.Event) ([]byte, error) { return codec.Marshal(e) }

func (orgCodec) Unmarshal(eventType string, payload []byte) (eventsourcing.Event, error) {
	switch eventType {
	case (&contract.OrganizationCreated{}).EventType():
		return decodeOrg[contract.OrganizationCreated](payload)
	case (&contract.OrganizationTrialStarted{}).EventType():
		return decodeOrg[contract.OrganizationTrialStarted](payload)
	case (&contract.OrganizationTrialEndingSoon{}).EventType():
		return decodeOrg[contract.OrganizationTrialEndingSoon](payload)
	case (&contract.OrganizationActivated{}).EventType():
		return decodeOrg[contract.OrganizationActivated](payload)
	case (&contract.OrganizationSuspended{}).EventType():
		return decodeOrg[contract.OrganizationSuspended](payload)
	}
	// A HARD ERROR, never (nil, nil). A codec that silently skips an unknown
	// type replays an aggregate as though the event never happened — a warned
	// organization reads back as unwarned, and every idempotency assertion in
	// this file would pass for the wrong reason.
	return nil, errors.New("orgCodec: unregistered event type " + eventType)
}

func decodeOrg[T any, P interface {
	*T
	eventsourcing.Event
}](payload []byte) (eventsourcing.Event, error) {
	// Tolerant, like the real codec: an event read back from the log may carry
	// members this build does not know (ADR-047).
	v, err := codec.Tolerant[T](payload)
	if err != nil {
		return nil, err
	}
	return P(&v), nil
}

func (orgCodec) MarshalMetadata(eventsourcing.Metadata) ([]byte, error) { return nil, nil }
func (orgCodec) UnmarshalMetadata([]byte) (eventsourcing.Metadata, error) {
	return eventsourcing.Metadata{}, nil
}

// ---------------------------------------------------------------------------

const (
	warnOrg   = "org_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	warnOwner = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV"
)

var (
	warnNow   = time.Date(2026, 3, 11, 9, 0, 0, 0, time.UTC)
	trialEnds = time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)
)

type warnHarness struct {
	warnings *app.TrialWarnings
	store    *orgStore
	repo     *eventsourcing.Repository[*domain.Organization]
}

// newWarnHarness builds a trialing organization with an owner.
func newWarnHarness(t *testing.T) *warnHarness {
	t.Helper()
	store := newOrgStore()
	repo := eventsourcing.NewRepository[*domain.Organization](
		store, orgCodec{}, nil, domain.Category, domain.NewOrganization)

	org, err := repo.Load(context.Background(), domain.StreamKey(warnOrg))
	if err != nil {
		t.Fatal(err)
	}
	if err := org.Create(warnOrg, "Acme", "acme", warnOwner, warnNow.Add(-14*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := org.StartTrial("cus_1", "sub_1", trialEnds, warnNow.Add(-14*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Save(context.Background(), domain.StreamKey(warnOrg), org, "seed",
		eventsourcing.Metadata{OrgID: warnOrg, OccurredAt: warnNow}); err != nil {
		t.Fatal(err)
	}

	warnings, err := app.NewTrialWarnings(app.TrialWarningsDeps{
		Repo: repo, Now: func() time.Time { return warnNow },
	})
	if err != nil {
		t.Fatalf("NewTrialWarnings: %v", err)
	}
	return &warnHarness{warnings: warnings, store: store, repo: repo}
}

func (h *warnHarness) warned() int {
	var n int
	for _, e := range h.store.events(warnOrg) {
		if e.Type == (&contract.OrganizationTrialEndingSoon{}).EventType() {
			n++
		}
	}
	return n
}

// THE WARNING NAMES THE OWNER, AND WITHOUT THAT IT REACHES NOBODY.
//
// The notification reactor resolves AudienceSubject from the envelope's
// SubjectIDs and nothing else. An event appended without one produces an EMPTY
// recipient list, which the dispatcher treats as "nobody to tell" rather than as
// an error — so the warning would be recorded, the catalogue entry would look
// correct, every test below this layer would pass, and no mail would ever be
// sent. For a cardless trial that is the only warning there is.
func TestTheTrialWarningNamesTheOwner(t *testing.T) {
	h := newWarnHarness(t)

	if err := h.warnings.Warn(context.Background(), warnOrg, trialEnds, "evt_1"); err != nil {
		t.Fatal(err)
	}
	if h.warned() != 1 {
		t.Fatalf("appended %d warnings, want 1", h.warned())
	}

	// The warning is the second event on the stream: created, trial started,
	// warned — so index 2.
	meta := h.store.meta(warnOrg, 2)
	if len(meta.SubjectIDs) != 1 || meta.SubjectIDs[0] != warnOwner {
		t.Fatalf("the warning's SubjectIDs are %v, want [%s]. AudienceSubject reads exactly "+
			"this field, so an empty one means the warning is recorded and NEVER SENT — and "+
			"for a cardless trial it is the only warning there is",
			meta.SubjectIDs, warnOwner)
	}
	if meta.OrgID != warnOrg {
		t.Errorf("the warning's OrgID is %q", meta.OrgID)
	}
}

// THE EVENT CARRIES THE DEADLINE STRIPE REPORTED.
//
// The mail states a date. A date computed here rather than taken from the
// re-fetched subscription could differ from the one the subscription actually
// enforces, which is a support ticket beginning "your email said the 14th".
func TestTheWarningCarriesStripesDeadline(t *testing.T) {
	h := newWarnHarness(t)

	if err := h.warnings.Warn(context.Background(), warnOrg, trialEnds, "evt_1"); err != nil {
		t.Fatal(err)
	}
	events := h.store.events(warnOrg)
	warning, err := codec.Tolerant[contract.OrganizationTrialEndingSoon](
		events[len(events)-1].Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !warning.TrialEndsAt.Equal(trialEnds) {
		t.Errorf("the warning says %v, want Stripe's %v", warning.TrialEndsAt, trialEnds)
	}
}

// A REDELIVERY WARNS ONCE.
//
// Stripe retries by design, and this endpoint has no way to know which delivery
// it is. Three mails saying "your trial ends in three days" is how a customer
// learns to filter mail from us.
func TestARedeliveredTrialWarningMailsOnce(t *testing.T) {
	h := newWarnHarness(t)
	ctx := context.Background()

	for range 3 {
		if err := h.warnings.Warn(ctx, warnOrg, trialEnds, "evt_1"); err != nil {
			t.Fatal(err)
		}
	}
	if got := h.warned(); got != 1 {
		t.Fatalf("appended %d warnings for one Stripe event, want 1; the customer gets %d "+
			"identical mails", got, got)
	}
}

// AN EXTENDED TRIAL WARNS AGAIN.
//
// Stripe permits moving `trial_end`, and it then emits a fresh `trial_will_end`
// for the NEW date. A boolean "already warned" would warn about the old deadline
// and never about the real one — the customer is told the wrong date once and
// then locked out with no warning at all.
func TestAnExtendedTrialIsWarnedAboutAgain(t *testing.T) {
	h := newWarnHarness(t)
	ctx := context.Background()

	if err := h.warnings.Warn(ctx, warnOrg, trialEnds, "evt_1"); err != nil {
		t.Fatal(err)
	}
	extended := trialEnds.Add(7 * 24 * time.Hour)
	if err := h.warnings.Warn(ctx, warnOrg, extended, "evt_2"); err != nil {
		t.Fatal(err)
	}

	if got := h.warned(); got != 2 {
		t.Fatalf("appended %d warnings, want 2; an extended trial's real deadline was never "+
			"announced", got)
	}
	events := h.store.events(warnOrg)
	latest, err := codec.Tolerant[contract.OrganizationTrialEndingSoon](
		events[len(events)-1].Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !latest.TrialEndsAt.Equal(extended) {
		t.Errorf("the second warning says %v, want the extended %v", latest.TrialEndsAt, extended)
	}
}

// AN EARLIER DEADLINE DOES NOT RE-WARN.
//
// Stripe does not guarantee ordering, so a `trial_will_end` for the ORIGINAL
// deadline can arrive after one for the extended date. Warning again would tell
// the customer their trial ends sooner than it does.
func TestAStaleDeadlineDoesNotWarnAgain(t *testing.T) {
	h := newWarnHarness(t)
	ctx := context.Background()

	extended := trialEnds.Add(7 * 24 * time.Hour)
	if err := h.warnings.Warn(ctx, warnOrg, extended, "evt_2"); err != nil {
		t.Fatal(err)
	}
	if err := h.warnings.Warn(ctx, warnOrg, trialEnds, "evt_1"); err != nil {
		t.Fatal(err)
	}

	if got := h.warned(); got != 1 {
		t.Fatalf("appended %d warnings, want 1; an out-of-order webhook told the customer "+
			"their trial ends sooner than it does", got)
	}
}

// A CONVERTED ORGANIZATION IS NOT WARNED.
//
// `trial_will_end` fires three days out and the customer may add a card the next
// day. The webhook is still delivered. Warning a paying customer that they are
// about to lose access is worse than silence.
func TestAConvertedOrganizationIsNotWarned(t *testing.T) {
	h := newWarnHarness(t)
	ctx := context.Background()

	org, err := h.repo.Load(ctx, domain.StreamKey(warnOrg))
	if err != nil {
		t.Fatal(err)
	}
	if err := org.Activate(warnNow); err != nil {
		t.Fatal(err)
	}
	if _, err := h.repo.Save(ctx, domain.StreamKey(warnOrg), org, "converted",
		eventsourcing.Metadata{OrgID: warnOrg, OccurredAt: warnNow}); err != nil {
		t.Fatal(err)
	}

	if err := h.warnings.Warn(ctx, warnOrg, trialEnds, "evt_1"); err != nil {
		t.Fatalf("a stale warning errored: %v; the webhook is redelivered forever", err)
	}
	if h.warned() != 0 {
		t.Error("a paying customer was warned they are about to lose access")
	}
}

// AN UNKNOWN ORGANIZATION IS POISON.
//
// A subscription whose metadata names an organization with no events. Retrying
// re-reads the same object, so it would park forever.
func TestAWarningForAnUnknownOrganizationIsPoison(t *testing.T) {
	h := newWarnHarness(t)

	err := h.warnings.Warn(context.Background(),
		"org_01ARZ3NDEKTSV4RRFFQ69G5FBB", trialEnds, "evt_1")
	if !errors.Is(err, eventsourcing.ErrPoison) {
		t.Fatalf("returned %v, want ErrPoison", err)
	}
}

// A WARNING WITH NO DEADLINE IS POISON, NOT A MAIL WITH A BLANK DATE.
func TestAWarningWithNoDeadlineIsPoison(t *testing.T) {
	h := newWarnHarness(t)

	err := h.warnings.Warn(context.Background(), warnOrg, time.Time{}, "evt_1")
	if !errors.Is(err, eventsourcing.ErrPoison) {
		t.Fatalf("returned %v, want ErrPoison; the mail states a date and there is none", err)
	}
	if h.warned() != 0 {
		t.Error("a warning with no deadline was recorded")
	}
}

// BOTH IDENTIFIERS ARE REQUIRED.
func TestAWarningNeedsAnOrganizationAndAnEventID(t *testing.T) {
	h := newWarnHarness(t)
	ctx := context.Background()

	if err := h.warnings.Warn(ctx, "", trialEnds, "evt_1"); err == nil {
		t.Error("a warning with no organization was accepted")
	}
	if err := h.warnings.Warn(ctx, warnOrg, trialEnds, ""); err == nil {
		t.Error("a warning with no event id was accepted; two deliveries would derive " +
			"different event ids and both would land")
	}
	if h.warned() != 0 {
		t.Error("an incomplete warning was recorded")
	}
}

// AN INCOMPLETE WIRING IS REFUSED AT CONSTRUCTION.
func TestTrialWarningsRefusesAnIncompleteWiring(t *testing.T) {
	if _, err := app.NewTrialWarnings(app.TrialWarningsDeps{
		Now: func() time.Time { return warnNow },
	}); err == nil {
		t.Error("a use case with no repository was accepted")
	}
	if _, err := app.NewTrialWarnings(app.TrialWarningsDeps{
		Repo: eventsourcing.NewRepository[*domain.Organization](
			newOrgStore(), orgCodec{}, nil, domain.Category, domain.NewOrganization),
	}); err == nil {
		t.Error("a use case with no clock was accepted")
	}
}
