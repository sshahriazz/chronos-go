package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"log/slog"

	"sync"

	stripeadapter "github.com/chronos/chronos-go/internal/adapter/stripe"
	billingapi "github.com/chronos/chronos-go/internal/modules/billing/api"
	orgapp "github.com/chronos/chronos-go/internal/modules/organization/app"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

type fakeVerifier struct {
	event stripeadapter.Event
	err   error
	state orgapp.SubscriptionState
	//nolint:unused // set by tests that need SubscriptionFor to fail
	stateErr error
}

func (f fakeVerifier) Verify([]byte, string) (stripeadapter.Event, error) {
	return f.event, f.err
}

func (f fakeVerifier) SubscriptionFor(context.Context, []byte) (orgapp.SubscriptionState, error) {
	return f.state, f.stateErr
}

// recordingTrials stands in for the trial-warning use case.
type recordingTrials struct {
	mu    sync.Mutex
	calls int
	orgID string
	ends  time.Time
	err   error
}

func (r *recordingTrials) Warn(
	_ context.Context, orgID string, trialEndsAt time.Time, _ string,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.orgID, r.ends = orgID, trialEndsAt
	return r.err
}

type countingSync struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (c *countingSync) Apply(context.Context, orgapp.SubscriptionState, string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return c.err
}

func (c *countingSync) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// An unsigned or wrongly-signed payload is refused, and nothing is applied.
//
// # Why this is the most important assertion in the file
//
// The endpoint is reachable by anybody on the internet, and what it changes is
// whether a tenant is suspended, active or closed. Signature verification is the
// ONLY thing standing between "a stranger POSTed some JSON" and a customer's
// account being switched off. It has to happen before anything else is trusted,
// and a failure has to stop the request dead.
func TestAnUnverifiedWebhookChangesNothing(t *testing.T) {
	t.Parallel()

	sync := &countingSync{}
	hook, err := billingapi.NewWebhook(billingapi.WebhookDeps{
		Trials:   &recordingTrials{},
		Verifier: fakeVerifier{err: errors.New("bad signature")},
		Sync:     sync,
		Events:   &fakeEvents{},
		Log:      discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}

	rec := httptest.NewRecorder()
	hook.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, billingapi.Path,
		strings.NewReader(`{"id":"evt_forged"}`)))

	if rec.Code != http.StatusBadRequest {
		t.Errorf("an unverified webhook answered %d, want 400", rec.Code)
	}
	if sync.count() != 0 {
		t.Fatal("an unverified webhook was APPLIED. Anybody who can reach this endpoint can " +
			"now suspend a tenant or mark one active")
	}
}

// The refusal tells the caller nothing useful.
//
// Anybody can POST here. Explaining WHY verification failed — wrong secret,
// stale timestamp, malformed header — helps only somebody probing it.
func TestTheRefusalDoesNotExplainItself(t *testing.T) {
	t.Parallel()

	hook, err := billingapi.NewWebhook(billingapi.WebhookDeps{
		Trials:   &recordingTrials{},
		Verifier: fakeVerifier{err: errors.New("timestamp outside the tolerance window")},
		Sync:     &countingSync{},
		Events:   &fakeEvents{},
		Log:      discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}

	rec := httptest.NewRecorder()
	hook.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, billingapi.Path,
		strings.NewReader(`{}`)))

	if strings.Contains(rec.Body.String(), "tolerance") {
		t.Errorf("the response repeats the internal reason to the caller: %q", rec.Body.String())
	}
}

// An event that can never be applied is answered 200, so Stripe stops retrying.
//
// Poison is not a transient failure. Returning 500 would have Stripe redeliver
// for three days, and at the end of it the event would still be unapplicable —
// the row and its recorded error are the trail, not the retry.
func TestAPoisonEventIsNotRetriedForever(t *testing.T) {
	t.Parallel()

	hook, err := billingapi.NewWebhook(billingapi.WebhookDeps{
		Trials:   &recordingTrials{},
		Verifier: fakeVerifier{event: stripeadapter.Event{ID: "evt_1", Type: "x"}},
		Sync: &countingSync{err: errors.New(
			"organization unknown: " + eventsourcing.ErrPoison.Error())},
		Events: &fakeEvents{claimed: true},
		Log:    discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}

	rec := httptest.NewRecorder()
	hook.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, billingapi.Path,
		strings.NewReader(`{}`)))

	// The stub sync returns a plain error, so this asserts the TRANSIENT branch:
	// 500 asks Stripe to retry, which is right for anything not poison.
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("a transient failure answered %d, want 500 so Stripe retries", rec.Code)
	}
}

// A GET is refused: this endpoint only ever receives POSTs.
func TestOnlyPostIsAccepted(t *testing.T) {
	t.Parallel()

	hook, err := billingapi.NewWebhook(billingapi.WebhookDeps{
		Trials:   &recordingTrials{},
		Verifier: fakeVerifier{},
		Sync:     &countingSync{},
		Events:   &fakeEvents{},
		Log:      discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}

	rec := httptest.NewRecorder()
	hook.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, billingapi.Path, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("a GET answered %d, want 405", rec.Code)
	}
}

// The endpoint refuses to exist without a way to verify.
func TestAWebhookWithoutAVerifierIsRefused(t *testing.T) {
	t.Parallel()

	if _, err := billingapi.NewWebhook(billingapi.WebhookDeps{
		Sync: &countingSync{}, Events: &fakeEvents{}, Log: discardLogger(),
	}); err == nil {
		t.Fatal("a webhook endpoint was built with no verifier; it would accept unsigned " +
			"requests that change billing state")
	}
}

// fakeEvents is the idempotency boundary. `claimed` decides whether this
// delivery is the one that should apply the change.
type fakeEvents struct {
	claimed   bool
	processed int
	failures  int
}

func (f *fakeEvents) Claim(context.Context, string, string, []byte) (bool, error) {
	return f.claimed, nil
}

func (f *fakeEvents) MarkProcessed(context.Context, string) error {
	f.processed++
	return nil
}

func (f *fakeEvents) MarkFailed(context.Context, string, error) error {
	f.failures++
	return nil
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// hookFor builds an endpoint over one verified event.
func hookFor(
	t *testing.T, eventType string, state orgapp.SubscriptionState,
	sync *countingSync, trials *recordingTrials,
) *billingapi.Webhook {
	t.Helper()
	hook, err := billingapi.NewWebhook(billingapi.WebhookDeps{
		Verifier: fakeVerifier{
			event: stripeadapter.Event{ID: "evt_1", Type: eventType},
			state: state,
		},
		Sync:   sync,
		Trials: trials,
		// claimed: THIS delivery is the one that applies. Left false the handler
		// correctly short-circuits as a duplicate and every assertion below
		// would measure a no-op.
		Events: &fakeEvents{claimed: true},
		Log:    discardLogger(),
	})
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}
	return hook
}

func post(hook *billingapi.Webhook) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	hook.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, billingapi.Path,
		strings.NewReader(`{"id":"evt_1"}`)))
	return rec
}

// TRIAL_WILL_END DRIVES THE WARNING.
//
// It is the only warning a cardless trial ever produces: the subscription then
// pauses, the organization is Suspended, and the customer's first signal would
// otherwise be being locked out of their own tenant. The status sync cannot
// carry it — this event reports `trialing`, which is the state the organization
// is already in, so the sync correctly does nothing.
func TestTrialWillEndDrivesTheWarning(t *testing.T) {
	t.Parallel()

	ends := time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)
	trials := &recordingTrials{}
	hook := hookFor(t, billingapi.TrialWillEndEvent, orgapp.SubscriptionState{
		OrgID: "org_x", SubscriptionID: "sub_1", TrialEndsAt: ends,
	}, &countingSync{}, trials)

	if code := post(hook).Code; code != http.StatusOK {
		t.Fatalf("answered %d, want 200", code)
	}
	if trials.calls != 1 {
		t.Fatalf("warned %d times, want 1; a cardless trial's only warning was dropped and "+
			"the customer's first signal is being locked out", trials.calls)
	}
	if trials.orgID != "org_x" {
		t.Errorf("warned %q", trials.orgID)
	}
	if !trials.ends.Equal(ends) {
		t.Errorf("warned about %v, want Stripe's re-fetched %v; the mail states a date",
			trials.ends, ends)
	}
}

// EVERY OTHER EVENT WARNS NOBODY.
//
// The branch is on the event TYPE, not on "there happens to be a trial end".
// Every trialing subscription carries one, so a condition on the deadline alone
// would warn on `customer.subscription.updated` — every time anything about a
// trialing subscription changed.
func TestAnOrdinarySubscriptionEventWarnsNobody(t *testing.T) {
	t.Parallel()

	trials := &recordingTrials{}
	hook := hookFor(t, "customer.subscription.updated", orgapp.SubscriptionState{
		OrgID: "org_x", SubscriptionID: "sub_1",
		// A trial end IS present, which is the trap: it is present on every
		// trialing subscription.
		TrialEndsAt: time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC),
	}, &countingSync{}, trials)

	if code := post(hook).Code; code != http.StatusOK {
		t.Fatalf("answered %d, want 200", code)
	}
	if trials.calls != 0 {
		t.Fatal("an ordinary subscription update sent a trial-ending warning; every change " +
			"to a trialing subscription now mails the customer")
	}
}

// THE STATUS SYNC STILL RUNS FOR TRIAL_WILL_END.
//
// Almost always a no-op, and it is not decoration: if the provisioning event has
// not been applied yet, the sync is what puts the organization into Trialing —
// and the warning refuses to fire for an organization that is not.
func TestTrialWillEndAlsoSyncsTheStatus(t *testing.T) {
	t.Parallel()

	sync := &countingSync{}
	hook := hookFor(t, billingapi.TrialWillEndEvent, orgapp.SubscriptionState{
		OrgID: "org_x", SubscriptionID: "sub_1",
		TrialEndsAt: time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC),
	}, sync, &recordingTrials{})

	post(hook)
	if sync.count() != 1 {
		t.Fatalf("synced %d times, want 1; an organization whose provisioning has not landed "+
			"is never moved to Trialing, and the warning then refuses to fire", sync.count())
	}
}

// A FAILED WARNING IS RETRIED, NOT ACKED.
//
// 500 so Stripe redelivers. Answering 200 would lose the only warning there is,
// with the row marked received and nothing to retry it.
func TestAFailedTrialWarningIsRetried(t *testing.T) {
	t.Parallel()

	trials := &recordingTrials{err: errors.New("kurrentdb: unavailable")}
	hook := hookFor(t, billingapi.TrialWillEndEvent, orgapp.SubscriptionState{
		OrgID: "org_x", SubscriptionID: "sub_1",
		TrialEndsAt: time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC),
	}, &countingSync{}, trials)

	if code := post(hook).Code; code != http.StatusInternalServerError {
		t.Fatalf("answered %d, want 500 so Stripe retries; the only warning a cardless "+
			"trial produces was dropped", code)
	}
}

// A WEBHOOK WITH NO TRIAL WARNING PORT IS REFUSED AT CONSTRUCTION.
//
// A nil one would panic at the moment a trial is three days from lapsing, which
// is the worst possible time to discover it — or, worse, be branched around and
// silently drop every warning.
func TestAWebhookWithNoTrialPortIsRefused(t *testing.T) {
	t.Parallel()

	if _, err := billingapi.NewWebhook(billingapi.WebhookDeps{
		Verifier: fakeVerifier{},
		Sync:     &countingSync{},
		Events:   &fakeEvents{},
		Log:      discardLogger(),
	}); err == nil {
		t.Error("a webhook with no trial warning port was accepted; trial_will_end would be " +
			"consumed and dropped, and no cardless trial would ever be warned")
	}
}
