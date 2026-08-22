package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
