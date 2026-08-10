package webpush_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/chronos/chronos-go/internal/adapter/webpush"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

// The payload privacy rules are asserted in payload_internal_test.go, against
// the CONSTRUCTED payload. They cannot be checked here: the wire body is
// encrypted, so a test reading the HTTP request would pass no matter what the
// payload contained.

// ---------------------------------------------------------------------------
// pruning
// ---------------------------------------------------------------------------

// A 410 means the browser dropped the subscription. Retrying can never succeed,
// and leaving it makes every future send slower for no benefit.
func TestGoneSubscriptionIsPruned(t *testing.T) {
	for _, status := range []int{http.StatusGone, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			body := captureBody(t, status)
			tr, subs := newTransport(t, body.server.URL, titles{title: "t", body: "b"})

			err := tr.Deliver(context.Background(), notification())
			if err != nil {
				t.Fatalf("a dead endpoint must not be an error — it is pruned: %v", err)
			}
			if len(subs.retired) != 1 {
				t.Fatalf("the subscription was not retired after %d", status)
			}
			if !strings.Contains(subs.retired[0], "returned") {
				t.Errorf("the retirement reason should record the status: %q", subs.retired[0])
			}
		})
	}
}

// A 5xx is weather. Retry.
func TestServerErrorIsRetried(t *testing.T) {
	body := captureBody(t, http.StatusServiceUnavailable)
	tr, subs := newTransport(t, body.server.URL, titles{title: "t", body: "b"})

	err := tr.Deliver(context.Background(), notification())
	if err == nil {
		t.Fatal("a 503 from the push service must be retried, not swallowed")
	}
	if errors.Is(err, webpush.ErrUnrecoverable) {
		t.Error("a 503 is transient and must not be parked")
	}
	if len(subs.retired) != 0 {
		t.Error("a transient failure must not retire the subscription")
	}
}

// A 403 means our VAPID keys are wrong. That is configuration, not weather, and
// no number of retries will fix it.
func TestAuthFailureIsUnrecoverable(t *testing.T) {
	body := captureBody(t, http.StatusForbidden)
	tr, _ := newTransport(t, body.server.URL, titles{title: "t", body: "b"})

	err := tr.Deliver(context.Background(), notification())
	if !errors.Is(err, webpush.ErrUnrecoverable) {
		t.Fatalf("a 403 must be parked rather than retried forever, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// deliberate non-delivery
// ---------------------------------------------------------------------------

// Most people never grant push permission. Treating that as a failure would
// retry forever and park a notification that email delivered perfectly well.
func TestNoSubscriptionsIsNotAFailure(t *testing.T) {
	body := captureBody(t, http.StatusCreated)
	tr, subs := newTransport(t, body.server.URL, titles{title: "t", body: "b"})
	subs.active = nil

	if err := tr.Deliver(context.Background(), notification()); err != nil {
		t.Fatalf("a subject with no push subscriptions is not an error: %v", err)
	}
}

// userVisibleOnly means a push that displays nothing risks the browser revoking
// permission for the whole origin. A template with no push wording is therefore
// skipped rather than sent empty.
func TestTemplateWithoutPushWordingIsSkipped(t *testing.T) {
	body := captureBody(t, http.StatusCreated)
	tr, _ := newTransport(t, body.server.URL, titles{ok: false})

	if err := tr.Deliver(context.Background(), notification()); err != nil {
		t.Fatalf("a template with no push wording must be skipped: %v", err)
	}
	if body.count() != 0 {
		t.Fatal("a push was sent with no wording; the browser may revoke permission for the origin")
	}
}

func TestOperatorNotificationHasNoSubjectAndIsRefused(t *testing.T) {
	body := captureBody(t, http.StatusCreated)
	tr, _ := newTransport(t, body.server.URL, titles{title: "t", body: "b"})

	err := tr.Deliver(context.Background(), notify.Notification{
		Template:  "operator.alert",
		Class:     notify.Operator,
		Recipient: notify.Recipient{Address: "ops@chronos.test"},
	})
	if !errors.Is(err, notify.ErrNoAddress) {
		t.Fatalf("push needs a subject; operators have none, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func notification() notify.Notification {
	return notify.Notification{
		Template:       "identity.password_changed",
		Class:          notify.Security,
		Recipient:      notify.Recipient{SubjectID: "sub_1"},
		IdempotencyKey: "evt_1:0",
	}
}

func newTransport(t *testing.T, endpoint string, ti titles) (*webpush.Transport, *fakeSubs) {
	t.Helper()
	pub, priv := vapidKeys(t)
	subs := &fakeSubs{active: []webpush.Subscription{{
		ID: "psub_1", SubjectID: "sub_1", Endpoint: endpoint,
		P256dh: browserKey(t), Auth: randB64(t, 16),
	}}}
	return webpush.New(subs, ti, webpush.Config{
		VAPID:   webpush.VAPID{PublicKey: pub, PrivateKey: priv, Subject: "mailto:ops@chronos.test"},
		BaseURL: "https://app.chronos.test",
	}), subs
}

type titles struct {
	title, body string
	ok          bool
}

func (ti titles) Push(string, map[string]any) (string, string, bool) {
	if ti.title == "" && !ti.ok {
		return "", "", false
	}
	return ti.title, ti.body, true
}

type fakeSubs struct {
	active  []webpush.Subscription
	retired []string
}

func (f *fakeSubs) Active(context.Context, string, string) ([]webpush.Subscription, error) {
	return f.active, nil
}

func (f *fakeSubs) Retire(_ context.Context, _ string, _ webpush.Subscription, reason string) error {
	f.retired = append(f.retired, reason)
	return nil
}

// capture is a stand-in push service: it counts requests and answers with a
// fixed status, which is all the transport's behaviour depends on.
type capture struct {
	mu     sync.Mutex
	server *httptest.Server
	n      int
}

func (c *capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func captureBody(t *testing.T, status int) *capture {
	t.Helper()
	c := &capture{}
	c.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		c.mu.Lock()
		c.n++
		c.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(c.server.Close)
	return c
}

func vapidKeys(t *testing.T) (pub, priv string) {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("vapid keys: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
		base64.RawURLEncoding.EncodeToString(key.Bytes())
}

func browserKey(t *testing.T) string {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("browser key: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
}

func randB64(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
