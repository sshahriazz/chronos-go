//go:build integration

package centrifugo_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/centrifugo"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/realtime"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func newPublisher(t *testing.T) *centrifugo.Publisher {
	t.Helper()
	conn, err := centrifugo.Dial(envOr("CENTRIFUGO_GRPC_ENDPOINT", "localhost:10000"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return centrifugo.New(conn, os.Getenv("CENTRIFUGO_API_KEY"), nil)
}

// The gRPC API works, over the transport ADR-037 requires.
func TestPublish(t *testing.T) {
	p := newPublisher(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	payload, _ := codec.Marshal(map[string]any{"type": "notification", "id": uuid.NewString()})
	err := p.Publish(ctx, realtime.Message{
		Channel:        realtime.UserChannel("sub_" + uuid.NewString()[:8]),
		Type:           "notification.created",
		Data:           payload,
		IdempotencyKey: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
}

// A projector often touches several channels for one event. One round trip, not
// one per channel.
func TestPublishManyIsOneRoundTrip(t *testing.T) {
	p := newPublisher(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	msgs := make([]realtime.Message, 0, 5)
	for range 5 {
		payload, _ := codec.Marshal(map[string]any{"id": uuid.NewString()})
		msgs = append(msgs, realtime.Message{
			Channel: realtime.UserChannel("sub_" + uuid.NewString()[:8]),
			Type:    "notification.created",
			Data:    payload,
		})
	}
	if err := p.PublishMany(ctx, msgs); err != nil {
		t.Fatalf("publish many: %v", err)
	}
}

// Presence is what makes alert arbitration implementable (ADR-026). Nobody
// connected must read as zero, not as an error — otherwise every arbitration
// decision fails closed and every Activity email is suppressed.
func TestPresenceForAnAbsentUser(t *testing.T) {
	p := newPublisher(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	online, err := p.Online(ctx, "sub_definitely_not_connected")
	if err != nil {
		t.Fatalf("presence must answer for an absent user, not fail: %v", err)
	}
	if online {
		t.Fatal("reported a connection for a user that has never connected")
	}
}

// A channel outside a configured namespace silently loses presence, history and
// recovery — a failure nobody notices until they need recovery.
func TestChannelWithoutANamespaceIsRefused(t *testing.T) {
	p := newPublisher(t)
	err := p.Publish(context.Background(), realtime.Message{
		Channel: realtime.Channel("no-namespace-here"),
		Type:    "x",
		Data:    []byte(`{}`),
	})
	if !errors.Is(err, realtime.ErrInvalidChannel) {
		t.Fatalf("expected the channel to be refused, got %v", err)
	}
}

// A realtime message carries a pointer, not the data of record. An oversized
// payload means the message has BECOME the record, and a client that missed it
// has lost something.
func TestOversizedPayloadIsRefused(t *testing.T) {
	p := newPublisher(t)
	err := p.Publish(context.Background(), realtime.Message{
		Channel: realtime.UserChannel("sub_1"),
		Type:    "x",
		Data:    []byte(strings.Repeat("x", realtime.MaxPayloadBytes+1)),
	})
	if err == nil {
		t.Fatal("an oversized realtime payload must be refused")
	}
}

// ---------------------------------------------------------------------------
// tokens: the authorisation seam
// ---------------------------------------------------------------------------

func TestSubscriptionTokenIsScopedToOneChannel(t *testing.T) {
	secret := os.Getenv("CENTRIFUGO_CLIENT_TOKEN_HMAC_SECRET_KEY")
	if secret == "" {
		secret = "test-secret"
	}
	m := centrifugo.NewTokenMinter(secret, clock.System{})
	ch := realtime.UserChannel("sub_1")

	token, err := m.Subscription(context.Background(), "sub_1", ch, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return []byte(secret), nil })
	if err != nil {
		t.Fatalf("the minted token does not verify: %v", err)
	}
	claims := parsed.Claims.(jwt.MapClaims)

	// One channel, never a wildcard: a token good for "user:*" is a token good
	// for everyone's notifications.
	if claims["channel"] != ch.String() {
		t.Errorf("channel claim is %v, want %s", claims["channel"], ch)
	}
	if claims["sub"] != "sub_1" {
		t.Errorf("subject claim is %v", claims["sub"])
	}
	// The subject must be the pseudonym — Centrifugo logs it and exposes it in
	// presence (ADR-002).
	if strings.Contains(claims["sub"].(string), "@") {
		t.Error("the token subject looks like an email address")
	}
	if _, ok := claims["exp"]; !ok {
		t.Error("a token with no expiry is a permanent capability")
	}
}

func TestTokenMinterRefusesBadInput(t *testing.T) {
	m := centrifugo.NewTokenMinter("secret", clock.System{})
	ctx := context.Background()

	if _, err := m.Subscription(ctx, "sub_1", realtime.Channel("nonamespace"), time.Minute); err == nil {
		t.Error("a channel with no namespace must be refused")
	}
	if _, err := m.Connection(ctx, "", time.Minute); err == nil {
		t.Error("a connection token with no subject must be refused")
	}

	// An unsigned token fails at the browser, far from the cause.
	unsigned := centrifugo.NewTokenMinter("", clock.System{})
	if _, err := unsigned.Connection(ctx, "sub_1", time.Minute); err == nil {
		t.Error("minting without a secret must fail here, not at the browser")
	}
}

func TestProbeReportsHealth(t *testing.T) {
	p := newPublisher(t)
	probe := centrifugo.Probe{Publisher: p}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := probe.Check(ctx); err != nil {
		t.Fatalf("probe: %v", err)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
