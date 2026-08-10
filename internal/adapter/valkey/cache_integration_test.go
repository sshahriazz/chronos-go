//go:build integration

package valkey_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	valkeyadapter "github.com/chronos/chronos-go/internal/adapter/valkey"
	"github.com/chronos/chronos-go/internal/platform/cache"
	"github.com/valkey-io/valkey-go"
)

func dial(t *testing.T) valkey.Client {
	t.Helper()
	addr := os.Getenv("VALKEY_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	c, err := valkey.NewClient(valkey.ClientOption{
		InitAddress:  []string{addr},
		Password:     os.Getenv("VALKEY_PASSWORD"),
		DisableCache: true,
	})
	if err != nil {
		t.Fatalf("dial valkey at %s: %v", addr, err)
	}
	t.Cleanup(c.Close)
	return c
}

// Every entry carries an expiry. A key written without one is a permanent second
// source of truth in a store whose stated property is that FLUSHALL is
// survivable, so this asserts against the SERVER rather than against our
// intention: TTL is read back from Valkey itself.
func TestSetAlwaysAppliesAnExpiry(t *testing.T) {
	client := dial(t)
	c := valkeyadapter.NewCache(client)
	ctx := context.Background()
	key := "test:ttl:" + t.Name()
	t.Cleanup(func() { _ = c.Delete(context.Background(), key) })

	if err := c.Set(ctx, key, []byte("v"), 30*time.Second); err != nil {
		t.Fatalf("Set: %v", err)
	}

	ttl, err := client.Do(ctx, client.B().Pttl().Key(key).Build()).AsInt64()
	if err != nil {
		t.Fatalf("PTTL: %v", err)
	}
	// -1 is "no expiry", -2 is "no key". Either means the guarantee is broken.
	if ttl <= 0 {
		t.Fatalf("PTTL returned %d: the key was stored without an expiry", ttl)
	}
	if ttl > 30_000 {
		t.Fatalf("PTTL %dms exceeds the requested 30s", ttl)
	}
}

func TestSetRejectsNonPositiveTTL(t *testing.T) {
	c := valkeyadapter.NewCache(dial(t))
	for _, ttl := range []time.Duration{0, -time.Second} {
		if err := c.Set(context.Background(), "test:bad", []byte("v"), ttl); !errors.Is(err, cache.ErrNoTTL) {
			t.Fatalf("Set with TTL %s should be refused, got %v", ttl, err)
		}
	}
}

// A miss is not an error. Callers treat "absent" and "cache down" identically,
// and forcing them to unwrap a nil reply is how a restart becomes a 500.
func TestGetMissIsNotAnError(t *testing.T) {
	c := valkeyadapter.NewCache(dial(t))
	v, found, err := c.Get(context.Background(), "test:definitely-absent:"+t.Name())
	if err != nil {
		t.Fatalf("a miss must not be an error, got %v", err)
	}
	if found || v != nil {
		t.Fatalf("got found=%v value=%q for an absent key", found, v)
	}
}

// Values must survive the round trip byte for byte, including bytes that are not
// valid UTF-8: sealed ciphertext and protobuf both look like this.
func TestRoundTripIsBinarySafe(t *testing.T) {
	c := valkeyadapter.NewCache(dial(t))
	ctx := context.Background()
	key := "test:binary:" + t.Name()
	t.Cleanup(func() { _ = c.Delete(context.Background(), key) })

	want := []byte{0x00, 0xff, 0xfe, 0x01, 0x80, 0x00}
	if err := c.Set(ctx, key, want, time.Minute); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, found, err := c.Get(ctx, key)
	if err != nil || !found {
		t.Fatalf("Get: found=%v err=%v", found, err)
	}
	if string(got) != string(want) {
		t.Fatalf("value changed in transit: got % x, want % x", got, want)
	}
}

func TestDeleteAbsentKeyIsNotAnError(t *testing.T) {
	c := valkeyadapter.NewCache(dial(t))
	if err := c.Delete(context.Background(), "test:absent:"+t.Name()); err != nil {
		t.Fatalf("deleting an absent key must not be an error, got %v", err)
	}
	if err := c.Delete(context.Background()); err != nil {
		t.Fatalf("deleting nothing must not be an error, got %v", err)
	}
}

// The bus is what makes an in-process key cache safe across replicas. This
// asserts the real path: one client publishes, another receives.
func TestBusDeliversToAnotherConnection(t *testing.T) {
	publisher := valkeyadapter.NewBus(dial(t))
	subscriber := valkeyadapter.NewBus(dial(t))
	channel := "test.bus." + t.Name()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	received := make(chan string, 1)
	subscribed := make(chan struct{})
	go func() {
		close(subscribed)
		_ = subscriber.Subscribe(ctx, channel, func(m []byte) {
			select {
			case received <- string(m):
			default:
			}
		})
	}()
	<-subscribed

	// Publish until one lands: SUBSCRIBE is asynchronous, and a message sent
	// before the server registers the subscriber is simply dropped.
	deadline := time.After(5 * time.Second)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := publisher.Publish(ctx, channel, []byte("subj_1")); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		select {
		case got := <-received:
			if got != "subj_1" {
				t.Fatalf("received %q", got)
			}
			return
		case <-deadline:
			t.Fatal("no message received within 5s")
		case <-tick.C:
		}
	}
}

// Cancelling the context must end the subscription rather than leak the
// goroutine holding it.
func TestSubscribeStopsOnContextCancel(t *testing.T) {
	b := valkeyadapter.NewBus(dial(t))
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- b.Subscribe(ctx, "test.cancel."+t.Name(), func([]byte) {}) }()

	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Subscribe did not return after its context was cancelled")
	}
}
