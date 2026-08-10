package valkey

import (
	"context"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/platform/cache"
	"github.com/valkey-io/valkey-go"
)

// Cache implements cache.Cache over Valkey.
//
// Every write goes out with PX, so there is no path by which an entry outlives
// its TTL — not a forgotten EXPIRE, not a SET that raced with one. `FLUSHALL`
// must be survivable (INFRA), and the inverse obligation is that nothing here
// survives without an expiry.
type Cache struct {
	client valkey.Client
}

var _ cache.Cache = (*Cache)(nil)

// NewCache adapts a Valkey client.
func NewCache(c valkey.Client) *Cache { return &Cache{client: c} }

// Get returns the stored bytes. A missing key is (nil, false, nil): Valkey's nil
// reply is the normal case, not a fault, and treating it as an error would make
// every caller unwrap the distinction the port exists to hide.
func (c *Cache) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if c.client == nil {
		return nil, false, errNoClient
	}
	b, err := c.client.Do(ctx, c.client.B().Get().Key(key).Build()).AsBytes()
	switch {
	case valkey.IsValkeyNil(err):
		return nil, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("valkey: get %s: %w", key, err)
	}
	return b, true, nil
}

// Set stores bytes with an expiry.
//
// PX rather than EX: a sub-second TTL is meaningful for the short-lived entries
// this is used for, and EX would silently round one to zero — which Valkey
// rejects, turning a deliberate 200ms cache into a runtime error.
func (c *Cache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if c.client == nil {
		return errNoClient
	}
	if err := cache.ValidateTTL(ttl); err != nil {
		return err
	}
	cmd := c.client.B().Set().Key(key).Value(valkey.BinaryString(value)).
		Px(ttl).Build()
	if err := c.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("valkey: set %s: %w", key, err)
	}
	return nil
}

// Delete removes keys. Absent keys are not an error.
func (c *Cache) Delete(ctx context.Context, keys ...string) error {
	if c.client == nil {
		return errNoClient
	}
	if len(keys) == 0 {
		return nil
	}
	if err := c.client.Do(ctx, c.client.B().Del().Key(keys...).Build()).Error(); err != nil {
		return fmt.Errorf("valkey: delete: %w", err)
	}
	return nil
}

// Bus implements cache.Bus over Valkey pub/sub.
//
// Pub/sub, not a stream: an invalidation is only useful to processes that are
// running when it is sent, and a process that was down has to distrust its cache
// on startup anyway. Persisting these messages would create a backlog whose only
// possible effect is to invalidate entries that already expired.
type Bus struct {
	client valkey.Client
}

var _ cache.Bus = (*Bus)(nil)

// NewBus adapts a Valkey client for invalidation messages.
func NewBus(c valkey.Client) *Bus { return &Bus{client: c} }

func (b *Bus) Publish(ctx context.Context, channel string, message []byte) error {
	if b.client == nil {
		return errNoClient
	}
	cmd := b.client.B().Publish().Channel(channel).
		Message(valkey.BinaryString(message)).Build()
	if err := b.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("valkey: publish %s: %w", channel, err)
	}
	return nil
}

// Subscribe blocks until ctx is cancelled or the connection drops.
//
// It returns an error on a dropped connection rather than reconnecting
// internally, because the caller's correct response is not just to reconnect: a
// subscriber that missed messages has to assume it missed an invalidation, and
// whether that means purging a cache is the caller's decision, not this
// adapter's.
func (b *Bus) Subscribe(ctx context.Context, channel string, fn func([]byte)) error {
	if b.client == nil {
		return errNoClient
	}
	err := b.client.Receive(ctx, b.client.B().Subscribe().Channel(channel).Build(),
		func(msg valkey.PubSubMessage) { fn([]byte(msg.Message)) })
	if err != nil {
		return fmt.Errorf("valkey: subscribe %s: %w", channel, err)
	}
	return nil
}

var errNoClient = fmt.Errorf("valkey: client not initialised")
