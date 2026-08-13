package valkey

import (
	"context"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/platform/ratelimit"
	"github.com/valkey-io/valkey-go"
)

// Counter implements ratelimit.Counter over Valkey.
type Counter struct {
	client valkey.Client
}

var _ ratelimit.Counter = (*Counter)(nil)

// NewCounter adapts a Valkey client.
func NewCounter(c valkey.Client) *Counter { return &Counter{client: c} }

// incrWithTTL increments a key and sets its expiry on FIRST increment only.
//
// One script rather than INCR followed by EXPIRE, and the difference is not
// stylistic. Two commands leave a window in which the process dies after the
// INCR and before the EXPIRE — the key then has no expiry, the counter never
// resets, and that scope is refused forever. It would present as one user
// permanently unable to log in, with a Valkey key nobody thinks to look at.
//
// That specific failure is NOT covered by any test here, and saying so matters:
// reproducing it needs a process death between two round trips, which a test
// cannot stage. Swapping this script for INCR-then-PEXPIRE passes the whole
// suite. The script is chosen because it removes the failure mode, not because
// anything demonstrates its absence.
//
// The TTL is set only when the counter is created (result == 1), so a fixed
// window starts at the first attempt and is not extended by later ones. Refreshing
// it on every increment would turn the window into a sliding ban: an attacker
// pushing one attempt per second would hold the counter above the limit
// indefinitely, and so would a stuck client retrying in a loop.
var incrWithTTL = valkey.NewLuaScript(`
local n = redis.call('INCR', KEYS[1])
if n == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return n
`)

// Incr increments the counter for key, creating it with the window as its TTL.
func (c *Counter) Incr(ctx context.Context, key string, window time.Duration) (int64, error) {
	if c.client == nil {
		return 0, errNoClient
	}
	// Sub-millisecond windows are REFUSED, not rounded up.
	//
	// window.Milliseconds() truncates, so anything under 1ms becomes 0 — and
	// PEXPIRE with 0 DELETES the key. The counter would be created and destroyed
	// on every call, every attempt would read 1, and the ceiling would never be
	// reached: a rate limiter that silently permits everything.
	//
	// Rounding up to 1ms was the first fix and it is worse, because it cannot be
	// tested deterministically — a 1ms key may or may not survive to the next
	// assertion — so the guard would go unverified. Refusing is both safer and
	// checkable, and a rate-limit window below a millisecond is not a real
	// policy in any case.
	if window < time.Millisecond {
		return 0, fmt.Errorf("valkey: a rate-limit window must be at least 1ms, got %v", window)
	}
	ms := window.Milliseconds()
	n, err := incrWithTTL.Exec(ctx, c.client, []string{key}, []string{fmt.Sprint(ms)}).AsInt64()
	if err != nil {
		return 0, fmt.Errorf("valkey: incrementing %s: %w", key, err)
	}
	return n, nil
}
