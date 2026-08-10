package projection

import (
	"fmt"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// Routing must be by stream and stable, because that is the entire correctness
// argument for sharding a rebuild. An event's shard may never depend on its
// position: two events of one aggregate landing in different workers is how a
// projection ends up holding a row from the middle of an aggregate's history.
//
// Internal, so the routing stays unexported — a test-only export would invite a
// caller to shard by something else.
func TestShardOfIsStablePerStream(t *testing.T) {
	const shards = 8
	first := map[eventsourcing.StreamID]int{}

	for i := range 500 {
		s := eventsourcing.StreamID(fmt.Sprintf("probe-%d", i))
		got := shardOf(s, shards)
		if got < 0 || got >= shards {
			t.Fatalf("%s routed to shard %d, outside [0,%d)", s, got, shards)
		}
		if prev, seen := first[s]; seen && prev != got {
			t.Fatalf("%s routed to %d then %d: routing is not stable", s, prev, got)
		}
		first[s] = got
	}

	// Every shard should see work; a hash that piles one stream family into one
	// worker would make the fan-out useless without failing anything.
	used := map[int]bool{}
	for _, shard := range first {
		used[shard] = true
	}
	if len(used) != shards {
		t.Errorf("only %d of %d shards received work across 500 streams", len(used), shards)
	}
}

// One shard is the sequential path and must route everything to worker zero.
func TestShardOfWithOneShard(t *testing.T) {
	for _, s := range []eventsourcing.StreamID{"probe-1", "probe-2", "other-9"} {
		if got := shardOf(s, 1); got != 0 {
			t.Fatalf("%s routed to %d with a single shard", s, got)
		}
	}
	if got := shardOf("probe-1", 0); got != 0 {
		t.Fatalf("zero shards must degrade to sequential, got %d", got)
	}
}
