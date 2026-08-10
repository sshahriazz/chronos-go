//go:build integration

package projectionit_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kurrent-io/KurrentDB-Client-Go/kurrentdb"
)

// A projection filtered to a quiet part of the system must still advance its
// position while the rest of the system writes.
//
// Before this, the stored position moved only when a MATCHING event was applied,
// so a projector interested in a quiet module sat at its last match forever. Every
// restart made the server re-scan the whole intervening log to find nothing. The
// cost grows with the log and never stops growing — the same shape as the rebuild
// problem, but paid on every ordinary restart rather than on a deliberate act.
//
// The server already offers the resume point: a filtered subscription emits
// checkpoints for spans it scanned and found no match in. Honouring them is what
// this asserts.
func TestQuietProjectionAdvancesPastUnmatchedEvents(t *testing.T) {
	h := newHarness(t)

	// One matching event, so the projection has a position to be stuck at.
	h.append(t, "thing_1", "org_"+h.suffix, "ws_1", ThingRecorded{ID: h.suffix + "_1", Name: "first"}, 1)
	h.runUntil(t, 1)

	stuck := h.checkpoint(t)
	if stuck.Position.Commit == 0 {
		t.Fatal("the projection recorded no position for its first event")
	}

	// Now the REST of the system writes: events this projection's filter excludes.
	// This is the ordinary state of a multi-module deployment.
	appendNoise(t, 20_000, h.suffix)

	// Run again. Nothing matches, so nothing is applied — but the position must
	// move, because the server told us it scanned past all of it.
	h.runFor(t, 8*time.Second)

	after := h.checkpoint(t)
	if after.EventsProcessed != stuck.EventsProcessed {
		t.Fatalf("EventsProcessed moved from %d to %d: a checkpoint is not an event and "+
			"must not be counted as one", stuck.EventsProcessed, after.EventsProcessed)
	}
	if after.Position.Commit <= stuck.Position.Commit {
		t.Fatalf("the position did not advance past %d unmatched events: still at commit %d. "+
			"Every restart will re-scan the whole log from here",
			20_000, after.Position.Commit)
	}

	t.Logf("position advanced %d -> %d across 20k unmatched events, 0 applied",
		stuck.Position.Commit, after.Position.Commit)
}

// The position must never move backwards. A server checkpoint can trail the last
// event already applied, and rewinding would replay events the projection has
// processed — not corruption, since Apply is idempotent, but silent repeated work
// that looks exactly like the bug this fix removes.
func TestCheckpointNeverRegresses(t *testing.T) {
	h := newHarness(t)

	h.append(t, "thing_1", "org_"+h.suffix, "ws_1", ThingRecorded{ID: h.suffix + "_1", Name: "first"}, 1)
	h.runUntil(t, 1)
	first := h.checkpoint(t)

	appendNoise(t, 2_000, h.suffix)
	h.runFor(t, 5*time.Second)
	second := h.checkpoint(t)

	if second.Position.Commit < first.Position.Commit {
		t.Fatalf("the position regressed from %d to %d", first.Position.Commit, second.Position.Commit)
	}

	// Running again with nothing new must be a no-op, not a rewind.
	h.runFor(t, 3*time.Second)
	third := h.checkpoint(t)
	if third.Position.Commit < second.Position.Commit {
		t.Fatalf("the position regressed from %d to %d on an idle run",
			second.Position.Commit, third.Position.Commit)
	}
	if third.EventsProcessed != first.EventsProcessed {
		t.Fatalf("an idle run reapplied events: EventsProcessed %d -> %d",
			first.EventsProcessed, third.EventsProcessed)
	}
}

// A projection that IS matching events must still record the position of the
// events it applied, not a scanned position that skipped them. This is the guard
// against "fixing" the resume cost by advancing past work.
func TestMatchedEventsAreStillApplied(t *testing.T) {
	h := newHarness(t)
	org := "org_" + h.suffix

	appendNoise(t, 5_000, h.suffix)
	for i := 1; i <= 5; i++ {
		h.append(t, fmt.Sprintf("thing_%d", i), org, "ws_1",
			ThingRecorded{ID: fmt.Sprintf("%s_%d", h.suffix, i), Name: fmt.Sprintf("n%d", i)}, i)
	}
	appendNoise(t, 5_000, h.suffix)

	h.runUntil(t, 5)

	rows := h.rows(t, org, "ws_1")
	if len(rows) != 5 {
		t.Fatalf("expected 5 projected rows, got %d: the checkpoint advanced past events "+
			"that should have been applied", len(rows))
	}
	if cp := h.checkpoint(t); cp.EventsProcessed != 5 {
		t.Fatalf("EventsProcessed = %d, want 5", cp.EventsProcessed)
	}
}

// appendNoise writes events into streams no probe projection subscribes to,
// standing in for the rest of a busy system.
func appendNoise(t *testing.T, n int, suffix string) {
	t.Helper()
	client, err := kurrentdb.NewClient(mustParse(t, kurrentDSN()))
	if err != nil {
		t.Fatalf("kurrentdb: %v", err)
	}
	defer client.Close()

	const perStream = 500
	for i := 0; i < n; i += perStream {
		size := min(perStream, n-i)
		batch := make([]kurrentdb.EventData, 0, size)
		for range size {
			batch = append(batch, kurrentdb.EventData{
				ContentType: kurrentdb.ContentTypeJson,
				EventType:   "noise.v1",
				Data:        []byte(`{"n":1}`),
			})
		}
		stream := fmt.Sprintf("noise%s-%d", suffix, i/perStream)
		if _, err := client.AppendToStream(context.Background(), stream,
			kurrentdb.AppendToStreamOptions{}, batch...); err != nil {
			t.Fatalf("appending noise: %v", err)
		}
	}
}

func mustParse(t *testing.T, dsn string) *kurrentdb.Configuration {
	t.Helper()
	cfg, err := kurrentdb.ParseConnectionString(dsn)
	if err != nil {
		t.Fatalf("parsing %q: %v", dsn, err)
	}
	return cfg
}
