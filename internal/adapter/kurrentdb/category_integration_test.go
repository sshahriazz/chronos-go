//go:build integration

package kurrentdb_test

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	kdb "github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/google/uuid"
	"github.com/kurrent-io/KurrentDB-Client-Go/kurrentdb"
)

// Category streams must stay available.
//
// They were believed unavailable for weeks because RUN_PROJECTIONS was set to
// None. That value disables ALL projections; the ban in CLAUDE.md is on
// user-written JavaScript projections, which require All. System runs only the
// built-in native ones ($by_category, $by_event_type) and no JS.
//
// This test is the tripwire: if someone sets None again to "turn off
// projections", selective rebuilds silently fall back to scanning the whole
// log — measured at 29x slower — with nothing else failing.
func TestCategoryStreamAvailable(t *testing.T) {
	cfg, err := kurrentdb.ParseConnectionString("kurrentdb://localhost:2113?tls=false")
	if err != nil {
		t.Fatal(err)
	}
	c, err := kurrentdb.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// A fresh category per run, so a previous run's events cannot make this pass.
	raw := uuid.New()
	cat := "cattest" + hex.EncodeToString(raw[:4])
	ctx := context.Background()

	for i := range 3 {
		_, err := c.AppendToStream(ctx, cat+"-s"+string(rune('a'+i)),
			kurrentdb.AppendToStreamOptions{StreamState: kurrentdb.Any{}},
			kurrentdb.EventData{
				EventID: uuid.New(), EventType: "CatTested",
				ContentType: kurrentdb.ContentTypeJson, Data: []byte(`{"i":1}`),
			})
		if err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	// The category stream is maintained by the $by_category system projection.
	// ResolveLinkTos is REQUIRED: a category stream holds link events pointing
	// at the originals, not the originals themselves.
	var found int
	for attempt := range 20 {
		rs, err := c.ReadStream(ctx, "$ce-"+cat,
			kurrentdb.ReadStreamOptions{
				Direction: kurrentdb.Forwards, From: kurrentdb.Start{}, ResolveLinkTos: true,
			}, 100)
		if err != nil {
			var kerr *kurrentdb.Error
			if errors.As(err, &kerr) && kerr.Code() == kurrentdb.ErrorCodeResourceNotFound {
				t.Logf("attempt %d: $ce-%s not there yet", attempt, cat)
				time.Sleep(250 * time.Millisecond)
				continue
			}
			t.Fatalf("read $ce-%s: %v", cat, err)
		}
		found = 0
		for {
			ev, err := rs.Recv()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				break
			}
			if ev.Event != nil {
				found++
			}
		}
		rs.Close()
		if found >= 3 {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}

	if found < 3 {
		t.Fatalf("category stream returned %d events, want 3 — $ce- is still unavailable", found)
	}
	t.Logf("SUCCESS: $ce-%s returned %d events across 3 streams", cat, found)
}

// Event-type streams must carry exactly one type.
//
// $et- is the narrowest rebuild source available: a category stream carries
// every type its aggregate emits, so a projection wanting one of them reads and
// discards the rest. Measured on this server with 2000 events in a category of
// which 200 were the wanted type — $et- 7.1ms, $ce- 105.3ms, 14.7x.
//
// The property that makes it usable is exactness. A type stream that also
// carried a neighbouring type would rebuild a projection with events it never
// subscribed to, and nothing downstream would notice.
func TestEventTypeStreamCarriesOnlyThatType(t *testing.T) {
	client, store := typeStore(t)
	ctx := context.Background()

	raw := uuid.New()
	sfx := hex.EncodeToString(raw[:4])
	wanted := "ettest." + sfx + ".Wanted.v1"
	other := "ettest." + sfx + ".Other.v1"

	// Interleaved in one stream, so the type stream cannot succeed merely by
	// picking a stream.
	const pairs = 10
	batch := make([]kurrentdb.EventData, 0, pairs*2)
	for range pairs {
		batch = append(batch,
			kurrentdb.EventData{EventID: uuid.New(), ContentType: kurrentdb.ContentTypeJson,
				EventType: wanted, Data: []byte(`{"k":"w"}`)},
			kurrentdb.EventData{EventID: uuid.New(), ContentType: kurrentdb.ContentTypeJson,
				EventType: other, Data: []byte(`{"k":"o"}`)})
	}
	if _, err := client.AppendToStream(ctx, "ettest"+sfx+"-1",
		kurrentdb.AppendToStreamOptions{}, batch...); err != nil {
		t.Fatalf("append: %v", err)
	}

	// $by_event_type writes the links asynchronously.
	var seen []string
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		seen = seen[:0]
		err := store.ReadEventType(ctx, wanted, func(_ context.Context, e eventsourcing.RecordedEvent) error {
			seen = append(seen, e.Type)
			return nil
		})
		if err != nil {
			t.Fatalf("ReadEventType: %v", err)
		}
		if len(seen) >= pairs {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	if len(seen) != pairs {
		t.Fatalf("read %d events of %s, want %d — $by_event_type may be disabled or behind",
			len(seen), wanted, pairs)
	}
	for _, got := range seen {
		if got != wanted {
			t.Fatalf("the type stream delivered %q; a rebuild would apply an event this "+
				"projection never subscribed to", got)
		}
	}

	// And the links must RESOLVE. Without ResolveLinkTos every event arrives as
	// an unreadable link and a rebuild silently produces an empty table.
	err := store.ReadEventType(ctx, wanted, func(_ context.Context, e eventsourcing.RecordedEvent) error {
		if len(e.Payload) == 0 {
			t.Fatal("a link was delivered unresolved: the payload is empty, so a rebuild " +
				"would write nothing while reporting success")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ReadEventType: %v", err)
	}
}

// An absent type stream is not an error: it means no events of that type exist
// yet, and an empty rebuild is the right answer for an empty slice of the log.
func TestReadEventTypeOfUnknownTypeIsEmptyNotAnError(t *testing.T) {
	_, store := typeStore(t)
	count := 0
	err := store.ReadEventType(context.Background(), "ettest.definitely.absent.v1",
		func(context.Context, eventsourcing.RecordedEvent) error { count++; return nil })
	if err != nil {
		t.Fatalf("an absent type stream must not be an error, got %v", err)
	}
	if count != 0 {
		t.Fatalf("read %d events from a type that was never written", count)
	}
}

// typeStore builds a Store for the type-stream tests. The codec is irrelevant
// here — ReadEventType hands back RecordedEvent, which is decoded by the caller.
func typeStore(t *testing.T) (*kurrentdb.Client, *kdb.Store) {
	t.Helper()
	cfg, err := kurrentdb.ParseConnectionString("kurrentdb://localhost:2113?tls=false")
	if err != nil {
		t.Fatal(err)
	}
	c, err := kurrentdb.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, kdb.NewStore(c, eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry()))
}
