//go:build integration

package kurrentdb_test

import (
	"context"
	jsonv1 "encoding/json"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	kdb "github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	es "github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/kurrent-io/KurrentDB-Client-Go/kurrentdb"
)

// Every event ALREADY ON DISK still decodes.
//
// This is the only test that says anything about the encoding/json v1 → v2
// migration. A round-trip test — marshal then unmarshal — passes identically
// under both libraries, because it never reads a byte that the current code did
// not just write. The log is append-only and permanent, so the question that
// matters is not "can we read what we write" but "can we read what we wrote".
//
// Two v2 behaviour changes could break stored data silently:
//
//   - Field matching is CASE-SENSITIVE. v1 populated OccurredAt from
//     {"occurredat":...}; v2 does not, and the field would come back zero.
//   - Duplicate object members are an ERROR where v1 took the last one.
//
// Neither produces a compile error, and neither shows up until a projector
// rebuilds against real history.
func TestEveryStoredEventStillDecodes(t *testing.T) {
	conn := os.Getenv("KURRENTDB_CONNECTION_STRING")
	if conn == "" {
		conn = "kurrentdb://localhost:2113?tls=false"
	}
	client, err := kdb.Dial(conn)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	c := eventcodec.NewJSON(es.NewUpcasterRegistry())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stream, err := client.ReadAll(ctx, kurrentdb.ReadAllOptions{
		From:      kurrentdb.Start{},
		Direction: kurrentdb.Forwards,
	}, 5000)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	defer stream.Close()

	var (
		total    int
		system   int
		decoded  int
		checked  int
		failures []string
	)
	for {
		ev, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			break
		}
		total++
		rec := ev.Event
		if rec == nil {
			continue
		}
		// System events carry KurrentDB's own metadata shape, not ours.
		if len(rec.EventType) > 0 && rec.EventType[0] == '$' {
			system++
			continue
		}

		// Metadata is the part this codebase writes for EVERY event, so it is
		// the broadest possible sample of the stored shape — including events
		// written before ADR-044 changed it to flat strings.
		m, merr := c.UnmarshalMetadata(rec.UserMetadata)
		if merr != nil {
			failures = append(failures, rec.EventType+": metadata: "+merr.Error())
			continue
		}
		// Compare the DECODED value against the raw stored string, rather than
		// asserting it is non-zero.
		//
		// "non-zero" is the wrong assertion and it fired on 715 real events: a
		// snapshot legitimately stores "0001-01-01T00:00:00Z", so a correct
		// decode looks identical to a field that silently failed to match. What
		// actually detects the case-sensitivity trap is that the decoded value
		// agrees with what is on disk — including when what is on disk is zero.
		if raw, ok := rawString(rec.UserMetadata, "occurredAt"); ok {
			want, perr := time.Parse(time.RFC3339Nano, raw)
			if perr != nil {
				failures = append(failures, rec.EventType+": stored occurredAt "+raw+
					" is not a timestamp: "+perr.Error())
				continue
			}
			if !m.OccurredAt.Equal(want) {
				failures = append(failures, rec.EventType+
					": stored occurredAt "+raw+" decoded as "+m.OccurredAt.String()+
					" — the field did not match, which is what case-sensitive matching "+
					"looks like when it silently fails")
				continue
			}
			checked++
		}
		decoded++
	}

	if total == 0 {
		t.Skip("the log is empty; run the stack and produce some events first, or this " +
			"test asserts nothing")
	}
	t.Logf("read %d events (%d system, %d decoded, %d with a timestamp compared "+
		"against its stored bytes)", total, system, decoded, checked)

	if len(failures) > 0 {
		t.Fatalf("%d of %d stored events no longer decode:\n  %s",
			len(failures), total-system, failures[0])
	}
	if decoded == 0 {
		t.Fatalf("read %d events but decoded none of them; the sample is entirely system "+
			"events, so nothing about the stored format was checked", total)
	}
	if checked == 0 {
		t.Fatal("no stored event carried an occurredAt to compare against, so the " +
			"case-sensitivity check above ran on nothing")
	}
}

// rawString pulls one top-level string member out of stored JSON, without the
// codec under test.
//
// Deliberately independent: using the codec to produce the expected value would
// make the comparison tautological — both sides would fail the same way.
func rawString(b []byte, key string) (string, bool) {
	var m map[string]any
	if err := jsonv1.Unmarshal(b, &m); err != nil {
		return "", false
	}
	s, ok := m[key].(string)
	return s, ok
}
