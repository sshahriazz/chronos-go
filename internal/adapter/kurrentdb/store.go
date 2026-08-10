// Package kurrentdb implements the event-sourcing ports against KurrentDB,
// using the official client (ADR-037) — which is gRPC-native, so there is no
// protocol translation on the write path.
package kurrentdb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/google/uuid"
	"github.com/kurrent-io/KurrentDB-Client-Go/kurrentdb"
)

// Store implements eventsourcing.EventStore.
type Store struct {
	client *kurrentdb.Client
	codec  eventsourcing.Codec
}

// NewStore wraps an existing client. The client is long-lived and shared:
// creating one per request would defeat gRPC multiplexing (ADR-037).
func NewStore(client *kurrentdb.Client, codec eventsourcing.Codec) *Store {
	return &Store{client: client, codec: codec}
}

// Dial parses a kurrentdb:// connection string and builds a client.
//
// It does not connect: the connection is established lazily and re-established
// automatically, which is what lets the process start before the database is up
// (ADR-010).
func Dial(connectionString string) (*kurrentdb.Client, error) {
	cfg, err := kurrentdb.ParseConnectionString(connectionString)
	if err != nil {
		return nil, fmt.Errorf("kurrentdb: %w", err)
	}
	return kurrentdb.NewClient(cfg)
}

// Append writes events under an optimistic-concurrency precondition.
//
// Two guarantees ride on this call, both verified against the server:
//   - a stale expected revision is REJECTED — that rejection is the aggregate
//     consistency boundary;
//   - re-appending the same event id at the same expected revision is accepted
//     and does NOT duplicate, which is what makes command retries safe.
func (s *Store) Append(
	ctx context.Context,
	stream eventsourcing.StreamID,
	expected eventsourcing.ExpectedRevision,
	events []eventsourcing.PendingEvent,
) (eventsourcing.AppendResult, error) {
	if len(events) == 0 {
		return eventsourcing.AppendResult{}, nil
	}

	data, err := s.toEventData(events)
	if err != nil {
		return eventsourcing.AppendResult{}, err
	}

	res, err := s.client.AppendToStream(ctx, stream.String(),
		kurrentdb.AppendToStreamOptions{StreamState: toStreamState(expected)}, data...)
	if err != nil {
		// NOTE: do not use kurrentdb.FromError here. Its bool is inverted from
		// the Go comma-ok idiom — it returns true only when err is nil — so
		// `if e, ok := FromError(err); ok` never fires for a real error.
		// errors.As is both correct and unwrap-safe.
		var kerr *kurrentdb.Error
		if errors.As(err, &kerr) && kerr.Code() == kurrentdb.ErrorCodeWrongExpectedVersion {
			// Expected under concurrency: the caller reloads and re-decides.
			return eventsourcing.AppendResult{}, fmt.Errorf("%w: stream %s expected %s",
				eventsourcing.ErrWrongExpectedRevision, stream, expected)
		}
		return eventsourcing.AppendResult{}, fmt.Errorf("kurrentdb: append to %s: %w", stream, err)
	}

	return eventsourcing.AppendResult{
		Revision: toRevision(res.NextExpectedVersion),
		Position: eventsourcing.Position{
			Commit:  res.CommitPosition,
			Prepare: res.PreparePosition,
		},
	}, nil
}

// ReadStream reads forwards from a revision.
func (s *Store) ReadStream(
	ctx context.Context,
	stream eventsourcing.StreamID,
	from eventsourcing.Revision,
) ([]eventsourcing.RecordedEvent, error) {
	var start kurrentdb.StreamPosition = kurrentdb.Start{}
	if from > 0 {
		start = kurrentdb.Revision(uint64(from))
	}

	rs, err := s.client.ReadStream(ctx, stream.String(),
		kurrentdb.ReadStreamOptions{Direction: kurrentdb.Forwards, From: start},
		^uint64(0))
	if err != nil {
		return nil, s.readErr(stream, err)
	}
	defer rs.Close()

	var out []eventsourcing.RecordedEvent
	for {
		resolved, err := rs.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, s.readErr(stream, err)
		}
		if resolved.Event == nil {
			continue
		}
		out = append(out, toRecorded(resolved.Event))
	}
	return out, nil
}

func (s *Store) readErr(stream eventsourcing.StreamID, err error) error {
	var kerr *kurrentdb.Error
	if errors.As(err, &kerr) && kerr.Code() == kurrentdb.ErrorCodeResourceNotFound {
		// A stream that does not exist is not a failure: it is an aggregate
		// that has never been written.
		return fmt.Errorf("%w: %s", eventsourcing.ErrStreamNotFound, stream)
	}
	return fmt.Errorf("kurrentdb: read %s: %w", stream, err)
}

func toRecorded(e *kurrentdb.RecordedEvent) eventsourcing.RecordedEvent {
	return eventsourcing.RecordedEvent{
		ID:        ids.FromUUID[ids.Event](e.EventID),
		Type:      e.EventType,
		Stream:    eventsourcing.StreamID(e.StreamID),
		Revision:  toRevision(e.EventNumber),
		Position:  eventsourcing.Position{Commit: e.Position.Commit, Prepare: e.Position.Prepare},
		Payload:   e.Data,
		Metadata:  e.UserMetadata,
		CreatedAt: e.CreatedDate.UTC(),
	}
}

func toStreamState(e eventsourcing.ExpectedRevision) kurrentdb.StreamState {
	switch {
	case e.IsNoStream():
		return kurrentdb.NoStream{}
	case e.IsStreamExists():
		return kurrentdb.StreamExists{}
	case e.IsAny():
		return kurrentdb.Any{}
	}
	rev, _ := e.Exact()
	if rev < 0 {
		// Defensive: ExpectedFor never produces a negative exact revision — a
		// never-persisted aggregate yields NoStream instead.
		return kurrentdb.NoStream{}
	}
	return kurrentdb.Revision(uint64(rev))
}

// toRevision narrows KurrentDB's uint64 stream position to our int64 Revision,
// which is signed so that -1 can mean "no stream". A stream long enough to
// overflow int64 is not physically reachable; saturating is still better than a
// silent wrap.
func toRevision(n uint64) eventsourcing.Revision {
	if n > uint64(math.MaxInt64) {
		return eventsourcing.Revision(math.MaxInt64)
	}
	return eventsourcing.Revision(n)
}

// toUUID reinterprets our 16-byte identifier as the client's UUID type. The
// derived id is already 16 deterministic bytes (EVENT-SOURCING §3), so no
// mapping table is needed and the value survives a round trip.
func toUUID(id ids.EventID) uuid.UUID {
	return uuid.UUID(id.Bytes())
}
