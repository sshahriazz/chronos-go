package kurrentdb

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/kurrent-io/KurrentDB-Client-Go/kurrentdb"
)

var (
	_ eventsourcing.SnapshotStore = (*Store)(nil)
	_ eventsourcing.StreamAdmin   = (*Store)(nil)
)

// LoadSnapshot reads the most recent snapshot for a stream.
//
// Backwards from the end, limit one — a single round trip that costs the same
// whether the stream holds one snapshot or a thousand. Reading forwards would
// mean scanning to find the latest, which is the cost snapshots exist to avoid.
func (s *Store) LoadSnapshot(
	ctx context.Context, stream eventsourcing.StreamID,
) (eventsourcing.RecordedEvent, bool, error) {
	rs, err := s.client.ReadStream(ctx, stream.String(),
		kurrentdb.ReadStreamOptions{Direction: kurrentdb.Backwards, From: kurrentdb.End{}}, 1)
	if err != nil {
		if isNotFound(err) {
			return eventsourcing.RecordedEvent{}, false, nil
		}
		return eventsourcing.RecordedEvent{}, false, fmt.Errorf("kurrentdb: reading snapshot %s: %w", stream, err)
	}
	defer rs.Close()

	resolved, err := rs.Recv()
	if errors.Is(err, io.EOF) {
		return eventsourcing.RecordedEvent{}, false, nil
	}
	if err != nil {
		if isNotFound(err) {
			return eventsourcing.RecordedEvent{}, false, nil
		}
		return eventsourcing.RecordedEvent{}, false, fmt.Errorf("kurrentdb: reading snapshot %s: %w", stream, err)
	}
	if resolved.Event == nil {
		return eventsourcing.RecordedEvent{}, false, nil
	}
	return toRecorded(resolved.Event), true, nil
}

// SaveSnapshot appends a snapshot and bounds the stream to the latest one.
//
// StreamState is Any: snapshots have no consistency requirement of their own —
// they describe a stream whose own append already enforced concurrency, and two
// processes racing to snapshot the same revision write identical content under
// the same deterministic id.
func (s *Store) SaveSnapshot(
	ctx context.Context, stream eventsourcing.StreamID, e eventsourcing.PendingEvent,
) error {
	payload, err := s.codec.Marshal(e.Event)
	if err != nil {
		return fmt.Errorf("kurrentdb: marshalling snapshot: %w", err)
	}
	meta, err := s.codec.MarshalMetadata(e.Meta)
	if err != nil {
		return fmt.Errorf("kurrentdb: marshalling snapshot metadata: %w", err)
	}

	res, err := s.client.AppendToStream(ctx, stream.String(),
		kurrentdb.AppendToStreamOptions{StreamState: kurrentdb.Any{}},
		kurrentdb.EventData{
			EventID:     toUUID(e.ID),
			EventType:   e.Event.EventType(),
			ContentType: kurrentdb.ContentTypeJson,
			Data:        payload,
			Metadata:    meta,
		})
	if err != nil {
		return fmt.Errorf("kurrentdb: writing snapshot to %s: %w", stream, err)
	}

	// Bound the stream on its first write only. $maxCount=1 makes the server
	// scavenge superseded snapshots by itself — without it the stream grows
	// forever and LoadSnapshot's cheap backwards read sits on top of an
	// ever-growing pile of dead state.
	if res.NextExpectedVersion == 0 {
		if err := s.SetRetention(ctx, stream, eventsourcing.Retention{MaxCount: 1}); err != nil {
			return fmt.Errorf("kurrentdb: bounding snapshot stream %s: %w", stream, err)
		}
	}
	return nil
}

// SetRetention writes a stream's retention policy.
//
// The server enforces this: no cleanup job, nothing to fall behind, and it keeps
// working when every application instance is down.
func (s *Store) SetRetention(
	ctx context.Context, stream eventsourcing.StreamID, r eventsourcing.Retention,
) error {
	var m kurrentdb.StreamMetadata
	if r.MaxCount > 0 {
		m.SetMaxCount(r.MaxCount)
	}
	if r.MaxAge > 0 {
		m.SetMaxAge(r.MaxAge)
	}
	if r.TruncateBefore > 0 {
		m.SetTruncateBefore(uint64(r.TruncateBefore))
	}

	if _, err := s.client.SetStreamMetadata(ctx, stream.String(),
		kurrentdb.AppendToStreamOptions{StreamState: kurrentdb.Any{}}, m); err != nil {
		return fmt.Errorf("kurrentdb: setting retention on %s: %w", stream, err)
	}
	return nil
}

// Retention reads a stream's retention policy. A stream with none reports the
// zero value rather than an error.
func (s *Store) Retention(
	ctx context.Context, stream eventsourcing.StreamID,
) (eventsourcing.Retention, error) {
	m, err := s.client.GetStreamMetadata(ctx, stream.String(), kurrentdb.ReadStreamOptions{})
	if err != nil {
		if isNotFound(err) {
			return eventsourcing.Retention{}, nil
		}
		return eventsourcing.Retention{}, fmt.Errorf("kurrentdb: reading retention of %s: %w", stream, err)
	}

	var out eventsourcing.Retention
	if v := m.MaxCount(); v != nil {
		out.MaxCount = *v
	}
	if v := m.MaxAge(); v != nil {
		out.MaxAge = *v
	}
	if v := m.TruncateBefore(); v != nil {
		out.TruncateBefore = toRevision(*v)
	}
	return out, nil
}

// isNotFound recognises "there is nothing here", which for snapshots and
// metadata is an ordinary answer rather than a failure.
func isNotFound(err error) bool {
	var kerr *kurrentdb.Error
	return errors.As(err, &kerr) &&
		(kerr.Code() == kurrentdb.ErrorCodeResourceNotFound || kerr.Code() == kurrentdb.ErrorCodeStreamDeleted)
}
