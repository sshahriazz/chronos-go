package kurrentdb

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/kurrent-io/KurrentDB-Client-Go/kurrentdb"
)

var _ eventsourcing.MultiAppender = (*Store)(nil)

// AppendToMany writes to several streams atomically.
//
// The server evaluates every precondition and then commits all of them or none.
// Verified against the running server: failing one stream's expected revision
// rolled the other stream's events back, and neither appeared in $all.
//
// This is NOT a general transaction across aggregates — see the port's comment
// on why that stays forbidden. It exists so a claim and the aggregate that owns
// it can be written together: a reservation stream with NoStream alongside the
// aggregate creation with NoStream, which as two appends leaves an orphaned
// reservation whenever the process dies between them.
func (s *Store) AppendToMany(
	ctx context.Context, appends []eventsourcing.StreamAppend,
) ([]eventsourcing.AppendResult, error) {
	if len(appends) == 0 {
		return nil, nil
	}
	// One stream is an ordinary append. Routing it here anyway would give the
	// same operation two code paths with different error handling.
	if len(appends) == 1 {
		res, err := s.Append(ctx, appends[0].Stream, appends[0].Expected, appends[0].Events)
		if err != nil {
			return nil, err
		}
		return []eventsourcing.AppendResult{res}, nil
	}

	seen := make(map[eventsourcing.StreamID]struct{}, len(appends))
	requests := make([]kurrentdb.AppendStreamRequest, 0, len(appends))
	for _, a := range appends {
		if len(a.Events) == 0 {
			return nil, fmt.Errorf("kurrentdb: multi-append to %s carries no events", a.Stream)
		}
		// Two entries for one stream would have two preconditions against the
		// same revision, so at most one can hold. Rejecting here names the
		// mistake; the server would report a confusing revision conflict.
		if _, dup := seen[a.Stream]; dup {
			return nil, fmt.Errorf("kurrentdb: multi-append names %s twice; "+
				"put those events in one entry", a.Stream)
		}
		seen[a.Stream] = struct{}{}

		data, err := s.toEventData(a.Events)
		if err != nil {
			return nil, err
		}
		requests = append(requests, kurrentdb.AppendStreamRequest{
			StreamName:          a.Stream.String(),
			Events:              sliceSeq(data),
			ExpectedStreamState: toStreamState(a.Expected),
		})
	}

	res, err := s.client.MultiStreamAppend(ctx, sliceSeq(requests))
	if err != nil {
		// The multi-append path reports a precondition failure as
		// ErrorCodeStreamRevisionConflict, NOT the ErrorCodeWrongExpectedVersion
		// a single-stream append returns. Verified against the running server:
		// mapping only the latter left every failed reservation looking like an
		// infrastructure fault instead of the ordinary contention it is.
		var kerr *kurrentdb.Error
		if errors.As(err, &kerr) &&
			(kerr.Code() == kurrentdb.ErrorCodeWrongExpectedVersion ||
				kerr.Code() == kurrentdb.ErrorCodeStreamRevisionConflict) {
			// Expected under concurrency, and atomic: NOTHING was written, so the
			// caller reloads and re-decides exactly as for a single-stream append.
			return nil, fmt.Errorf("%w: one of %d streams in an atomic append",
				eventsourcing.ErrWrongExpectedRevision, len(appends))
		}
		return nil, fmt.Errorf("kurrentdb: atomic append across %d streams: %w", len(appends), err)
	}

	// The server reports ONE log position for the whole append and a revision per
	// stream. Position.Prepare is left equal to Commit: the multi-append API does
	// not report a prepare position, and inventing one would produce a resume
	// point that does not correspond to anything.
	out := make([]eventsourcing.AppendResult, 0, len(res.Responses))
	byStream := make(map[string]int64, len(res.Responses))
	for _, r := range res.Responses {
		byStream[r.Stream] = r.StreamRevision
	}
	pos := eventsourcing.Position{
		Commit:  uint64(res.Position), //nolint:gosec // a log position is never negative
		Prepare: uint64(res.Position), //nolint:gosec
	}
	for _, a := range appends {
		rev, ok := byStream[a.Stream.String()]
		if !ok {
			return nil, fmt.Errorf("kurrentdb: the server reported no result for %s in an "+
				"atomic append; the write cannot be confirmed", a.Stream)
		}
		out = append(out, eventsourcing.AppendResult{
			Revision: eventsourcing.Revision(rev),
			Position: pos,
		})
	}
	return out, nil
}

// toEventData marshals pending events. Shared with Append so one path cannot
// acquire an encoding the other does not have.
func (s *Store) toEventData(events []eventsourcing.PendingEvent) ([]kurrentdb.EventData, error) {
	data := make([]kurrentdb.EventData, 0, len(events))
	for _, pe := range events {
		payload, err := s.codec.Marshal(pe.Event)
		if err != nil {
			return nil, fmt.Errorf("kurrentdb: marshal %s: %w", pe.Event.EventType(), err)
		}
		// Checked HERE, after encoding and before the wire, because the encoded
		// size is the only one that matters and this is the single place both
		// append paths pass through. Refusing our own oversized append names the
		// event; the server's refusal is a generic write failure arriving after
		// the command has already reserved uniqueness.
		large, err := eventsourcing.CheckEventSize(pe.Event.EventType(), payload)
		if err != nil {
			return nil, err
		}
		if large {
			slog.Warn("event payload is large; log throughput is a function of payload size, "+
				"and bytes this size usually belong in object storage with the event carrying a reference",
				"event_type", pe.Event.EventType(),
				"bytes", len(payload),
				"threshold", eventsourcing.LargeEventBytes)
		}
		meta, err := s.codec.MarshalMetadata(pe.Meta)
		if err != nil {
			return nil, fmt.Errorf("kurrentdb: marshal metadata: %w", err)
		}
		data = append(data, kurrentdb.EventData{
			EventID:     toUUID(pe.ID),
			EventType:   pe.Event.EventType(),
			ContentType: kurrentdb.ContentTypeJson,
			Data:        payload,
			Metadata:    meta,
		})
	}
	return data, nil
}

// sliceSeq adapts a slice to the iterator the multi-append API takes.
func sliceSeq[T any](items []T) iter.Seq[T] {
	return func(yield func(T) bool) {
		for _, item := range items {
			if !yield(item) {
				return
			}
		}
	}
}
