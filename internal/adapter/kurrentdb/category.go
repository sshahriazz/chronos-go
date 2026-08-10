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
	_ eventsourcing.CategoryReader = (*Store)(nil)
	_ eventsourcing.TypeReader     = (*Store)(nil)
	_ eventsourcing.Deleter        = (*Store)(nil)
)

// ReadCategory streams every event of one aggregate type in log order.
//
// This is the rebuild path. A filtered $all subscription makes the SERVER walk
// the entire log even when a projection wants a fraction of it, so rebuild cost
// tracks total log size rather than the projection's slice. A category stream
// reads only the slice: measured at 253 ms versus 17 ms for 1,000 events out of
// 20,000 — 14.8x.
//
// ResolveLinkTos is mandatory: a $ce- stream contains LINK events pointing at
// the originals. Without it every event arrives as an unreadable link and the
// projection rebuilds into an empty table while reporting success.
func (s *Store) ReadCategory(
	ctx context.Context, category eventsourcing.Category, h eventsourcing.Handler,
) error {
	return s.readLinkStream(ctx, "$ce-"+string(category), "category "+string(category), h)
}

// ReadEventType streams every event of one exact type in log order.
//
// Narrower than a category stream, and cheaper in proportion: $ce-notification
// carries every type the notification aggregate emits, so a projection that
// wants one of them reads and discards the rest. $et- carries only that type.
//
// Exact types only, never prefixes. There is no $et- stream for a prefix, and
// "notification.Created.v1" as a prefix would also select
// "notification.Created.v10" — a stream that does not exist and a version that
// does.
func (s *Store) ReadEventType(ctx context.Context, eventType string, h eventsourcing.Handler) error {
	return s.readLinkStream(ctx, "$et-"+eventType, "event type "+eventType, h)
}

// readLinkStream drains one system link stream into h.
//
// ResolveLinkTos is mandatory: a $ce- or $et- stream contains LINK events
// pointing at the originals. Without it every event arrives as an unreadable
// link and the projection rebuilds into an empty table while reporting success.
//
// A missing stream is not an error. It means no events of that category or type
// exist yet, or the system projection has not caught up — and an empty rebuild
// is the right answer for an empty slice of the log.
func (s *Store) readLinkStream(
	ctx context.Context, stream, describe string, h eventsourcing.Handler,
) error {
	rs, err := s.client.ReadStream(ctx, stream,
		kurrentdb.ReadStreamOptions{
			Direction:      kurrentdb.Forwards,
			From:           kurrentdb.Start{},
			ResolveLinkTos: true,
		}, ^uint64(0))
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("kurrentdb: reading %s: %w", describe, err)
	}
	defer rs.Close()

	for {
		resolved, err := rs.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			if isNotFound(err) {
				return nil
			}
			return fmt.Errorf("kurrentdb: reading %s: %w", describe, err)
		}
		if resolved.Event == nil {
			// A link whose target was scavenged or deleted.
			continue
		}
		rec := toRecorded(resolved.Event)
		if rec.IsSystem() {
			continue
		}
		if err := h(ctx, rec); err != nil {
			return err
		}
	}
}

// SoftDelete makes a stream unreadable and reclaimable by the next scavenge.
func (s *Store) SoftDelete(ctx context.Context, stream eventsourcing.StreamID) error {
	if _, err := s.client.DeleteStream(ctx, stream.String(),
		kurrentdb.DeleteStreamOptions{StreamState: kurrentdb.Any{}}); err != nil {
		return fmt.Errorf("kurrentdb: deleting %s: %w", stream, err)
	}
	return nil
}

// Tombstone deletes a stream permanently and irreversibly.
//
// The stream name is burned: any future append to it fails forever. This exists
// for erasure obligations that crypto-shredding cannot satisfy, and it should be
// reached for only when destroying the key is genuinely not enough (ADR-002).
func (s *Store) Tombstone(ctx context.Context, stream eventsourcing.StreamID) error {
	if _, err := s.client.TombstoneStream(ctx, stream.String(),
		kurrentdb.TombstoneStreamOptions{StreamState: kurrentdb.Any{}}); err != nil {
		return fmt.Errorf("kurrentdb: tombstoning %s: %w", stream, err)
	}
	return nil
}
