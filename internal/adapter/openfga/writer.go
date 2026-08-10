package openfga

import (
	"context"
	"fmt"

	fgav1 "github.com/chronos/chronos-go/gen/thirdparty/openfga/v1"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"google.golang.org/grpc"
)

// maxTuplesPerWrite is OpenFGA's server-side limit on one Write request.
//
// Exceeding it fails the WHOLE request, so a projector applying a large event —
// a team of 200 given access to a folder — would stall permanently rather than
// partially succeed. Batching here is what keeps that a latency cost instead of
// an outage.
const maxTuplesPerWrite = 100

// Writer is the write side of the authorization graph (access.md §15).
//
// Reachable from a projector only. It lives in its own type rather than on
// Checker so that handing a request handler a Checker cannot also hand it the
// ability to write a tuple — the restriction is enforced by what a caller holds,
// not by a comment.
type Writer struct {
	client  fgav1.OpenFGAServiceClient
	storeID string
	modelID string
}

var _ authz.TupleWriter = (*Writer)(nil)

func NewWriter(conn *grpc.ClientConn, cfg Config) (*Writer, error) {
	if conn == nil {
		return nil, fmt.Errorf("openfga: a connection is required")
	}
	if cfg.StoreID == "" {
		return nil, fmt.Errorf("openfga: a store id is required; without one every tuple " +
			"would be written to no store at all")
	}
	return &Writer{
		client:  fgav1.NewOpenFGAServiceClient(conn),
		storeID: cfg.StoreID,
		modelID: cfg.ModelID,
	}, nil
}

// Write adds edges, tolerating ones that already exist.
//
// `on_duplicate: ignore` is what makes this replay-safe. Without it, OpenFGA
// answers a duplicate with `write_failed_due_to_invalid_input`, and since a
// projector re-applies events on every restart and every rebuild, the second
// pass over the same grant would stop the projection for good.
func (w *Writer) Write(ctx context.Context, tuples []authz.Tuple) error {
	return w.each(ctx, tuples, func(ctx context.Context, batch []authz.Tuple) error {
		keys := make([]*fgav1.TupleKey, 0, len(batch))
		for _, t := range batch {
			keys = append(keys, &fgav1.TupleKey{
				User:     t.Subject.String(),
				Relation: string(t.Relation),
				Object:   t.Resource.String(),
			})
		}
		_, err := w.client.Write(ctx, &fgav1.WriteRequest{
			StoreId:              w.storeID,
			AuthorizationModelId: w.modelID,
			Writes: &fgav1.WriteRequestWrites{
				TupleKeys:   keys,
				OnDuplicate: onDuplicateIgnore,
			},
		})
		if err != nil {
			return fmt.Errorf("%w: writing %d tuples: %w", authz.ErrUnavailable, len(batch), err)
		}
		return nil
	})
}

// Delete removes edges, tolerating ones that are already gone.
//
// `on_missing: ignore` for the same reason as Write, and one that matters more:
// a delete that failed because the tuple was already removed would abort the
// batch, so the tombstones behind it would never be confirmed and every
// principal in that batch would stay denied until the TTL.
func (w *Writer) Delete(ctx context.Context, tuples []authz.Tuple) error {
	return w.each(ctx, tuples, func(ctx context.Context, batch []authz.Tuple) error {
		keys := make([]*fgav1.TupleKeyWithoutCondition, 0, len(batch))
		for _, t := range batch {
			keys = append(keys, &fgav1.TupleKeyWithoutCondition{
				User:     t.Subject.String(),
				Relation: string(t.Relation),
				Object:   t.Resource.String(),
			})
		}
		_, err := w.client.Write(ctx, &fgav1.WriteRequest{
			StoreId:              w.storeID,
			AuthorizationModelId: w.modelID,
			Deletes: &fgav1.WriteRequestDeletes{
				TupleKeys: keys,
				OnMissing: onMissingIgnore,
			},
		})
		if err != nil {
			return fmt.Errorf("%w: deleting %d tuples: %w", authz.ErrUnavailable, len(batch), err)
		}
		return nil
	})
}

// The server's spellings. Written once, because a typo here is not rejected —
// an unrecognised value falls back to "error" and the idempotency this whole
// design depends on is silently gone.
const (
	onDuplicateIgnore = "ignore"
	onMissingIgnore   = "ignore"
)

// each validates every tuple BEFORE sending any of them, then applies them in
// server-sized batches.
//
// Validating the whole set first is deliberate: a malformed tuple discovered
// halfway through would leave the graph holding part of one event's changes,
// which is drift that no replay corrects — the event has already been applied
// as far as the projector is concerned.
func (w *Writer) each(ctx context.Context, tuples []authz.Tuple, fn func(context.Context, []authz.Tuple) error) error {
	if len(tuples) == 0 {
		return nil
	}
	for _, t := range tuples {
		if err := t.Validate(); err != nil {
			return fmt.Errorf("openfga: refusing to apply %s: %w", t, err)
		}
	}
	for start := 0; start < len(tuples); start += maxTuplesPerWrite {
		end := min(start+maxTuplesPerWrite, len(tuples))
		if err := fn(ctx, tuples[start:end]); err != nil {
			return err
		}
	}
	return nil
}
