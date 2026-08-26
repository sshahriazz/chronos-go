package kurrentdb

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	compliancedomain "github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/operator/app"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// LegalHolds writes compliance's LegalHold aggregate on the operator's behalf.
//
// The same shape as Organizations and for the same reason: the operator plane
// calls the owning module's own aggregate and appends the owning module's own
// event. compliance's erasure gate reads that event and knows nothing about the
// operator plane — which is what lets the check be written once and hold for
// any future way of placing a hold.
type LegalHolds struct {
	repo *eventsourcing.Repository[*compliancedomain.LegalHold]
}

// NewLegalHolds builds the writer.
func NewLegalHolds(
	store eventsourcing.EventStore,
	codec eventsourcing.Codec,
	upcasters *eventsourcing.UpcasterRegistry,
) (*LegalHolds, error) {
	if store == nil || codec == nil {
		return nil, fmt.Errorf("operator kurrentdb: the legal-hold writer needs a store and a codec")
	}
	return &LegalHolds{
		repo: eventsourcing.NewRepository(store, codec, upcasters,
			compliancedomain.LegalHoldCategory, compliancedomain.NewLegalHold),
	}, nil
}

var _ app.TenantLegalHolds = (*LegalHolds)(nil)

// Place holds a subject's data.
func (h *LegalHolds) Place(
	ctx context.Context, subjectID, placedBy, matter string, at time.Time,
) error {
	agg, err := h.repo.Load(ctx, compliancedomain.LegalHoldStreamKey(subjectID))
	if err != nil {
		return fmt.Errorf("loading legal holds for %s: %w", subjectID, err)
	}
	if err := agg.Place(subjectID, placedBy, matter, at); err != nil {
		return err
	}
	return h.save(ctx, subjectID, agg)
}

// Lift releases a subject, and reports whether anything changed.
func (h *LegalHolds) Lift(
	ctx context.Context, subjectID, liftedBy string, at time.Time,
) (bool, error) {
	agg, err := h.repo.Load(ctx, compliancedomain.LegalHoldStreamKey(subjectID))
	if err != nil {
		return false, fmt.Errorf("loading legal holds for %s: %w", subjectID, err)
	}
	if err := agg.Lift(subjectID, liftedBy, at); err != nil {
		return false, err
	}
	if len(agg.Uncommitted()) == 0 {
		// Not held. A success that changed nothing — lifting a hold that does
		// not exist is asking for a state that already holds.
		return false, nil
	}
	return true, h.save(ctx, subjectID, agg)
}

func (h *LegalHolds) save(
	ctx context.Context, subjectID string, agg *compliancedomain.LegalHold,
) error {
	key := ids.New[ids.Event](time.Now(), rand.Reader).String()
	if _, err := h.repo.Save(ctx, compliancedomain.LegalHoldStreamKey(subjectID), agg, key,
		eventsourcing.Metadata{}); err != nil {
		return fmt.Errorf("appending a legal hold for %s: %w", subjectID, err)
	}
	return nil
}
