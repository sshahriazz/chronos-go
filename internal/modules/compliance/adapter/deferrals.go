package adapter

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/app"
	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// Deferrals records that an erasure is waiting, and that the person was told.
//
// It reads and writes the STREAM rather than a projection, and here that is not
// a lag argument — it is an idempotency one. The aggregate's "already deferred,
// record nothing" is what stops a person being mailed weekly for the length of
// a legal matter, and a projection could report a deferral as absent for the
// window in which the second mail would go out.
type Deferrals struct {
	repo *eventsourcing.Repository[*domain.Deferral]
}

// NewDeferrals builds the recorder.
func NewDeferrals(
	store eventsourcing.EventStore,
	codec eventsourcing.Codec,
	upcasters *eventsourcing.UpcasterRegistry,
) (*Deferrals, error) {
	if store == nil || codec == nil {
		return nil, fmt.Errorf("compliance: the deferral recorder needs a store and a codec")
	}
	return &Deferrals{
		repo: eventsourcing.NewRepository(store, codec, upcasters,
			domain.DeferralCategory, domain.NewDeferral),
	}, nil
}

var _ app.Deferrals = (*Deferrals)(nil)

// Defer records the wait once, and reports whether it recorded anything.
func (d *Deferrals) Defer(ctx context.Context, subjectID string, at time.Time) (bool, error) {
	agg, err := d.repo.Load(ctx, domain.DeferralStreamKey(subjectID))
	if err != nil {
		return false, fmt.Errorf("compliance: loading the deferral of %s: %w", subjectID, err)
	}
	if err := agg.Defer(subjectID, at); err != nil {
		return false, err
	}
	if len(agg.Uncommitted()) == 0 {
		// Already deferred. The common case for every attempt after the first,
		// and it must be free — the workflow reaches it hourly for weeks.
		return false, nil
	}
	return true, d.save(ctx, subjectID, agg)
}

// Resume clears a deferral.
func (d *Deferrals) Resume(ctx context.Context, subjectID string, at time.Time) error {
	agg, err := d.repo.Load(ctx, domain.DeferralStreamKey(subjectID))
	if err != nil {
		return fmt.Errorf("compliance: loading the deferral of %s: %w", subjectID, err)
	}
	if err := agg.Resume(subjectID, at); err != nil {
		return err
	}
	if len(agg.Uncommitted()) == 0 {
		// Nothing was deferred. THE common path — every erasure of an unheld
		// subject reaches it — so it costs one stream read and no append.
		return nil
	}
	return d.save(ctx, subjectID, agg)
}

func (d *Deferrals) save(ctx context.Context, subjectID string, agg *domain.Deferral) error {
	key := ids.New[ids.Event](time.Now(), rand.Reader).String()
	if _, err := d.repo.Save(ctx, domain.DeferralStreamKey(subjectID), agg, key,
		eventsourcing.Metadata{}); err != nil {
		return fmt.Errorf("compliance: recording the deferral of %s: %w", subjectID, err)
	}
	return nil
}
