// Package adapter implements compliance's ports.
package adapter

import (
	"context"
	"fmt"

	"github.com/chronos/chronos-go/internal/modules/compliance/app"
	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// LegalHolds answers "is this subject held" from the EVENT LOG.
//
// # From the log, not from a projection, and this is the one place that matters
//
// Every other read in this system tolerates a projection being a second behind:
// a poll corrects itself, a list refreshes. This one gates an IRREVERSIBLE
// destruction — and the direction of the lag is the wrong one.
//
// A hold placed moments before an erasure runs would not yet be in a
// projection, so the check would say "not held" and the key would be destroyed
// under a live court order. There is no correcting poll after that.
//
// The reverse lag is harmless: a hold LIFTED and not yet projected would defer
// an erasure that could have proceeded, and the next attempt runs it.
//
// So this reads the stream. It costs one round trip per erasure, which is a
// rare operation with a statutory deadline measured in days.
type LegalHolds struct {
	repo *eventsourcing.Repository[*domain.LegalHold]
}

// NewLegalHolds builds the reader.
func NewLegalHolds(
	store eventsourcing.EventStore,
	codec eventsourcing.Codec,
	upcasters *eventsourcing.UpcasterRegistry,
) (*LegalHolds, error) {
	if store == nil || codec == nil {
		return nil, fmt.Errorf("compliance: the legal-hold reader needs a store and a codec")
	}
	return &LegalHolds{
		repo: eventsourcing.NewRepository(store, codec, upcasters,
			domain.LegalHoldCategory, domain.NewLegalHold),
	}, nil
}

var _ app.LegalHolds = (*LegalHolds)(nil)

// Held reports whether this subject is currently held, and under what matter.
//
// An error is returned rather than swallowed into `false`. The caller treats a
// failure to answer as a reason not to proceed, which is the whole point of
// asking — and a reader that reported "not held" when it could not tell would
// turn an unreachable event store into a destroyed key.
func (h *LegalHolds) Held(ctx context.Context, subjectID string) (string, bool, error) {
	agg, err := h.repo.Load(ctx, domain.LegalHoldStreamKey(subjectID))
	if err != nil {
		return "", false, fmt.Errorf("compliance: loading legal holds for %s: %w", subjectID, err)
	}
	// A missing stream is not an error: the repository returns a new aggregate,
	// and a subject nothing was ever recorded about is not held. That is the
	// answer for almost everybody, and it is the correct default here even
	// though it is the permissive one — a hold is an EXCEPTION to a statutory
	// right, so defaulting to "held" would withhold a right nobody claimed.
	return agg.Matter(), agg.Held(), nil
}
