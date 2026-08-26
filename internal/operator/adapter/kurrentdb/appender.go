// Package kurrentdb appends the operator plane's events.
//
// A thin adapter over the shared event-sourcing repository rather than a second
// client: the operator plane writes to the SAME event log as everything else,
// because "what happened" has one answer in this system (ADR-013). What is
// separate here is the read model and the database role, not the log.
package kurrentdb

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/operator/app"
	"github.com/chronos/chronos-go/internal/operator/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// Appender writes operator and audit events.
type Appender struct {
	audit     *eventsourcing.Repository[*domain.AuditEntry]
	operators *eventsourcing.Repository[*domain.Operator]
	clock     func() time.Time
}

// New builds the appender.
func New(
	store eventsourcing.EventStore,
	codec eventsourcing.Codec,
	upcasters *eventsourcing.UpcasterRegistry,
	clock func() time.Time,
) (*Appender, error) {
	if store == nil || codec == nil {
		return nil, fmt.Errorf("operator kurrentdb: the appender needs a store and a codec")
	}
	if clock == nil {
		clock = time.Now
	}
	return &Appender{
		clock: clock,
		audit: eventsourcing.NewRepository(store, codec, upcasters,
			domain.AuditCategory, domain.NewAuditEntry),
		operators: eventsourcing.NewRepository(store, codec, upcasters,
			domain.OperatorCategory, domain.NewOperator),
	}, nil
}

var _ app.EventAppender = (*Appender)(nil)

// AppendAudit writes one audit event to its own stream.
//
// The idempotency key is the ENTRY ID, which is minted per action and never
// reused. That is deliberate and it is the opposite of the tenant plane's
// convention: there, a retried command must collapse onto its first append, so
// the key comes from the caller's Idempotency-Key. Here a repeat is not a
// retry — an operator who opened the same customer twice performed two
// processing activities, and collapsing them would make the audit trail
// under-report access, which is the one direction it must never be wrong in.
func (a *Appender) AppendAudit(ctx context.Context, entryID string, ev any) error {
	event, ok := ev.(eventsourcing.Event)
	if !ok {
		return fmt.Errorf("operator kurrentdb: %T is not an event", ev)
	}

	entry := eventsourcing.NewAggregate(domain.NewAuditEntry)
	eventsourcing.Record(entry, event)

	if _, err := a.audit.Save(ctx, domain.AuditStreamKey(entryID), entry, entryID,
		eventsourcing.Metadata{}); err != nil {
		return fmt.Errorf("operator kurrentdb: appending an audit entry: %w", err)
	}
	return nil
}

// AppendOperator writes to an operator's own stream.
//
// It LOADS first, so the append carries the optimistic precondition implied by
// the version it read. Two operator_admins changing one operator's role at once
// is rare and is exactly the case operator.md §5's D15 answers: the second
// write fails with a conflict and the admin is shown what changed, rather than
// one grant silently overwriting the other.
func (a *Appender) AppendOperator(ctx context.Context, operatorID string, ev any) error {
	event, ok := ev.(eventsourcing.Event)
	if !ok {
		return fmt.Errorf("operator kurrentdb: %T is not an event", ev)
	}

	agg, err := a.operators.Load(ctx, domain.OperatorStreamKey(operatorID))
	if err != nil {
		return fmt.Errorf("operator kurrentdb: loading operator %s: %w", operatorID, err)
	}
	eventsourcing.Record(agg, event)

	// A fresh idempotency key per append.
	//
	// Unlike the audit path this COULD be derived from a command key, and is
	// not: every caller is a server-initiated write with no client key to
	// derive from, and a constant key would make two legitimate consecutive
	// appends collide on the same derived event id. The optimistic version
	// precondition above is what actually protects against a lost update here.
	key := ids.New[ids.Event](a.clock(), rand.Reader).String()

	if _, err := a.operators.Save(ctx, domain.OperatorStreamKey(operatorID), agg, key,
		eventsourcing.Metadata{}); err != nil {
		return fmt.Errorf("operator kurrentdb: appending to operator %s: %w", operatorID, err)
	}
	return nil
}
