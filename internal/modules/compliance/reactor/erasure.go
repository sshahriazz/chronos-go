// Package reactor consumes the events compliance must act on.
package reactor

import (
	"context"
	"errors"
	"fmt"

	identitycontract "github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/workflow"
)

// ErasureReactorName is the persistent subscription group, and it is PERMANENT.
//
// Renaming it creates a fresh group positioned at the END of the log (ADR-019),
// silently abandoning every erasure request the old group had not yet started a
// workflow for. Each one is a person who asked to be forgotten, was told a date,
// and would still be in the database after it — with nothing anywhere reporting
// a failure, because from this system's side nothing happened.
const ErasureReactorName = "compliance-erasure"

// Starter begins the grace-period workflow.
//
// The platform's own port rather than a narrower one of this module's: a second
// convention for "start a workflow" is a second place for the no-personal-data
// rule on workflow input to be forgotten.
type Starter interface {
	Start(ctx context.Context, s workflow.Start) (workflow.Run, error)
}

// ErasureArgs is what the workflow is started with.
//
// A pseudonym and nothing else. Workflow input is written to HISTORY, which is
// durable and replicated, so ADR-002 applies here exactly as it does to the
// event log — and it applies with particular force to this workflow, since an
// address in the argument would be personal data sitting in the one store
// erasure cannot reach.
//
// It mirrors the adapter's ErasureInput rather than importing it: a module may
// not import an adapter, and the two are matched by their field names on the
// wire.
type ErasureArgs struct {
	SubjectID string
}

// Erasure turns a deletion request into a running clock.
//
// # Why a workflow and not a sweep
//
// A sweep over "requests whose deadline has passed" would work, and it would put
// the statutory obligation on a job that has to be running, that has to be
// scanning the right table, and whose absence is a silence. A workflow per
// request is durable in Temporal, visible in its UI, and retries for as long as
// it takes — which is what an obligation with a legal clock needs.
//
// The reconciliation sweep still has a place as a BACKSTOP, and it is not built
// here. It is named in the worklist rather than implied by this comment.
type Erasure struct {
	starter      Starter
	workflowName string
	codec        eventsourcing.Codec
}

// NewErasure builds the reactor.
//
// Both dependencies are required. A nil starter produces a reactor that consumes
// the event, does nothing, and acks — indistinguishable at runtime from the gap
// this closes, and the gap is an unmet legal obligation.
func NewErasure(
	starter Starter, workflowName string, codec eventsourcing.Codec,
) (*Erasure, error) {
	switch {
	case workflowName == "":
		return nil, errors.New("compliance/reactor: a workflow name is required; it is " +
			"persisted in history, so an empty one starts nothing and strands the request")
	case starter == nil:
		return nil, errors.New("compliance/reactor: an erasure starter is required; without " +
			"one every deletion request is consumed and dropped, and the account keeps " +
			"working indefinitely")
	case codec == nil:
		return nil, errors.New("compliance/reactor: a codec is required; without one the " +
			"event cannot be decoded and every request parks")
	}
	return &Erasure{starter: starter, workflowName: workflowName, codec: codec}, nil
}

// Name is the persistent subscription group.
func (r *Erasure) Name() string { return ErasureReactorName }

// Filter narrows the subscription to the request event.
//
// Only the REQUEST starts a clock. Cancellation is read by the workflow when it
// wakes, not reacted to here: a reactor that cancelled the workflow would have
// to find it, and the workflow already re-reads for exactly this reason.
func (r *Erasure) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		EventTypePrefixes: []string{deletionRequestedType},
	}
}

// Taken from the contract type rather than written out, so it cannot drift from
// what the codec registers and identity appends.
var deletionRequestedType = (&identitycontract.UserDeletionRequested{}).EventType()

// React starts the grace-period workflow for one request.
func (r *Erasure) React(ctx context.Context, env eventsourcing.Envelope) error {
	if env.Type != deletionRequestedType {
		// The filter over-delivered, or the group predates the filter. Not an
		// error, and deliberately not a start: reacting to whatever arrives
		// would let a filter change put erasure clocks on unrelated subjects.
		return nil
	}

	event, err := r.codec.Unmarshal(env.Type, env.Payload)
	if err != nil {
		return fmt.Errorf("%w: compliance/reactor: decoding %s: %w",
			eventsourcing.ErrPoison, env.Type, err)
	}
	requested, ok := event.(*identitycontract.UserDeletionRequested)
	if !ok {
		return fmt.Errorf("%w: compliance/reactor: %s decoded as %T",
			eventsourcing.ErrPoison, env.Type, event)
	}
	if requested.SubjectID == "" {
		// Retrying re-reads the same bytes. Poison rather than a failure — and
		// an empty subject reaching the workflow would start a run that can only
		// ever fail.
		return fmt.Errorf("%w: compliance/reactor: %s names no subject",
			eventsourcing.ErrPoison, env.Type)
	}

	// Keyed on the SUBJECT rather than the event id, so a redelivery finds the
	// workflow already running rather than starting a second clock on the same
	// account.
	//
	// A cancel-then-request cycle appends a new event under the SAME key, which
	// is correct and needs saying: the first run ended when it read the
	// cancellation, so the id is free and Temporal starts a fresh one. Keying on
	// the event id instead would leave two clocks racing on one account, and the
	// loser would erase after the winner had already been cancelled.
	_, err = r.starter.Start(ctx, workflow.Start{
		ID:    "erasure:" + requested.SubjectID,
		Name:  r.workflowName,
		Input: ErasureArgs{SubjectID: requested.SubjectID},
	})
	if errors.Is(err, workflow.ErrAlreadyStarted) {
		// The clock is already running for this subject. The ordinary case for a
		// redelivery, and not a failure.
		return nil
	}
	if err != nil {
		return fmt.Errorf("compliance/reactor: starting the erasure clock for %s: %w",
			requested.SubjectID, err)
	}
	return nil
}
