package reactor

import (
	"context"
	"errors"
	"fmt"

	"github.com/chronos/chronos-go/internal/modules/compliance/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/workflow"
)

// ExportReactorName is the persistent subscription group, and it is PERMANENT.
//
// Renaming it creates a fresh group positioned at the END of the log (ADR-019),
// silently abandoning every export request the old group had not yet started a
// workflow for. Each one is a person who exercised Article 15, was told their
// request was accepted, and would never receive a bundle — with nothing anywhere
// reporting a failure, because from this system's side nothing happened.
const ExportReactorName = "compliance-data-export"

// ExportArgs is what the workflow is started with.
//
// An export id and NOTHING else — not the subject, not a prefix. Workflow input
// is written to HISTORY, which is durable and replicated, so ADR-002 applies
// here exactly as it does to the event log. Everything the run needs is read
// from the log inside its first activity, which means a history somebody reads
// later says an export happened and never whose.
//
// It mirrors the adapter's ExportInput rather than importing it: a module may
// not import an adapter, and the two are matched by field name on the wire.
type ExportArgs struct {
	ExportID string
}

// Export turns an accepted request into a running workflow.
//
// # Why a reactor and not the handler
//
// The handler could start the workflow directly, and that is the version this
// deliberately is not. A request that appended the event and then failed to
// start the run would leave a person's request recorded as pending with nothing
// building it — visible in the log, invisible to everything else, and
// unrecoverable without somebody noticing. Starting from the EVENT means the
// subscription retries until the run exists.
//
// The same shape the erasure reactor uses, for the same reason.
type Export struct {
	starter  Starter
	workflow string
	codec    eventsourcing.Codec
}

// NewExport builds the reactor.
//
// The workflow NAME is passed in rather than named here, exactly as the erasure
// reactor takes its own: a module may not import the adapter that defines it,
// and a constant duplicated across that boundary is a constant that can drift —
// producing requests started against a name no worker answers to, which sit
// forever with no error anywhere.
func NewExport(starter Starter, workflowName string, codec eventsourcing.Codec) (*Export, error) {
	switch {
	case workflowName == "":
		return nil, errors.New("compliance/reactor: the export reactor needs a workflow name")
	case starter == nil:
		return nil, errors.New("compliance/reactor: the export reactor needs a workflow " +
			"starter; without one every accepted request is consumed by nothing and the " +
			"person who asked waits for a bundle nothing is building")
	case codec == nil:
		return nil, errors.New("compliance/reactor: the export reactor needs a codec")
	}
	return &Export{starter: starter, workflow: workflowName, codec: codec}, nil
}

func (e *Export) Name() string { return ExportReactorName }

var exportRequestedType = (&contract.DataExportRequested{}).EventType()

// Filter names the one event exactly.
func (e *Export) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		EventTypePrefixes: []string{exportRequestedType},
	}
}

// React starts the run.
//
// The workflow id is the EXPORT id, which is what makes this idempotent at the
// engine: a redelivered event asks Temporal to start a run that already exists,
// and ErrAlreadyStarted is success rather than a failure. Without that the
// at-least-once subscription would build one person's bundle twice and mail them
// twice about it.
func (e *Export) React(ctx context.Context, env eventsourcing.Envelope) error {
	if env.Type != exportRequestedType {
		// The filter over-delivered, or the group predates the filter. Not an
		// error, and deliberately not a start: reacting to whatever arrives would
		// make a filter change into a workflow.
		return nil
	}

	event, err := e.codec.Unmarshal(env.Type, env.Payload)
	if err != nil {
		return fmt.Errorf("%w: compliance/reactor: decoding %s: %w",
			eventsourcing.ErrPoison, env.Type, err)
	}
	requested, ok := event.(*contract.DataExportRequested)
	if !ok {
		return fmt.Errorf("%w: compliance/reactor: %s decoded as %T",
			eventsourcing.ErrPoison, env.Type, event)
	}
	if requested.ExportID == "" {
		// A run started for no request could never complete: its first activity
		// loads an export by id and finds nothing. Retrying re-reads the same
		// bytes, so this is poison rather than a failure.
		return fmt.Errorf("%w: compliance/reactor: %s records no export id",
			eventsourcing.ErrPoison, env.Type)
	}

	_, err = e.starter.Start(ctx, workflow.Start{
		ID:    "chronos-data-export-" + requested.ExportID,
		Name:  e.workflow,
		Input: ExportArgs{ExportID: requested.ExportID},
	})
	if errors.Is(err, workflow.ErrAlreadyStarted) {
		// Success. A run under this id exists, and the id IS the request, so that
		// run is building exactly this bundle.
		return nil
	}
	if err != nil {
		return fmt.Errorf("compliance/reactor: starting the export run for %s: %w",
			requested.ExportID, err)
	}
	return nil
}
