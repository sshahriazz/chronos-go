// Package workflow is the kernel's view of durable, long-running work.
//
// It declares WHAT the system can start and what starting means; it knows
// nothing about Temporal, and nothing here imports the SDK (ADR-001). The
// adapter in internal/adapter/temporal implements it.
//
// The distinction that matters: a REACTOR performs one effect and is done, and
// its retries are the subscription's. Work that spans several effects, needs
// timers, or must survive a process dying halfway belongs here — mail sending,
// reserve-change-release, scheduled scavenging (ADR-017). A goroutine, a
// time.AfterFunc or a cron table are all forbidden alternatives, because none of
// them survives the process that started them.
package workflow

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrAlreadyStarted means a run with this ID already exists.
//
// It is not a failure. Workflow IDs are derived from the event that caused them
// (EVENT-SOURCING §9), so a redelivered event tries to start the same run twice
// and the second attempt SHOULD be refused — that refusal is the idempotency
// guarantee, in the same way the event store's duplicate-append rejection is.
var ErrAlreadyStarted = errors.New("workflow: a run with this id already exists")

// ErrUnavailable means the workflow service could not be reached, so the work
// was NOT started. Callers must treat it as "not done" and retry — a reactor
// returns it and the event is redelivered.
var ErrUnavailable = errors.New("workflow: service unavailable")

// Run identifies one started execution.
type Run struct {
	// ID is the caller-chosen workflow id — always derived, never random.
	ID string

	// RunID is the service's identifier for this particular attempt. It changes
	// if the workflow is retried or continued-as-new, so nothing durable should
	// key on it.
	RunID string
}

// Start describes work to begin.
type Start struct {
	// ID makes the start idempotent and MUST be derived from what caused it —
	// normally the event id. A random id turns every redelivery into a second
	// run, which for mail is a second email.
	ID string

	// Name is the registered workflow name. It is persisted in history, so it
	// is permanent: renaming one strands every in-flight execution.
	Name string

	// Queue is the task queue whose workers may run it. Empty takes the
	// adapter's configured default.
	Queue string

	// Input is the workflow argument. It is written to workflow HISTORY, which
	// is durable, replicated and long-lived — so the event-log rule applies
	// unchanged: NO personal data, only SubjectID pseudonyms (ADR-002). A
	// workflow that needs an address resolves it from the vault inside an
	// activity, at the moment it sends.
	Input any
}

// Validate rejects a start that could only misbehave.
func (s Start) Validate() error {
	switch {
	case strings.TrimSpace(s.ID) == "":
		return fmt.Errorf("workflow: a start needs an id derived from its cause; " +
			"without one a redelivered event starts a second run")
	case strings.TrimSpace(s.Name) == "":
		return errors.New("workflow: a start needs a workflow name")
	}
	return nil
}

// Starter begins durable work.
//
// Declared here because this package is its consumer (CONVENTIONS §2). The
// reactor that calls it does not know whether Temporal, or anything else, is
// behind it.
type Starter interface {
	Start(ctx context.Context, s Start) (Run, error)
}
