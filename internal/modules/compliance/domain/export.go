package domain

import (
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/contract"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// ExportCategory is the stream category, and it is PERMANENT: it is half of
// every stream name, so changing it orphans every export ever requested.
const ExportCategory eventsourcing.Category = "dataexport"

// ExportStreamKey is the export's own id.
//
// One stream per REQUEST, which is the opposite of Restriction above and for the
// opposite reason. A restriction is a STATE — halted or not — so it belongs on
// one stream per subject. An export is an EVENT in a person's life that produced
// an artefact, and a person may exercise Article 15 more than once: a stream per
// subject would make "what happened to the export I asked for on Tuesday" a
// question about which events in a long stream belong together.
func ExportStreamKey(exportID string) string { return exportID }

// ExportState is where one request has got to.
type ExportState string

const (
	// ExportStateNone is a stream with no events. The zero value, so an
	// unrequested export is never mistaken for a pending one.
	ExportStateNone ExportState = ""

	// ExportStatePending means the workflow is building the bundle.
	ExportStatePending ExportState = "pending"

	// ExportStateReady means the manifest exists and can be fetched.
	ExportStateReady ExportState = "ready"

	// ExportStateFailed means the workflow stopped without producing one.
	ExportStateFailed ExportState = "failed"
)

// Export is one data-subject request and what became of it.
//
// # Why the log rather than only the workflow
//
// Temporal knows whether a workflow is running, and asking it would be the
// obvious way to answer "is my export ready". It is the wrong authority twice
// over: workflow histories are retained for a bounded period and then gone,
// while Article 15's evidence that somebody exercised the right has to outlive
// that; and a read path that asked Temporal would stop answering during a
// Temporal outage, turning "your export is still building" into an error on the
// one endpoint a person uses when they are already unhappy with us.
//
// So the workflow does the work and appends the outcome, and every read is a
// question about the log.
type Export struct {
	eventsourcing.Base

	exportID    string
	subjectID   string
	state       ExportState
	manifestKey string
	objectCount int
	requestedAt time.Time
	completedAt time.Time
	reason      string
}

var _ eventsourcing.Root = (*Export)(nil)

// NewExport returns an empty aggregate for the repository to rebuild into.
func NewExport() *Export { return &Export{} }

func (e *Export) ExportID() string       { return e.exportID }
func (e *Export) SubjectID() string      { return e.subjectID }
func (e *Export) State() ExportState     { return e.state }
func (e *Export) ManifestKey() string    { return e.manifestKey }
func (e *Export) ObjectCount() int       { return e.objectCount }
func (e *Export) Reason() string         { return e.reason }
func (e *Export) RequestedAt() time.Time { return e.requestedAt }
func (e *Export) CompletedAt() time.Time { return e.completedAt }

// Exists reports whether anything was ever requested here.
func (e *Export) Exists() bool { return e.state != ExportStateNone }

// Apply is the pure transition.
func (e *Export) Apply(ev eventsourcing.Event) {
	switch t := ev.(type) {
	case *contract.DataExportRequested:
		e.exportID = t.ExportID
		e.subjectID = t.SubjectID
		e.state = ExportStatePending
		e.requestedAt = t.RequestedAt

	case *contract.DataExportCompleted:
		e.state = ExportStateReady
		e.manifestKey = t.ManifestKey
		e.objectCount = t.ObjectCount
		e.completedAt = t.CompletedAt
		// The reason is CLEARED. A completed export that still carried a failure
		// reason would read, to anybody querying it, as having both succeeded and
		// failed — and a retried workflow that succeeds after failing is the
		// ordinary case, not an exotic one.
		e.reason = ""

	case *contract.DataExportFailed:
		e.state = ExportStateFailed
		e.reason = t.Reason
		e.completedAt = t.FailedAt
	}
}

// Request records that a subject asked for their data.
func (e *Export) Request(exportID, subjectID string, at time.Time) error {
	switch {
	case exportID == "":
		return errs.ValidationFailedf("an export id is required")
	case subjectID == "":
		return errs.ValidationFailedf("a subject id is required")
	}
	if e.Exists() {
		// A retried command for the SAME request. Records nothing rather than a
		// second request event: the id is derived from the caller's idempotency
		// key, so a retry lands here and must not start a second workflow.
		return nil
	}
	eventsourcing.Record(e, &contract.DataExportRequested{
		SubjectID:   subjectID,
		ExportID:    exportID,
		RequestedAt: at.UTC(),
	})
	return nil
}

// Complete records that the bundle exists.
//
// Refused for an export that was never requested: an outcome for a request
// nobody made is a bundle nobody can be shown to have asked for, which is
// exactly the shape Article 15's evidence must not have.
func (e *Export) Complete(manifestKey string, objectCount int, at time.Time) error {
	switch {
	case !e.Exists():
		return errs.NotFoundf("no such export")
	case manifestKey == "":
		return errs.ValidationFailedf("a completed export must name its manifest")
	case objectCount < 0:
		return errs.ValidationFailedf("an object count cannot be negative")
	}
	if e.state == ExportStateReady && e.manifestKey == manifestKey {
		// The same completion again. A workflow activity is at-least-once, so this
		// is the ordinary retry rather than an error.
		return nil
	}
	eventsourcing.Record(e, &contract.DataExportCompleted{
		SubjectID:   e.subjectID,
		ExportID:    e.exportID,
		ManifestKey: manifestKey,
		ObjectCount: objectCount,
		CompletedAt: at.UTC(),
	})
	return nil
}

// Fail records that the bundle could not be produced.
//
// # A READY export is never failed afterwards
//
// The refusal is the point rather than tidiness. The workflow appends the
// completion and then finishes; a redelivered failure from an earlier attempt —
// or a late timeout on a run that had already succeeded — would otherwise
// overwrite a fetchable bundle with an error, and the subject would be told
// their export failed while the manifest sat there waiting for them.
func (e *Export) Fail(reason string, at time.Time) error {
	switch {
	case !e.Exists():
		return errs.NotFoundf("no such export")
	case reason == "":
		return errs.ValidationFailedf("a failed export must state a reason")
	}
	if e.state == ExportStateReady {
		return errs.Conflictf("this export has already been produced")
	}
	if e.state == ExportStateFailed && e.reason == reason {
		return nil
	}
	eventsourcing.Record(e, &contract.DataExportFailed{
		SubjectID: e.subjectID,
		ExportID:  e.exportID,
		Reason:    reason,
		FailedAt:  at.UTC(),
	})
	return nil
}
