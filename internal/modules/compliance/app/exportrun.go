package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/contract"
	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/blob"
	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/google/uuid"
)

// exportIDNamespace makes a derived export id reproducible without a store.
//
// A fixed UUIDv5 namespace, exactly as event ids use one: the same idempotency
// key produces the same export id in every process and after every restart, and
// a key from another purpose cannot collide into this space.
var exportIDNamespace = uuid.MustParse("6f4d1a2e-9c3b-4f7a-8d51-2b6e0c9a7f13")

// ExportPageSize is how many objects one listing activity returns.
//
// Small enough that a page is a cheap unit of work to redo after a crash, large
// enough that an ordinary subject's export finishes in one. It is the RESUME
// GRANULARITY: a workflow that dies mid-listing repeats at most this many keys.
const ExportPageSize = 200

// MaxExportPages bounds a single export's listing.
//
// A refusal rather than a truncation, and it mirrors MaxObjectsPerSubject's
// argument from the other direction: an export that silently stopped listing
// would hand somebody an incomplete answer to Article 15 while reporting
// success, which is worse than telling them — and an operator — that their
// account is too large for this path.
const MaxExportPages = MaxObjectsPerSubject / ExportPageSize

// ObjectLister reads one page of a subject's stored objects.
//
// Narrower than blob.Store on purpose: this port can enumerate and cannot
// delete, cannot grant an upload and cannot read an object's bytes. The export
// is compliance.md §3's "most dangerous endpoint in the product", and the code
// building it should hold the least capability that does the job.
type ObjectLister interface {
	ListPage(ctx context.Context, prefix, after string, limit int) (blob.Page, error)
}

// ExportRuns drives one data-subject request from arrival to fetchable bundle.
//
// # Why the steps are separate methods
//
// Each is one Temporal activity. The workflow owns the ORDER and the retries;
// these own the I/O and nothing else, which is what keeps the workflow
// deterministic (CLAUDE.md) — no clock, no network, no randomness in the part
// that replays.
//
// The split is also what makes the export resumable in the sense compliance.md
// §5 asks for. A run that dies after listing four pages restarts, replays the
// four completed activities from history, and issues the fifth listing with the
// cursor the fourth returned. Nothing is re-read from the store and nothing is
// re-decrypted.
type ExportRuns struct {
	exports    *eventsourcing.Repository[*domain.Export]
	profile    SubjectProfile
	objects    ObjectLister
	prefixes   SubjectPrefixes
	store      ExportStore
	prefix     func(subjectID string) string
	blocked    RestrictionReader
	exemptions RetentionExemptions
	now        func() time.Time
}

// RestrictionReader answers whether a subject is under Article 18 restriction.
//
// Consulted at the START of every run and not only at the request, because a
// restriction can arrive while an export is building. compliance.md §6 is
// explicit that a restricted subject gets "no email, no push, no export" — and
// an export already in flight is exactly the processing the restriction stops.
type RestrictionReader interface {
	Restricted(ctx context.Context, subjectID string) (bool, error)
}

// ExportRunsDeps is what the runner needs.
type ExportRunsDeps struct {
	Exports  *eventsourcing.Repository[*domain.Export]
	Profile  SubjectProfile
	Objects  ObjectLister
	Prefixes SubjectPrefixes
	Store    ExportStore

	// Prefix is where the manifest is written: the SUBJECT'S OWN namespace, so
	// erasure removes it by the traversal it already performs.
	Prefix func(subjectID string) string

	// Restrictions blocks a run for a subject under Article 18.
	Restrictions RestrictionReader

	// Exemptions states what this system keeps that is NOT in the bundle, and on
	// what legal basis. Article 15(1) asks about the processing, not only the
	// values.
	Exemptions RetentionExemptions

	Now func() time.Time
}

func NewExportRuns(d ExportRunsDeps) (*ExportRuns, error) {
	switch {
	case d.Exports == nil:
		return nil, errors.New("compliance: an export repository is required; the outcome " +
			"of a data-subject request is a compliance record and it lives in the log")
	case d.Profile == nil:
		return nil, errors.New("compliance: a subject profile source is required; an export " +
			"with no personal data in it answers Article 15 with an empty file")
	case d.Objects == nil:
		return nil, errors.New("compliance: an object lister is required; without one the " +
			"bundle silently omits every file the person uploaded")
	case d.Prefixes == nil:
		return nil, errors.New("compliance: subject prefixes are required")
	case d.Store == nil:
		return nil, errors.New("compliance: an object store is required")
	case d.Prefix == nil:
		return nil, errors.New("compliance: a manifest prefix is required; a bundle written " +
			"outside the subject's namespace is personal data that survives their erasure")
	case d.Restrictions == nil:
		return nil, errors.New("compliance: a restriction reader is required; building an " +
			"export for a restricted subject is exactly the processing Article 18 halts")
	case d.Exemptions == nil:
		return nil, errors.New("compliance: a retention-exemption resolver is required; a " +
			"bundle that lists a name and an address and says nothing about invoices " +
			"retained under Article 17(3)(b) is an accurate file and a misleading answer")
	case d.Now == nil:
		return nil, errors.New("compliance: a clock is required")
	}
	return &ExportRuns{
		exports: d.Exports, profile: d.Profile, objects: d.Objects,
		prefixes: d.Prefixes, store: d.Store, prefix: d.Prefix,
		blocked: d.Restrictions, exemptions: d.Exemptions, now: d.Now,
	}, nil
}

// RequestExportCommand asks for a copy of the caller's own data.
type RequestExportCommand struct {
	// SubjectID is the CALLER'S pseudonym. There is deliberately no field naming
	// another subject: compliance.md §3 calls this the most dangerous endpoint in
	// the product, and a command that could name somebody else would be the
	// exfiltration API that description warns about.
	SubjectID string

	IdempotencyKey string
}

// Request records that a subject asked, and returns the id they will poll with.
//
// It does NOT build the bundle. The reactor on DataExportRequested starts the
// workflow, which is the same shape erasure uses and for the same reason: a
// request handler that ran the work would hold a connection open for as long as
// somebody's data takes to gather, and would lose it entirely if the process
// restarted mid-way.
func (e *ExportRuns) Request(
	ctx context.Context, cmd RequestExportCommand,
) (string, error) {
	switch {
	case cmd.SubjectID == "":
		return "", errs.Internalf("no authenticated subject reached the export handler")
	case cmd.IdempotencyKey == "":
		return "", errs.ValidationFailedf("an idempotency key is required")
	}

	// DERIVED from the idempotency key, not random. A retried request must land
	// on the same stream, or one person pressing a button twice gets two
	// workflows, two bundles and two "your export is ready" mails.
	//
	// The same construction event ids use (EVENT-SOURCING §3): a namespaced SHA-1
	// UUID over the key, so the mapping is stable across processes and across
	// restarts without anything having to store it.
	exportID := ids.FromUUID[ids.DataExport](
		uuid.NewSHA1(exportIDNamespace, []byte(cmd.IdempotencyKey))).String()

	export, err := e.exports.Load(ctx, domain.ExportStreamKey(exportID))
	if err != nil {
		return "", fmt.Errorf("loading the export: %w", err)
	}
	now := e.now().UTC()
	if err := export.Request(exportID, cmd.SubjectID, now); err != nil {
		return "", err
	}
	if len(export.Uncommitted()) == 0 {
		// The same request again. Already recorded, already being built.
		return exportID, nil
	}

	if _, err := e.exports.Save(ctx, domain.ExportStreamKey(exportID), export,
		cmd.IdempotencyKey, eventsourcing.Metadata{
			OccurredAt: now,
			SubjectIDs: []string{cmd.SubjectID},
			ActorID:    cmd.SubjectID,
		}); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			// Two concurrent presses of one button. The other won, and it recorded
			// exactly what this one wanted.
			return exportID, nil
		}
		return "", fmt.Errorf("recording the export request: %w", err)
	}
	return exportID, nil
}

// ExportPlan is what a run needs to know before it starts.
type ExportPlan struct {
	SubjectID string

	// Prefixes are every namespace the subject's objects live under, in a stable
	// order. The workflow walks them one at a time so a resumed run knows which
	// it was on.
	Prefixes []string
}

// Begin checks that a run may proceed and reports what it has to walk.
//
// It is the FIRST activity, and it is separate from the listing so that a
// restriction arriving mid-flight stops the run at a defined point rather than
// halfway through a manifest.
func (e *ExportRuns) Begin(ctx context.Context, exportID string) (ExportPlan, error) {
	export, err := e.exports.Load(ctx, domain.ExportStreamKey(exportID))
	if err != nil {
		return ExportPlan{}, fmt.Errorf("loading the export: %w", err)
	}
	if !export.Exists() {
		return ExportPlan{}, errs.NotFoundf("no such export")
	}

	restricted, err := e.blocked.Restricted(ctx, export.SubjectID())
	if err != nil {
		// FAILS CLOSED, like every other read of a restriction: an unreadable
		// answer is not an absent restriction (ADR-010), and the alternative is
		// that a Postgres blip lets an export run for somebody who invoked
		// Article 18.
		return ExportPlan{}, fmt.Errorf("reading the processing restriction: %w", err)
	}
	if restricted {
		return ExportPlan{}, &PermanentExportError{Reason: contract.ExportFailedRestricted}
	}

	prefixes := e.prefixes(export.SubjectID())
	if len(prefixes) == 0 {
		// REFUSED, matching Objects.ErasePrefixes.
		//
		// The erasure has always refused an empty traversal — "an erasure that
		// traverses nothing reports success having deleted nothing" — and the
		// export did not, so the two halves of the same subject graph disagreed
		// about what an empty one means. An export over no prefixes writes a
		// manifest listing zero objects and reports READY, which tells the person
		// that everything we hold about them is in a file that omits their
		// photographs.
		//
		// Retrying cannot fix a graph with nothing in it, so this is PERMANENT
		// rather than an error the workflow would spend its retries on.
		return ExportPlan{}, &PermanentExportError{Reason: contract.ExportFailedNoSubjectGraph}
	}

	return ExportPlan{SubjectID: export.SubjectID(), Prefixes: prefixes}, nil
}

// PermanentExportError is a failure retrying cannot fix.
//
// The distinction matters at the workflow boundary and nowhere else: an
// unreachable object store is worth an hour of retries, and a subject under
// Article 18 restriction will still be restricted on the hundredth attempt. A
// workflow that retried both alike would burn its whole schedule reaching the
// same answer, and the subject would wait for it.
type PermanentExportError struct{ Reason string }

func (e *PermanentExportError) Error() string {
	// The reason is IN the message, because an activity error crosses a process
	// boundary and arrives as an ApplicationError that has lost the Go type. The
	// workflow reads the reason back out of the string, and this is the only
	// place that promises it is there.
	return "compliance: this export cannot be produced: " + e.Reason
}

// Permanent marks this as a failure retrying cannot fix.
//
// A METHOD rather than a sentinel of this package's, so the composition root's
// adapter can recognise it with a type assertion and map it to the workflow
// engine's own marker — neither this module nor that adapter may import the
// other, and the root is the one place allowed to see both.
func (e *PermanentExportError) Permanent() string { return e.Reason }

// ListObjects returns one page of a subject's stored objects.
//
// The RESUMABLE step. `after` is the cursor a previous page returned, carried by
// the workflow across restarts — so a run that died having listed four pages
// issues the fifth listing rather than starting again.
func (e *ExportRuns) ListObjects(
	ctx context.Context, prefix, after string,
) (blob.Page, error) {
	if prefix == "" {
		// Refused rather than passed through: an empty prefix lists the whole
		// bucket, which here would put another tenant's objects into somebody's
		// data export.
		return blob.Page{}, &PermanentExportError{Reason: contract.ExportFailedUnreadable}
	}
	page, err := e.objects.ListPage(ctx, prefix, after, ExportPageSize)
	if err != nil {
		return blob.Page{}, fmt.Errorf("listing %s: %w", prefix, err)
	}
	return page, nil
}

// WriteManifest reads the vault, writes the bundle and records the completion.
//
// The LAST activity, and the vault read is here rather than in its own step for
// a reason worth stating: personal data must live for as short a time as
// possible, and an earlier activity would have to hand it to the workflow —
// which writes its arguments and results to HISTORY, where ADR-002 applies
// exactly as it does to the event log. Reading and writing in one activity means
// the plaintext exists inside one call and reaches nothing durable but the
// bundle it is meant to produce.
func (e *ExportRuns) WriteManifest(
	ctx context.Context, exportID string, objects []ExportedObject,
) (string, error) {
	export, err := e.exports.Load(ctx, domain.ExportStreamKey(exportID))
	if err != nil {
		return "", fmt.Errorf("loading the export: %w", err)
	}
	if !export.Exists() {
		return "", errs.NotFoundf("no such export")
	}
	subjectID := export.SubjectID()

	fields, err := e.profile.Profile(ctx, subjectID)
	if err != nil {
		return "", fmt.Errorf("reading the personal data of %s: %w", subjectID, err)
	}

	now := e.now().UTC()
	body, err := codec.Marshal(Bundle{
		FormatVersion: ExportFormatVersion,
		SubjectID:     subjectID,
		GeneratedAt:   now,
		PersonalData:  fields,
		Objects:       objects,
		// Resolved for THIS subject, in the same activity as the vault read, so
		// the manifest's statement about what is retained is as current as the
		// values it sits beside. A set resolved at request time and carried
		// through the workflow would also have to travel in workflow history,
		// which is durable and replicated — and while a retention policy is not
		// personal data, "which classes apply to this person" edges towards
		// being a fact about them.
		Retained: retainedRecords(e.exemptions.For(ctx, subjectID)),
	})
	if err != nil {
		return "", fmt.Errorf("encoding the bundle for %s: %w", subjectID, err)
	}

	prefix := e.prefix(subjectID)
	if prefix == "" {
		return "", &PermanentExportError{Reason: contract.ExportFailedUnreadable}
	}
	key, err := blob.NewKey(prefix)
	if err != nil {
		return "", fmt.Errorf("minting an object key: %w", err)
	}
	if err := e.store.Put(ctx, key, body, "application/json"); err != nil {
		return "", fmt.Errorf("storing the bundle for %s: %w", subjectID, err)
	}

	// Recorded AFTER the object exists. The reverse order would announce a
	// fetchable export — and mail the subject about it — while the manifest was
	// still only an intention.
	if err := export.Complete(key.String(), len(objects), now); err != nil {
		return "", err
	}
	if err := e.save(ctx, exportID, export, subjectID, "complete"); err != nil {
		return "", err
	}
	return key.String(), nil
}

// Fail records that a run stopped without producing a bundle.
func (e *ExportRuns) Fail(ctx context.Context, exportID, reason string) error {
	export, err := e.exports.Load(ctx, domain.ExportStreamKey(exportID))
	if err != nil {
		return fmt.Errorf("loading the export: %w", err)
	}
	if !export.Exists() {
		return errs.NotFoundf("no such export")
	}
	if err := export.Fail(reason, e.now().UTC()); err != nil {
		if errs.ReasonOf(err) == errs.Conflict {
			// The export completed after all — a late failure from an earlier
			// attempt. The aggregate refuses it, and so does this: the bundle is
			// fetchable and telling the subject otherwise would be a lie.
			return nil
		}
		return err
	}
	return e.save(ctx, exportID, export, export.SubjectID(), "fail")
}

func (e *ExportRuns) save(
	ctx context.Context, exportID string, export *domain.Export, subjectID, what string,
) error {
	if len(export.Uncommitted()) == 0 {
		return nil
	}
	if _, err := e.exports.Save(ctx, domain.ExportStreamKey(exportID), export,
		exportID+":"+what, eventsourcing.Metadata{
			OccurredAt: e.now().UTC(),
			SubjectIDs: []string{subjectID},
			ActorID:    subjectID,
		}); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			// Another attempt of the same activity got there first, which is the
			// ordinary shape of at-least-once delivery.
			return nil
		}
		return fmt.Errorf("recording the export outcome: %w", err)
	}
	return nil
}
