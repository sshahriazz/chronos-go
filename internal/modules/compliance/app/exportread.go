package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/blob"
	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/errs"
)

// ExportView is one request's state, as the subject polls it.
type ExportView struct {
	ExportID string
	Status   domain.ExportState

	// ManifestURL is short-lived and set only when the export is READY. It is
	// minted per poll and stored nowhere: persisting one would turn an expiring
	// link into a durable credential for the most concentrated personal data
	// this system produces.
	ManifestURL string

	// Objects are the stored files the manifest references, each with its own
	// short-lived URL.
	Objects []ExportObjectView

	// ExpiresAt bounds every URL in this view. One deadline for all of them,
	// because they are minted together.
	ExpiresAt time.Time

	// FailureReason is the coarse machine string, set only when the export
	// FAILED. The client turns it into a sentence; it is not one.
	FailureReason string

	RequestedAt time.Time
	SettledAt   time.Time
}

// ExportObjectView is one referenced file and how to fetch it.
type ExportObjectView struct {
	Key  string
	Size int64

	// URL is empty when the object no longer exists.
	//
	// The manifest is a SNAPSHOT of what the subject held when the export ran,
	// and objects are referenced rather than copied — so a file deleted since has
	// nothing to fetch. It is reported as a present entry with no URL rather than
	// omitted, because "you had a file here and it is gone now" is a true answer
	// and silence is not.
	URL string
}

// ExportReader answers where a request has got to.
//
// It reads the PROJECTION, which is behind the log by construction and is safe
// here for the reason UserDirectory is: the answer decides only what to tell
// somebody about their own request, and a stale row costs one more poll. Every
// decision that spends anything is taken against the aggregate.
type ExportReader interface {
	Export(ctx context.Context, exportID, subjectID string) (ExportRecord, error)
	Exports(ctx context.Context, subjectID string, limit int) ([]ExportRecord, error)
}

// ExportRecord is one projected row.
type ExportRecord struct {
	ExportID      string
	SubjectID     string
	Status        string
	ManifestKey   string
	ObjectCount   int
	FailureReason string
	RequestedAt   time.Time
	SettledAt     time.Time
}

// ErrNoSuchExport means nothing is known about that id for that subject.
var ErrNoSuchExport = errors.New("compliance: no such export")

// ExportDownloads mints the links a ready export is fetched with.
type ExportDownloads struct {
	reader   ExportReader
	store    ExportStore
	manifest ManifestReader
	expiry   time.Duration
}

// ManifestReader reads back a stored bundle.
//
// Needed because the OBJECT LIST lives in the manifest rather than in the
// projection: putting a subject's file inventory in a Postgres row would make it
// personal data in a table erasure does not traverse, while the manifest already
// lives under the subject's own prefix where erasure deletes it. So the poll
// reads the bundle it is about to hand over, and mints a URL per object listed.
type ManifestReader interface {
	Get(ctx context.Context, key blob.Key) ([]byte, error)
}

// ExportDownloadsDeps is what the reader needs.
type ExportDownloadsDeps struct {
	Reader   ExportReader
	Store    ExportStore
	Manifest ManifestReader

	// Expiry bounds every minted URL. Zero takes DefaultExportExpiry.
	Expiry time.Duration
}

func NewExportDownloads(d ExportDownloadsDeps) (*ExportDownloads, error) {
	switch {
	case d.Reader == nil:
		return nil, errors.New("compliance: an export reader is required; without one a " +
			"subject cannot find out whether the bundle they asked for exists")
	case d.Store == nil:
		return nil, errors.New("compliance: an object store is required to mint downloads")
	case d.Manifest == nil:
		return nil, errors.New("compliance: a manifest reader is required; without it a " +
			"ready export hands back the bundle and none of the files it references")
	}
	if d.Expiry <= 0 {
		d.Expiry = DefaultExportExpiry
	}
	return &ExportDownloads{
		reader: d.Reader, store: d.Store, manifest: d.Manifest, expiry: d.Expiry,
	}, nil
}

// Get answers a poll, minting download URLs when the bundle is ready.
//
// # The subject is checked, not just the id
//
// An export id is unguessable, and "unguessable" is not an authorization rule.
// The reader is scoped by subject so that one leaked id does not hand a stranger
// the manifest for the most concentrated copy of somebody's data in the system —
// and so that an id belonging to another subject answers exactly as an unknown
// one does.
func (d *ExportDownloads) Get(
	ctx context.Context, exportID, subjectID string,
) (ExportView, error) {
	switch {
	case subjectID == "":
		return ExportView{}, errs.Internalf("no authenticated subject reached the export handler")
	case exportID == "":
		return ExportView{}, errs.ValidationFailedf("an export id is required")
	}

	record, err := d.reader.Export(ctx, exportID, subjectID)
	if err != nil {
		if errors.Is(err, ErrNoSuchExport) {
			// The SAME answer for "no such export" and "somebody else's export".
			// Distinguishing them confirms that an id names a real request, which
			// is the only thing a holder of a leaked id learns for free.
			return ExportView{}, errs.NotFoundf("not found")
		}
		return ExportView{}, fmt.Errorf("reading the export: %w", err)
	}

	view := ExportView{
		ExportID:      record.ExportID,
		Status:        domain.ExportState(record.Status),
		FailureReason: record.FailureReason,
		RequestedAt:   record.RequestedAt,
		SettledAt:     record.SettledAt,
	}
	if view.Status != domain.ExportStateReady {
		// Nothing to mint. A pending export has no bundle, and a failed one has
		// nothing to hand over — which is what the reason is for.
		return view, nil
	}

	view.ExpiresAt = record.SettledAt.Add(d.expiry)
	manifestURL, err := d.store.GrantDownload(ctx, blob.Key(record.ManifestKey), d.expiry)
	if err != nil {
		return ExportView{}, fmt.Errorf("granting the manifest download: %w", err)
	}
	view.ManifestURL = manifestURL

	objects, err := d.referenced(ctx, blob.Key(record.ManifestKey))
	if err != nil {
		return ExportView{}, err
	}
	view.Objects = objects
	return view, nil
}

// referenced reads the manifest and mints a URL per object it lists.
func (d *ExportDownloads) referenced(
	ctx context.Context, manifest blob.Key,
) ([]ExportObjectView, error) {
	body, err := d.manifest.Get(ctx, manifest)
	if err != nil {
		return nil, fmt.Errorf("reading the manifest: %w", err)
	}
	// TOLERANT, like every other read of stored bytes in this system (ADR-047):
	// a manifest written by a later build may carry fields this one has never
	// heard of, and refusing it would make a person's own export unfetchable by
	// the deployment that produced it.
	bundle, err := codec.Tolerant[Bundle](body)
	if err != nil {
		return nil, fmt.Errorf("decoding the manifest: %w", err)
	}

	out := make([]ExportObjectView, 0, len(bundle.Objects))
	for _, o := range bundle.Objects {
		entry := ExportObjectView{Key: o.Key, Size: o.Size}
		url, err := d.store.GrantDownload(ctx, blob.Key(o.Key), d.expiry)
		switch {
		case errors.Is(err, blob.ErrNotFound):
			// Deleted since the export ran. Reported as an entry with no URL —
			// see ExportObjectView.URL for why silence would be worse.
		case err != nil:
			return nil, fmt.Errorf("granting a download for a referenced object: %w", err)
		default:
			entry.URL = url
		}
		out = append(out, entry)
	}
	return out, nil
}

// List returns the subject's own requests, newest first.
//
// No URLs. Minting one per object of every past export would turn a list screen
// into a bulk issuance of bearer capabilities for everything the person has ever
// exported — so this reports STATE, and the subject opens the one they want.
func (d *ExportDownloads) List(
	ctx context.Context, subjectID string, limit int,
) ([]ExportView, error) {
	if subjectID == "" {
		return nil, errs.Internalf("no authenticated subject reached the export handler")
	}
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	records, err := d.reader.Exports(ctx, subjectID, limit)
	if err != nil {
		return nil, fmt.Errorf("listing exports: %w", err)
	}
	out := make([]ExportView, 0, len(records))
	for _, r := range records {
		out = append(out, ExportView{
			ExportID:      r.ExportID,
			Status:        domain.ExportState(r.Status),
			FailureReason: r.FailureReason,
			RequestedAt:   r.RequestedAt,
			SettledAt:     r.SettledAt,
		})
	}
	return out, nil
}
