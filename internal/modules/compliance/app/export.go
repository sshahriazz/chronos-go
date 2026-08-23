package app

import (
	"context"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/platform/blob"
	"github.com/chronos/chronos-go/internal/platform/codec"
)

// ExportFormatVersion is the bundle's own schema version.
//
// It is IN the bundle rather than only in this constant, because the bundle
// outlives this code: somebody opens a download six months from now with a tool
// written against whatever the shape was then. A version they can branch on is
// the difference between a portable file and a snapshot of one deployment.
const ExportFormatVersion = 1

// SubjectProfile is every personal-data field held for a subject.
//
// A port rather than the vault itself, and narrowed to ONE method for the same
// reason the erasure's vault port is: this reads every field of a person in one
// call, which is the single most sensitive capability in the system, and the
// code holding it should hold nothing else.
type SubjectProfile interface {
	Profile(ctx context.Context, subjectID string) (map[string]string, error)
}

// ExportStore writes the bundle and hands back a link to it.
type ExportStore interface {
	Put(ctx context.Context, key blob.Key, body []byte, contentType string) error
	GrantDownload(ctx context.Context, key blob.Key, expiry time.Duration) (string, error)
}

// Bundle is what a data subject receives.
//
// # Why JSON and not a database dump
//
// Article 20 asks for a "structured, commonly used and machine-readable format"
// — the point is that somebody can take it to a competitor, so the shape has to
// be readable by a tool nobody here wrote. A dump of our tables would satisfy
// "machine-readable" and defeat the purpose.
//
// # What is deliberately NOT in it
//
// No event log. Article 15 is about personal data, and the log's value is the
// causal history of a SYSTEM — it names pseudonyms, positions and revisions that
// mean nothing outside this deployment and would leak the shape of other
// people's activity where streams are shared. The personal data in it is the
// same data listed here, resolved through the same vault.
//
// No password hash, no TOTP secret, no session token digest. They are derived
// from credentials rather than data about the person, and exporting them creates
// an offline attack surface out of a privacy right.
type Bundle struct {
	// FormatVersion lets a reader branch. See ExportFormatVersion.
	FormatVersion int `json:"formatVersion"`

	// SubjectID is the pseudonym. Included so a person can quote it to support
	// without the support agent needing to resolve their address.
	SubjectID string `json:"subjectId"`

	// GeneratedAt is when the bundle was produced, which is what makes it a
	// snapshot rather than a claim about now.
	GeneratedAt time.Time `json:"generatedAt"`

	// PersonalData is every field the vault holds, by field name.
	PersonalData map[string]string `json:"personalData"`

	// Retained explains what this system keeps that is NOT in the bundle and
	// why — the same list the erasure confirmation carries.
	//
	// Article 15(1) requires telling the subject about the processing, not only
	// handing over the values. A bundle that listed a name and an address and
	// said nothing about invoices retained under a statutory obligation would be
	// an accurate file and a misleading answer.
	Retained []string `json:"retained"`
}

// Exports produces a data subject's portability bundle.
type Exports struct {
	profile SubjectProfile
	store   ExportStore
	prefix  func(subjectID string) string
	expiry  time.Duration
	now     func() time.Time
}

// ExportsDeps is what Exports needs.
type ExportsDeps struct {
	Profile SubjectProfile
	Store   ExportStore

	// Prefix is the object-store namespace the bundle is written under.
	//
	// It must be the SUBJECT'S OWN prefix, and that is not a tidiness rule: the
	// erasure deletes every object under a subject's prefixes, so a bundle
	// written there is purged by erasure automatically (compliance.md §4 step
	// 9). A bundle written anywhere else is personal data that survives the
	// erasure of the person it describes.
	Prefix func(subjectID string) string

	// Expiry bounds the download link.
	Expiry time.Duration

	Now func() time.Time
}

// DefaultExportExpiry is how long a download link lives.
//
// An hour. The bundle is the most concentrated personal data this system can
// produce, and the link is a bearer capability — anybody holding the URL can
// fetch it. Long enough to click from an email, short enough that a URL in a
// proxy log or a screenshot is stale before it is useful.
const DefaultExportExpiry = time.Hour

func NewExports(d ExportsDeps) (*Exports, error) {
	switch {
	case d.Profile == nil:
		return nil, fmt.Errorf("compliance: a subject profile source is required; an export " +
			"with no personal data in it answers Article 15 with an empty file")
	case d.Store == nil:
		return nil, fmt.Errorf("compliance: an object store is required")
	case d.Prefix == nil:
		return nil, fmt.Errorf("compliance: a subject prefix is required; a bundle written " +
			"outside the subject's own namespace is personal data that survives their erasure")
	case d.Now == nil:
		return nil, fmt.Errorf("compliance: a clock is required")
	}
	if d.Expiry <= 0 {
		d.Expiry = DefaultExportExpiry
	}
	return &Exports{
		profile: d.Profile, store: d.Store, prefix: d.Prefix,
		expiry: d.Expiry, now: d.Now,
	}, nil
}

// ExportResult is where the bundle went and how to fetch it.
type ExportResult struct {
	// ObjectKey is where it was written. Recorded so a later request can find
	// the same bundle rather than regenerating one.
	ObjectKey string

	// DownloadURL is short-lived and is NOT stored anywhere: it is a bearer
	// capability, and persisting one would turn an expiring link into a durable
	// credential.
	DownloadURL string

	ExpiresAt time.Time
}

// Produce builds a subject's bundle, stores it, and returns a link.
//
// # The bundle is written under the subject's OWN prefix
//
// Which means the erasure deletes it, for free, by the traversal that already
// deletes their avatars. compliance.md §4 step 9 asks for exported bundles to be
// purged on erasure; putting them in the same namespace makes that a property of
// where they live rather than a step somebody has to remember.
func (e *Exports) Produce(ctx context.Context, subjectID string) (ExportResult, error) {
	if subjectID == "" {
		return ExportResult{}, fmt.Errorf("compliance: an export needs a subject")
	}

	fields, err := e.profile.Profile(ctx, subjectID)
	if err != nil {
		return ExportResult{}, fmt.Errorf("compliance: reading the personal data of %s: %w",
			subjectID, err)
	}

	now := e.now().UTC()
	bundle := Bundle{
		FormatVersion: ExportFormatVersion,
		SubjectID:     subjectID,
		GeneratedAt:   now,
		PersonalData:  fields,
		Retained:      Retained,
	}
	body, err := codec.Marshal(bundle)
	if err != nil {
		return ExportResult{}, fmt.Errorf("compliance: encoding the bundle for %s: %w",
			subjectID, err)
	}

	prefix := e.prefix(subjectID)
	if prefix == "" {
		return ExportResult{}, fmt.Errorf("compliance: no object prefix for %s; a bundle "+
			"written outside the subject's namespace survives their erasure", subjectID)
	}
	// One key per REQUEST, not per subject: objects here are immutable (ADR-013),
	// and overwriting would replace a bundle somebody may still be downloading.
	// Every version lives under the same prefix, so erasure removes all of them.
	key, err := blob.NewKey(prefix)
	if err != nil {
		return ExportResult{}, fmt.Errorf("compliance: minting an object key: %w", err)
	}

	if err := e.store.Put(ctx, key, body, "application/json"); err != nil {
		return ExportResult{}, fmt.Errorf("compliance: storing the bundle for %s: %w",
			subjectID, err)
	}
	url, err := e.store.GrantDownload(ctx, key, e.expiry)
	if err != nil {
		return ExportResult{}, fmt.Errorf("compliance: granting a download for %s: %w",
			subjectID, err)
	}

	return ExportResult{
		ObjectKey:   key.String(),
		DownloadURL: url,
		ExpiresAt:   now.Add(e.expiry),
	}, nil
}
