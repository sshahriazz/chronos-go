package app

import (
	"context"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/blob"
)

// ExportFormatVersion is the bundle's own schema version.
//
// It is IN the bundle rather than only in this constant, because the bundle
// outlives this code: somebody opens a download six months from now with a tool
// written against whatever the shape was then. A version they can branch on is
// the difference between a portable file and a snapshot of one deployment.
//
// # Version 2: `retained` became objects
//
// It was an array of English sentences. A reader could display them and could do
// nothing else with them — not tell which data class a statement was about, not
// read the legal basis out of it, not translate it. Article 15(1)(d) asks for
// "the envisaged period for which the personal data will be stored", which is a
// value rather than a clause inside a sentence, so it is now its own field. See
// RetainedRecord.
//
// The break is safe to take here for the reason ExportMyDataResponse's was: no
// release has been cut, and the alternative is a permanently unparseable field
// in the one file this system produces specifically so that a machine can read
// it.
const ExportFormatVersion = 2

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

	// Objects lists the stored files this system holds for the subject —
	// avatars today — by opaque key, size and modification time.
	//
	// # Listed, not copied, and that is a decision rather than an economy
	//
	// Copying each object into the export would put a second copy of the most
	// concentrated personal data in the system beside the first, and erasure
	// would then have to find both. Referencing keeps one copy under one prefix,
	// which the erasure traversal already deletes.
	//
	// The cost is stated where it can be weighed: this is a SNAPSHOT of what
	// existed when the export ran, so an object deleted since has no download URL
	// when the subject fetches. GetDataExport says so per object rather than
	// omitting it, because "you had a file here and it is gone now" is a true
	// answer and silence is not.
	Objects []ExportedObject `json:"objects"`

	// Retained explains what this system keeps that is NOT in the bundle and
	// why — the same resolved set the erasure confirmation carries, produced by
	// the same resolver against the same schedule.
	//
	// Article 15(1) requires telling the subject about the processing, not only
	// handing over the values. A bundle that listed a name and an address and
	// said nothing about invoices retained under a statutory obligation would be
	// an accurate file and a misleading answer.
	Retained []RetainedRecord `json:"retained"`
}

// RetainedRecord is one retention exemption, as the manifest states it.
//
// # A separate type from domain.RetentionPolicy, on purpose
//
// The domain type is the policy; this is the wire shape of a statement about it.
// Serialising the domain type directly would put json tags in `domain`, which no
// aggregate in this repository carries, and would publish every field it ever
// grows — the first internal one to be added would appear in a file a data
// subject downloads, with nobody having decided that it should.
//
// So the fields a person is entitled to read are named here, once. The same
// four the erasure confirmation renders.
type RetainedRecord struct {
	// DataClass is which category of record this is about.
	DataClass string `json:"dataClass"`

	// Period is how long that category is kept.
	Period string `json:"period"`

	// Disposition is what an erasure would do to it: `retained` means readable
	// records survive, `pseudonymised` means they survive unreadable.
	//
	// In the manifest and not in the mail, and that asymmetry is deliberate. It
	// is the field a machine branches on, which is what this file is for; in a
	// message to a person it would be a word of art beside a sentence that
	// already says the same thing in plain language.
	Disposition string `json:"disposition"`

	// LegalBasis is the article permitting it. Empty is not possible here —
	// every entry in this list survives an erasure, and a retention with no
	// basis is one that should not be happening.
	LegalBasis string `json:"legalBasis"`

	// Reason is the plain-language sentence, so the bundle is readable by the
	// person as well as by a tool.
	Reason string `json:"reason"`
}

// retainedRecords maps the resolved policies onto the manifest's shape.
func retainedRecords(policies []domain.RetentionPolicy) []RetainedRecord {
	out := make([]RetainedRecord, 0, len(policies))
	for _, p := range policies {
		out = append(out, RetainedRecord{
			DataClass:   string(p.Class),
			Period:      p.Period,
			Disposition: string(p.Disposition),
			LegalBasis:  p.LegalBasis,
			Reason:      p.Reason,
		})
	}
	return out
}

// ExportedObject is one stored file, as the manifest records it.
//
// No content type: an S3 listing does not return one, and it is left empty
// rather than guessed from the key. A guessed type in a portability manifest is
// a claim about somebody's data that nothing verified — and the key deliberately
// carries no meaning to guess from (CLAUDE.md).
type ExportedObject struct {
	// Key is the opaque object key. Included so GetDataExport can mint a URL for
	// it, and so a person can quote it to support.
	Key string `json:"key"`

	// Size is the object's length in bytes, as the store reported it.
	Size int64 `json:"sizeBytes"`

	// ModifiedAt is when the store last saw it change.
	ModifiedAt time.Time `json:"modifiedAt"`
}

// DefaultExportExpiry is how long a download link lives.
//
// # Fifteen minutes, and the number is not ours to choose freely
//
// It was an hour, on the argument that the bundle is the most concentrated
// personal data this system can produce and an hour is long enough to click from
// an email while short enough that a URL in a proxy log is stale before it is
// useful. That argument still holds and the number was still wrong: the object
// store REFUSES a grant longer than `blob.Limits.MaxExpiry`, which defaults to
// fifteen minutes — so every ready export answered its poll with `internal`.
//
// Nothing caught it. The use case had unit tests against a fake store that
// granted whatever it was asked for, the handler had tests against a fake use
// case, and the two limits live in packages that do not import each other. It
// took a request driven through the real store to see it, and
// TestTheExportExpiryFitsTheStoresCeiling now holds the two together.
//
// Shorter is also the right direction on its own terms: the link is minted when
// the person asks for it, not mailed to them, so it only has to survive the
// click that follows.
const DefaultExportExpiry = 15 * time.Minute

// WHAT USED TO BE HERE: `Exports`, the SYNCHRONOUS export use case.
//
// It built a bundle, uploaded it and returned a download URL, in one call. It
// was complete and fully tested, and it was constructed by no binary — the
// asynchronous path (`ExportRuns`, driven by a Temporal workflow) is what
// cmd/worker wires and what the RPCs reach, and it has been since resumability
// landed (compliance.md §5).
//
// So there were two export implementations and one of them was dead: live
// duplication of the part of this system that hands a person a file containing
// everything we hold about them. A change made to one would not have been made
// to the other, and nothing would have failed.
//
// The types it shared with the async path are all still above — `Bundle`,
// `RetainedRecord`, `ExportedObject`, `SubjectProfile`, `ExportStore` — which is
// why this was a surgical removal rather than a file delete.
