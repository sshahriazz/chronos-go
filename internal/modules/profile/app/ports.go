// Package app is profile's use-case layer: the three things a person can do to
// their own profile, and the ports those three need.
//
// Ports are declared HERE, by the consumer, and narrowed to the methods the use
// cases actually call (ADR-001, CONVENTIONS §2). Narrow interfaces rather than
// the concrete types, for a reason that matters more than testability: a use
// case holding *piivault.Vault can erase a subject, and one holding this
// package's SubjectVault cannot.
package app

import (
	"context"
	"time"

	"github.com/chronos/chronos-go/internal/modules/profile/domain"
	"github.com/chronos/chronos-go/internal/platform/blob"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// ---------------------------------------------------------------------------
// Write ports
// ---------------------------------------------------------------------------

// Repository is the write side of a profile.
//
// Declared as an interface rather than depending on *eventsourcing.Repository so
// a use-case test can drive the "somebody else saved first" branch from a fake,
// with no store at all.
type Repository interface {
	// Load rebuilds one person's profile. A stream that does not exist is NOT an
	// error: it yields an empty aggregate, which here means "they have never
	// touched their profile" — so create and modify are one code path and the
	// append precondition decides between them.
	Load(ctx context.Context, key string) (*domain.Profile, error)

	// Save appends what the aggregate recorded, under the expected-revision
	// precondition it was loaded at — which is what turns two concurrent saves
	// into one CONFLICT rather than a lost update.
	Save(
		ctx context.Context,
		key string,
		agg *domain.Profile,
		idempotencyKey string,
		meta eventsourcing.Metadata,
	) (eventsourcing.AppendResult, error)
}

// SubjectVault is where personal data lives, and the only place it may.
//
// # Why this port can read, when identity's deliberately cannot
//
// identity's SubjectVault is write-only, and its comment gives the reason: a
// registration puts an address in and never needs one back, so a port that
// could read is a port through which an address can reach a log line, an error
// message or an event.
//
// Profile's whole read path is different. `GetProfile` exists to return the
// person their own display name, which means the value has to come back out;
// there is no version of this module in which the vault is write-only. So the
// port reads, and the containment is moved to where it can still be enforced:
// the value goes into a response DTO and into nothing else. It never reaches an
// event (the event carries a marker, see contract), never reaches the
// projection (the table has no column for it), and never reaches a log line
// (nothing here logs a field value).
//
// Erase is deliberately ABSENT. Erasure is the compliance domain's decision,
// and a profile edit must not be one keystroke away from it.
type SubjectVault interface {
	// PutAll stores several fields for one subject in one operation, so a failed
	// save cannot leave a half-changed profile behind.
	PutAll(ctx context.Context, id pii.SubjectID, values map[pii.Field]string) error

	// Profile decrypts everything held about a subject.
	//
	// Returns pii.ErrErased for a subject who exercised erasure and
	// pii.ErrNoSubject for one with nothing stored. Both are CORRECT outcomes
	// for a profile read and are reported as an empty profile, not as an error.
	Profile(ctx context.Context, id pii.SubjectID) (pii.Profile, error)
}

// AvatarStore is the object store, narrowed to the three operations an avatar
// needs.
//
// Delete is deliberately absent. Reclaiming abandoned uploads is a sweep's job,
// running against the whole bucket with the projection as its reference list —
// not something a request handler does inline, where a failure would either
// fail a save that already succeeded or leak an object silently.
type AvatarStore interface {
	// GrantUpload signs a POST policy for exactly one object. The bytes go from
	// the browser to the store and never through this server.
	GrantUpload(ctx context.Context, req blob.UploadRequest) (blob.Grant, error)

	// Verify reports what the store actually holds under a key. This is the
	// answer the domain validates — never the uploader's claim.
	Verify(ctx context.Context, key blob.Key) (blob.Object, error)

	// GrantDownload signs a time-limited URL for reading one object.
	GrantDownload(ctx context.Context, key blob.Key, expiry time.Duration) (string, error)
}

// ---------------------------------------------------------------------------
// Read ports
// ---------------------------------------------------------------------------

// View is one row of the profile projection.
//
// It carries no personal data — see the migration for why each omission is
// deliberate. Exists reports whether a row was found at all, so a caller can
// tell "never configured anything" from "configured and then cleared" without
// a second query or a sentinel timestamp.
type View struct {
	Exists         bool
	SubjectID      string
	DisplayNameSet bool
	LocaleSet      bool
	TimezoneSet    bool
	Avatar         domain.Avatar
	UpdatedAt      time.Time
}

// Reader is the profile projection.
type Reader interface {
	// View returns one subject's projected profile. A subject with no row is
	// NOT an error: it returns a zero View with Exists false.
	View(ctx context.Context, subjectID string) (View, error)
}

// ---------------------------------------------------------------------------
// Shared refusals
// ---------------------------------------------------------------------------

// requireSubject refuses a call that has no caller.
//
// It can only fire on a wiring mistake — the API layer takes the subject from
// the authn gate's principal and refuses the request itself when there is none
// — which is exactly why it is here: the use case is reachable from a test, a
// future worker and a replay, and a use case that trusts its caller to have
// checked is one that stops being checked the first time a second caller
// appears.
func requireSubject(subjectID, what string) error {
	if subjectID == "" {
		return errs.ValidationFailedf("%s needs a subject", what)
	}
	return nil
}
