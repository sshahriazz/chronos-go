package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/chronos/chronos-go/internal/platform/blob"
)

// MaxObjectsPerSubject bounds what one erasure will delete.
//
// A REFUSAL rather than a page, and the reasoning is the same one that governs
// the org-member fan-out: an erasure that deleted the first N and reported
// success is indistinguishable afterwards from one that deleted everything. So
// hitting it fails the erasure and the workflow retries with somebody's
// attention on it.
//
// 1000 is far above any plausible number of avatars one person accumulates —
// each upload is a deliberate act — and far below the point at which a single
// erasure becomes an unbounded delete.
const MaxObjectsPerSubject = 1000

// ObjectStore is the part of the blob store an erasure needs.
//
// Two methods out of five. The code that performs an irreversible deletion holds
// exactly the capability it needs: it cannot grant an upload, and it cannot mint
// a download URL for what it is about to destroy.
type ObjectStore interface {
	ListPrefix(ctx context.Context, prefix string, limit int) ([]blob.Key, error)
	Delete(ctx context.Context, key blob.Key) error
}

// SubjectPrefixes names every object-store prefix a subject's data lives under.
//
// # This is compliance.md §4 step 4, and it has exactly one member today
//
// "Traverse the subject graph → which streams, rows, objects." Streams and rows
// are covered by the key destruction — one key, every vault field unreadable at
// once — and OBJECTS ARE NOT. They are stored in SeaweedFS, outside the vault,
// and no key destruction touches them.
//
// It is a list of prefix FUNCTIONS rather than a list of keys, because a
// projection can only name the current object. An avatar that was replaced
// leaves the old one behind, and an upload that was granted and never confirmed
// leaves one no row ever mentioned; both are personal data and both are under
// the subject's prefix. Enumerating the prefix finds all three kinds.
//
// Adding a module that stores objects means adding its prefix here. That is the
// whole extension point, and a module that forgets it erases incompletely — so
// the composition root asserts the list is not empty rather than letting an
// empty traversal look like a clean one.
type SubjectPrefixes func(subjectID string) []string

// Objects deletes a subject's stored objects.
type Objects struct {
	store    ObjectStore
	prefixes SubjectPrefixes
}

// ObjectsDeps is what Objects needs.
type ObjectsDeps struct {
	Store    ObjectStore
	Prefixes SubjectPrefixes
}

func NewObjects(d ObjectsDeps) (*Objects, error) {
	switch {
	case d.Store == nil:
		return nil, fmt.Errorf("compliance: an object store is required; without one an " +
			"erased person's avatars stay in the bucket and stay servable by a signed URL")
	case d.Prefixes == nil:
		return nil, fmt.Errorf("compliance: a subject-prefix list is required")
	}
	return &Objects{store: d.Store, prefixes: d.Prefixes}, nil
}

// ErasePrefixes deletes every object belonging to a subject.
//
// # Why the whole prefix rather than the keys a projection names
//
// A projection names the CURRENT avatar. Objects here are immutable — a new
// version is a new key plus a new event (ADR-013) — so every earlier avatar is
// still there under a key no row has mentioned since, and every granted-but-
// abandoned upload is there under a key no row ever mentioned. ADR-056 left both
// unreclaimed and named it; for an erasure they are simply personal data that
// survives.
//
// # Idempotent
//
// The caller is a workflow activity and retries. A second run lists nothing and
// deletes nothing, and deleting an object already gone is not an error in the
// adapter either — so a partial first attempt completes on the second.
func (o *Objects) ErasePrefixes(ctx context.Context, subjectID string) (int, error) {
	if subjectID == "" {
		return 0, fmt.Errorf("compliance: erasing objects needs a subject")
	}

	prefixes := o.prefixes(subjectID)
	if len(prefixes) == 0 {
		// An empty traversal completes instantly and looks identical to a
		// successful one. Refused, because the whole point of the list is that
		// forgetting to add a module to it is the way this silently stops
		// covering everything.
		return 0, fmt.Errorf("compliance: no object prefixes are registered for a subject; " +
			"an erasure that traverses nothing reports success having deleted nothing")
	}

	deleted := 0
	for _, prefix := range prefixes {
		keys, err := o.store.ListPrefix(ctx, prefix, MaxObjectsPerSubject)
		if err != nil {
			if errors.Is(err, blob.ErrTooManyObjects) {
				// FAILS the erasure. Deleting what was listed and stopping would
				// leave objects behind under a subject reported as erased.
				return deleted, fmt.Errorf("compliance: %s has more than %d objects; "+
					"refusing a partial erasure: %w", subjectID, MaxObjectsPerSubject, err)
			}
			return deleted, fmt.Errorf("compliance: listing objects for %s: %w", subjectID, err)
		}
		for _, key := range keys {
			if err := o.store.Delete(ctx, key); err != nil {
				return deleted, fmt.Errorf("compliance: deleting an object of %s: %w",
					subjectID, err)
			}
			deleted++
		}
	}
	return deleted, nil
}
