package domain

import "github.com/chronos/chronos-go/internal/platform/eventsourcing"

// Category is the stream category every profile stream lives under.
//
// One category for the module, because the projector filters on it: a rebuild
// then reads the `$ce-profile` category stream instead of scanning the whole
// log (ADR-042).
const Category eventsourcing.Category = "profile"

// StreamKey names the stream holding one person's profile changes.
//
// # Why the pseudonym itself, and not a digest
//
// notification's PreferenceStreamKey hashes its key, and the reason it gives is
// specific: it joins an ORGANIZATION to a PERSON, and a stream name is a
// permanent artefact with no ciphertext for erasure to destroy — so the pair
// would still link that organization to that person after the person was
// erased.
//
// This key joins nothing. A SubjectID is already a pseudonym (ADR-002): on its
// own it reveals no name, no address and no membership, which is the entire
// property it was created to have. Hashing it would buy nothing and cost the
// ability to read the log while debugging — the same trade ADR-051 made when it
// chose to name the username reservation stream by the handle rather than by a
// keyed digest.
//
// It is also the reason the aggregate is keyed by the pseudonym rather than by
// a user id: profile depends on identity ONLY through the pseudonym, and never
// learns that identity's own identifiers exist.
//
// # Why one stream per person
//
// The stream is the consistency boundary, so it is also the concurrency
// boundary. One per person means two browser tabs saving one profile collide on
// the revision and one is told to retry — rather than both landing and leaving a
// state that is half of each save.
//
// A prefixed public identifier separates its prefix with '_' and never '-'
// (ADR-030), which is exactly what makes it safe as a stream key: KurrentDB
// derives a stream's category from everything before the FIRST dash, so a key
// containing one would file the stream under the wrong category and break every
// prefix-filtered subscription. eventsourcing.NewStreamID enforces that.
func StreamKey(subjectID string) string { return subjectID }
