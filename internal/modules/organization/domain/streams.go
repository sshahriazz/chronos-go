package domain

import (
	"strings"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// Category is the stream category every organization stream lives under.
//
// One category for the module, so a projector reads `$ce-organization` instead
// of scanning the whole log on every rebuild (ADR-042).
const Category eventsourcing.Category = "organization"

// StreamKey names the stream holding one organization's history.
//
// The org id itself. Unlike a person, an organization is not a data subject —
// there is no pseudonym to protect and nothing for erasure to destroy — so
// there is no reason to key it by a digest and every reason to keep the log
// readable while debugging.
//
// A prefixed public id separates its prefix with '_' and never '-' (ADR-030),
// which is what makes it safe as a stream key: KurrentDB derives a stream's
// category from everything before the FIRST dash, so a key containing one files
// the stream under the wrong category and breaks every prefix-filtered
// subscription. eventsourcing.NewStreamID enforces it.
func StreamKey(orgID string) string { return orgID }

// OwnerCategory holds one stream per subject, enforcing one organization per
// owner.
//
// Its own category rather than a stream inside `organization`, because the
// claim is about a PERSON and outlives any single organization: closing one
// releases the reservation, and the release belongs on the same stream as the
// hold.
const OwnerCategory eventsourcing.Category = "orgowner"

// OwnerStreamKey names the reservation stream for one subject.
//
// The SubjectID in the clear. A SubjectID is already a pseudonym (ADR-002) — on
// its own it names no person — and this stream joins it to nothing else, so
// there is nothing here for erasure to have to destroy. The same reasoning
// profile's StreamKey records.
func OwnerStreamKey(subjectID string) string { return subjectID }

// SlugCategory holds one stream per organization slug.
const SlugCategory eventsourcing.Category = "orgslug"

// SlugStreamKey names the reservation stream for one slug.
//
// The slug is published in URLs, so hiding it protects nothing and costs the
// ability to read the log while debugging — ADR-051's reasoning for the
// username. It cannot be used VERBATIM, though, and the reason is structural
// rather than aesthetic.
//
// KurrentDB derives a stream's category from everything before the FIRST dash,
// which is why eventsourcing.NewStreamID refuses a key containing one. A slug
// with a hyphen is entirely ordinary — `acme-corp` is what most organizations
// will choose — so `orgslug-acme-corp` would file the stream under category
// `orgslug` with key `acme`, and every slug sharing a first segment would
// collide into one reservation.
//
// So hyphens become underscores. The mapping is injective because a slug may
// NOT contain an underscore: NewSlug's pattern allows lowercase letters, digits
// and hyphens only, and ADR-030 reserves '_' to separate a prefix from a public
// id. `acme-corp` and `acme_corp` therefore cannot both exist as slugs, and the
// stream name stays readable.
//
// This was found by the first integration test to create an organization —
// every creation failed with "slug reservation stream", because the test's own
// generated slugs contained hyphens.
func SlugStreamKey(slug string) string { return strings.ReplaceAll(slug, "-", "_") }
