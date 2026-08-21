package domain

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// Category is the stream category every notification stream lives under.
//
// One category for the whole module, because the projectors filter on it: a feed
// item, a push subscription and a preference change all reach
// `notification_feed`'s and `notification_push_subscriptions`' subscriptions
// through the same `notification-` prefix, and a second category would need a
// second filter in every one of them.
const Category eventsourcing.Category = "notification"

// PreferenceStreamKey names the stream holding one person's channel toggles in
// one organization.
//
// # Why it is a digest rather than the two ids joined
//
// A stream name is PERMANENT. It appears in the `$streams` index and in every
// category stream, it is never rewritten, and — unlike an event payload — it has
// no ciphertext for erasure to destroy (ADR-048). A subject id is already a
// pseudonym rather than personal data, so this is not the difference between
// safe and unsafe; it is the difference between a permanent artefact that still
// links an organization to a person after that person is erased, and one that
// does not.
//
// It also removes a naming hazard that has bitten this repository before:
// KurrentDB derives a stream's category from everything before the FIRST dash,
// so a composite key has to avoid dashes, and a digest cannot accidentally
// contain one.
//
// # Why one stream per (subject, organization) rather than per subject
//
// The stream is the consistency boundary, so it is also the concurrency
// boundary. Per (subject, organization) means two settings screens for the SAME
// organization collide on the revision and one is told to retry, while a person
// changing preferences in two organizations at once does not contend at all —
// which is correct, because those are two independent decisions about two
// independent sets of rows.
//
// The NUL separator is what stops one pair being re-spelled as another.
func PreferenceStreamKey(orgID, subjectID string) string {
	sum := sha256.Sum256([]byte("chronos.notification.preferences\x00" + orgID + "\x00" + subjectID))
	return "pref" + hex.EncodeToString(sum[:16])
}
