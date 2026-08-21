// Package contract is the profile module's published surface — the only package
// another module may import (CONVENTIONS §1).
//
// Plain structs, no wire tags: serialization is the codec's job (ADR-001).
//
// # There is exactly one event, and that is the design
//
// A profile is a bag of presentation attributes that will only ever grow:
// pronouns, a job title, a pronunciation clip, a header image. An event per
// attribute would mean, for each one, a new stored type, a new codec
// registration in three binaries, a new entry in the notification catalogue, a
// new schema version and — the first time one of them changed shape — a new
// upcaster. That cost is paid per attribute forever, and it is paid to record
// nothing the single event could not.
//
// So there is one event with a SPARSE payload. Adding an attribute is a pointer
// field here, a column in the projection, and a field in the request message.
// No new event type, no catalogue entry, no upcaster.
//
// # Nothing here carries personal data
//
// The display name, the locale and the timezone are personal data
// (internal/platform/pii). This event records THAT each changed and never WHAT
// it changed to; the values go to the PII vault, which is where
// internal/platform/notify resolves them from at delivery time. An event is
// permanent and replayable, so a name in one is a name that outlives every
// erasure request the log will ever see (ADR-002).
//
// The avatar is the one value that does travel, and it travels as an object
// key: an opaque per-subject digest prefix and a random name, with no business
// meaning in it (ADR-013). No image is ever in an event.
package contract

import "time"

// Change is what happened to one field in a sparse update.
//
// A string constant rather than an int or a bool, for two reasons. Enums as raw
// ints let a reordered constant block rewrite history (CONVENTIONS §3), and a
// bool cannot grow a third state — "pending moderation" is the obvious next one
// — without changing the payload's shape and needing an upcaster.
type Change string

const (
	// Set means the field now holds a value. For the vault-held fields, the
	// value itself is in the vault and deliberately not here.
	Set Change = "set"

	// Cleared means the field now holds nothing.
	//
	// Distinct from a nil pointer, which means the field was not part of this
	// update at all. That distinction is the whole point of the payload's
	// shape: "leave my timezone alone" and "remove my timezone" are different
	// requests, and a shape that cannot tell them apart turns a settings screen
	// which renders three fields into one that silently erases the fourth.
	Cleared Change = "cleared"
)

// AvatarChange is what happened to the avatar, and where it now points.
//
// The one field of ProfileUpdated whose VALUE is in the event, because an
// object key is not personal data: it is a random name under a digest prefix,
// it identifies bytes rather than a person, and the projection needs it to be
// rebuildable from the log alone.
//
// When Change is Cleared the three reference fields are empty — the domain
// refuses to record anything else — so a projector can apply this without a
// branch on which combination it received.
type AvatarChange struct {
	// Change is Set or Cleared.
	Change Change

	// ObjectKey names the stored image. Empty when Cleared.
	ObjectKey string

	// ContentType is what the OBJECT STORE reported the stored bytes to be,
	// never what the uploader claimed. Empty when Cleared.
	ContentType string

	// SizeBytes is the stored object's size as the object store reported it.
	// Zero when Cleared.
	SizeBytes int64
}

// ProfileUpdated is the whole of what this module records.
//
// Every optional field is a POINTER, and nil means "this update did not mention
// this field". That is not a serialization convenience: it is the only way the
// log can distinguish a save that left a field alone from one that emptied it,
// and a projector applying the second reading to the first would erase data
// nobody asked it to touch.
type ProfileUpdated struct {
	// SubjectID is whose profile this is — the pseudonym, and the only way a
	// person appears in this event (ADR-002).
	//
	// On the payload as well as in the envelope because a projector rebuilding
	// from position zero must be able to scope each row from the event alone,
	// without the envelope having been written correctly by every producer that
	// ever existed.
	SubjectID string

	// DisplayName records that the name other people read changed. The name is
	// in the vault; only the fact is here.
	DisplayName *Change

	// Locale records that the language wording is rendered in changed.
	Locale *Change

	// Timezone records that the zone timestamps are rendered in changed.
	Timezone *Change

	// Avatar records that the picture changed, and carries its new reference.
	Avatar *AvatarChange

	// UpdatedAt is when the change was decided, UTC.
	UpdatedAt time.Time
}

func (*ProfileUpdated) EventType() string { return "profile.ProfileUpdated.v1" }
