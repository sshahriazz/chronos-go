// Package domain holds profile's invariants: what a display name, a locale, a
// timezone and an avatar reference may be, and what one sparse update to them
// records.
//
// It is PURE. No driver, no protobuf, no clock of its own — every time comes in
// as an argument (CONVENTIONS §2). It does not know that a PII vault exists,
// which is why no VALUE of a vault-held field ever reaches it: the aggregate is
// told THAT a field changed, and the app layer is what puts the value where it
// belongs.
//
// # Why this is its own module and not part of identity
//
// Identity answers "who is this": credentials, sessions, lifecycle. Every
// attribute added to that aggregate widens the thing that guards
// authentication, and a display name is presentation. Splitting them is the
// same move ADR-020 made for `organization` and `workspace`, for the same
// reason — two things whose growth directions differ end up as one thing where
// everything lands, because everything is a little bit about a person.
//
// The dependency is one-directional and thinner than that one: profile depends
// on identity ONLY through the pseudonym, and identity never learns this module
// exists.
package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	// Imported for its side effect: it embeds the IANA zone database so
	// time.LoadLocation answers the same way on every machine that runs this
	// code.
	//
	// Without it, whether "Europe/Berlin" is a valid timezone depends on
	// whether the host happens to ship /usr/share/zoneinfo — true on a
	// developer's laptop, false in a scratch container. A domain rule whose
	// answer depends on the image it is running in is not a rule.
	_ "time/tzdata"

	"github.com/chronos/chronos-go/internal/modules/profile/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// Field-shape errors. Separate from ErrAvatarRefused because they name input a
// caller can fix, and the API layer maps them to VALIDATION_FAILED.
var (
	// ErrDisplayNameRefused is a name this system will not store.
	ErrDisplayNameRefused = errors.New("profile: display name refused")

	// ErrLocaleRefused is a locale tag this system will not store.
	ErrLocaleRefused = errors.New("profile: locale refused")

	// ErrTimezoneRefused is a zone name this system will not store.
	ErrTimezoneRefused = errors.New("profile: timezone refused")

	// ErrNotClearable is an attempt to empty a field that has no empty state.
	//
	// It exists because the alternative — treating an empty value as "leave it
	// alone" — silently does nothing to a request that plainly meant something,
	// and the person is left looking at a save that appeared to work.
	ErrNotClearable = errors.New("profile: this field cannot be cleared")

	// ErrNothingToUpdate is an update that names no field.
	ErrNothingToUpdate = errors.New("profile: an update that names no field changes nothing")

	// ErrWrongSubject is an update aimed at another person's stream.
	ErrWrongSubject = errors.New("profile: this profile belongs to another subject")
)

// MaxDisplayNameLen bounds the one piece of free text this module accepts.
//
// Bounded because it is rendered into mail subjects, in-app headers and push
// payloads, all of which truncate — and because an unbounded value is an
// unbounded row in the PII vault, which is the one store that cannot be rebuilt
// (ADR-013).
const MaxDisplayNameLen = 80

// ParseDisplayName normalises and validates the name other people read.
//
// # Why this exists when protovalidate already has a rule
//
// The schema constrains what a CLIENT may send. This constrains what the system
// will ever HOLD, including values that arrive from a test, a future caller that
// is not an RPC, or an import. That is the same division ParsePushEndpoint draws
// in notification's domain, and it is the reason the checks overlap rather than
// one of them being redundant.
//
// # What is refused, and why each one
//
//   - Empty, after trimming. A blank name renders as a gap where a person's
//     identity should be, and it is not how you remove one — see ErrNotClearable.
//   - Control and formatting characters. A name is displayed next to other
//     people's names; a bidirectional override in one reorders the text around
//     it, and a zero-width joiner or a line separator lets one name impersonate
//     the layout of another. These are invisible by construction, so no reviewer
//     and no reader catches them.
//   - Over MaxDisplayNameLen runes. Counted in RUNES rather than bytes, so the
//     limit is the same number of characters for every script rather than three
//     times stricter for anyone writing in one that needs three bytes a
//     character.
func ParseDisplayName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", fmt.Errorf("%w: it is empty (%w)", ErrDisplayNameRefused, ErrNotClearable)
	}
	for _, r := range name {
		// Cc is C0/C1 controls, Cf is formatting characters — which is where
		// every bidirectional override lives — and Zl/Zp are the line and
		// paragraph separators. None of them has any business in a name, and
		// all of them are invisible when rendered.
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) ||
			unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return "", fmt.Errorf(
				"%w: it contains a control or formatting character, which is invisible "+
					"when displayed and can reorder the text around it", ErrDisplayNameRefused)
		}
	}
	if n := len([]rune(name)); n > MaxDisplayNameLen {
		return "", fmt.Errorf("%w: it is %d characters, over the %d-character limit",
			ErrDisplayNameRefused, n, MaxDisplayNameLen)
	}
	return name, nil
}

// ParseLocale validates a BCP-47 language tag, in the subset this system needs.
//
// Deliberately narrow: a language, an optional script, an optional region. That
// covers `en`, `en-GB`, `zh-Hans`, `zh-Hans-CN` and `es-419`, which is every
// shape a translation catalogue is keyed by. Extensions, variants and private
// use subtags are refused rather than stored — nothing renders differently for
// them, and accepting a value nothing reads makes the field a place to put
// arbitrary text.
//
// Case is significant and is NOT normalised: BCP-47 case conventions are
// `en-Latn-GB`, and a tag that arrives mis-cased is a client bug worth
// reporting rather than one worth hiding.
func ParseLocale(raw string) (string, error) {
	tag := strings.TrimSpace(raw)
	if tag == "" {
		return "", fmt.Errorf("%w: it is empty (%w)", ErrLocaleRefused, ErrNotClearable)
	}
	parts := strings.Split(tag, "-")
	if len(parts) > 3 {
		return "", fmt.Errorf("%w: %q has more subtags than a language, a script and a region",
			ErrLocaleRefused, tag)
	}

	language := parts[0]
	if !isAlpha(language, 2, 3, unicode.IsLower) {
		return "", fmt.Errorf("%w: %q does not begin with a two- or three-letter "+
			"lowercase language subtag", ErrLocaleRefused, tag)
	}
	rest := parts[1:]

	if len(rest) > 0 && isScriptSubtag(rest[0]) {
		rest = rest[1:]
	}
	if len(rest) > 0 {
		if !isRegionSubtag(rest[0]) {
			return "", fmt.Errorf("%w: %q ends in something that is neither a script nor "+
				"a region subtag", ErrLocaleRefused, tag)
		}
		rest = rest[1:]
	}
	if len(rest) > 0 {
		return "", fmt.Errorf("%w: %q carries subtags this system does not use",
			ErrLocaleRefused, tag)
	}
	return tag, nil
}

// isScriptSubtag reports the `Latn`/`Hans` shape: four letters, title case.
func isScriptSubtag(s string) bool {
	if len(s) != 4 || !unicode.IsUpper(rune(s[0])) {
		return false
	}
	return isAlpha(s[1:], 3, 3, unicode.IsLower)
}

// isRegionSubtag reports the `GB`/`419` shape: two uppercase letters or three
// digits.
func isRegionSubtag(s string) bool {
	if isAlpha(s, 2, 2, unicode.IsUpper) {
		return true
	}
	if len(s) != 3 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isAlpha(s string, minLen, maxLen int, class func(rune) bool) bool {
	if len(s) < minLen || len(s) > maxLen {
		return false
	}
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsLetter(r) || !class(r) {
			return false
		}
	}
	return true
}

// ParseTimezone validates an IANA zone name.
//
// # A zone name, never an offset
//
// `+01:00` is not a timezone. It is what a timezone happened to be at one
// instant, and it is wrong for half of every year across most of the world — so
// somebody who set one in January would silently start receiving mail an hour
// out in March, with nothing to indicate why. Only names are accepted.
//
// # It is resolved, not merely shaped
//
// time.LoadLocation is what says whether a name exists, and the embedded tzdata
// import at the top of this file is what makes that answer the same everywhere.
// A regex would accept `Europe/Berlim`, which renders every timestamp in UTC
// forever while looking configured.
//
// `Local` is refused explicitly. It parses, and it means "whatever zone the
// process happens to be in" — so a person who set it would see the SERVER's
// timezone rather than their own, and would see a different one after a
// deployment to a different region (ADR-035).
func ParseTimezone(raw string) (string, error) {
	zone := strings.TrimSpace(raw)
	switch {
	case zone == "":
		return "", fmt.Errorf("%w: it is empty (%w)", ErrTimezoneRefused, ErrNotClearable)
	case len(zone) > 64:
		return "", fmt.Errorf("%w: it is %d bytes", ErrTimezoneRefused, len(zone))
	case zone == "Local":
		return "", fmt.Errorf("%w: %q is whichever zone the server is in, not a zone",
			ErrTimezoneRefused, zone)
	}
	if _, err := time.LoadLocation(zone); err != nil {
		// The wrapped error names the file the zone database did not contain,
		// which is a path — so it is deliberately not surfaced to the caller.
		return "", fmt.Errorf("%w: %q is not an IANA zone name", ErrTimezoneRefused, zone)
	}
	return zone, nil
}

// Update is one sparse change to a profile.
//
// Every field is a POINTER and nil means "not part of this update". The three
// vault-held fields carry a *bool rather than a value, because the domain never
// sees the value: true means "a value was supplied and is on its way to the
// vault", false means "remove it".
type Update struct {
	// DisplayName, Locale and Timezone are the vault-held fields. A non-nil
	// false is the CLEAR case, which the aggregate records faithfully — see
	// Apply — even though the app layer cannot yet produce one.
	DisplayName *bool
	Locale      *bool
	Timezone    *bool

	// Avatar is the picture. A non-nil pointer to a zero Avatar means REMOVE.
	Avatar *Avatar
}

// IsEmpty reports an update that names no field.
func (u Update) IsEmpty() bool {
	return u.DisplayName == nil && u.Locale == nil && u.Timezone == nil && u.Avatar == nil
}

// Profile is one person's presentation attributes.
//
// It holds no personal data, and could not: the values of the vault-held fields
// never reach this package. What it holds is which fields are set and where the
// avatar points — enough to decide whether a change is a change, and nothing
// more.
type Profile struct {
	eventsourcing.Base

	subjectID      string
	displayNameSet bool
	localeSet      bool
	timezoneSet    bool
	avatar         Avatar
}

var _ eventsourcing.Root = (*Profile)(nil)

// NewProfile returns an empty aggregate for the repository to rebuild into.
func NewProfile() *Profile { return &Profile{} }

// SubjectID is whose profile this is, empty until the first event.
func (p *Profile) SubjectID() string { return p.subjectID }

// Avatar is the current reference, zero when there is none.
func (p *Profile) Avatar() Avatar { return p.avatar }

// HasDisplayName, HasLocale and HasTimezone report whether the vault currently
// holds each field for this subject, as far as the log knows.
func (p *Profile) HasDisplayName() bool { return p.displayNameSet }
func (p *Profile) HasLocale() bool      { return p.localeSet }
func (p *Profile) HasTimezone() bool    { return p.timezoneSet }

// Apply replays one event.
//
// Pure, and it validates nothing: it runs during rebuild over events that are
// already facts, and refusing one there would make the stream unloadable.
//
// The nil checks are what make the sparse payload work on the read side. A
// field this event did not mention leaves the aggregate's copy of it alone,
// which is the same rule the projection's COALESCE applies to the table.
func (p *Profile) Apply(e eventsourcing.Event) {
	u, ok := e.(*contract.ProfileUpdated)
	if !ok {
		return
	}
	p.subjectID = u.SubjectID
	if u.DisplayName != nil {
		p.displayNameSet = *u.DisplayName == contract.Set
	}
	if u.Locale != nil {
		p.localeSet = *u.Locale == contract.Set
	}
	if u.Timezone != nil {
		p.timezoneSet = *u.Timezone == contract.Set
	}
	if u.Avatar != nil {
		if u.Avatar.Change == contract.Cleared {
			p.avatar = Avatar{}
		} else {
			p.avatar = Avatar{
				ObjectKey:   u.Avatar.ObjectKey,
				ContentType: u.Avatar.ContentType,
				SizeBytes:   u.Avatar.SizeBytes,
			}
		}
	}
}

// Update records ONE event carrying only the fields that actually changed, and
// records nothing when nothing did.
//
// # One event, not one per field
//
// A save that changes a name, a timezone and an avatar is one fact — "they
// edited their profile" — and splitting it into three would make a partial
// application representable in the log, which is the state the aggregate exists
// to prevent.
//
// # What counts as a change
//
// The avatar is compared by object key, so re-confirming the key already stored
// records nothing. The three vault-held fields cannot be compared here: their
// values are in the vault and this package must never see one, so supplying a
// name records that the name was set even when the new name equals the old.
// That is the honest answer available — the log then says "they saved their
// name at T", which is true — and the alternative would mean reading personal
// data into the domain to avoid writing an event.
//
// subjectID is passed in rather than taken from the aggregate, because the
// aggregate is empty until its first event and the first save has to establish
// it. It is the CALLER'S, resolved from the session; nothing in an Update can
// change who this is about.
func (p *Profile) Update(subjectID string, u Update, at time.Time) error {
	if subjectID == "" {
		return errors.New("profile: an update needs a subject")
	}
	if u.IsEmpty() {
		return ErrNothingToUpdate
	}
	if p.subjectID != "" && p.subjectID != subjectID {
		// The repository loads this stream by a key derived from the subject, so
		// reaching here means the derivation and the caller disagree. Refused
		// rather than overwritten: the alternative writes one person's profile
		// into another person's stream.
		return ErrWrongSubject
	}

	event := &contract.ProfileUpdated{SubjectID: subjectID, UpdatedAt: at.UTC()}
	changed := false

	if c := changeFor(u.DisplayName, p.displayNameSet); c != nil {
		event.DisplayName, changed = c, true
	}
	if c := changeFor(u.Locale, p.localeSet); c != nil {
		event.Locale, changed = c, true
	}
	if c := changeFor(u.Timezone, p.timezoneSet); c != nil {
		event.Timezone, changed = c, true
	}

	if u.Avatar != nil {
		switch {
		case u.Avatar.IsZero() && p.avatar.IsZero():
			// Removing an avatar that is not there. The caller wanted it gone
			// and it is gone; recording it would put a change in the log that
			// changed nothing.
		case u.Avatar.IsZero():
			event.Avatar = &contract.AvatarChange{Change: contract.Cleared}
			changed = true
		case u.Avatar.ObjectKey == p.avatar.ObjectKey:
			// Confirming the key already stored — a retried confirm, or a second
			// tab. Not a change.
		default:
			event.Avatar = &contract.AvatarChange{
				Change:      contract.Set,
				ObjectKey:   u.Avatar.ObjectKey,
				ContentType: u.Avatar.ContentType,
				SizeBytes:   u.Avatar.SizeBytes,
			}
			changed = true
		}
	}

	if !changed {
		return nil
	}
	eventsourcing.Record(p, event)
	return nil
}

// changeFor turns "the caller supplied this field" into the event's marker, or
// nil when recording it would say nothing.
//
// The two directions are deliberately asymmetric. SETTING is always recorded,
// because this package cannot compare the values — they are in the vault, and
// the whole point is that they never come here. CLEARING a field that is
// already clear IS visible, and recording it would put a change in the log that
// changed nothing.
func changeFor(supplied *bool, currentlySet bool) *contract.Change {
	if supplied == nil {
		return nil
	}
	if *supplied {
		c := contract.Set
		return &c
	}
	if !currentlySet {
		return nil
	}
	c := contract.Cleared
	return &c
}
