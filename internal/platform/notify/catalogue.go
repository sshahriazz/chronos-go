package notify

import (
	"fmt"
	"sort"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// Audience is WHO an event notifies, expressed as a role rather than a list of
// people.
//
// A role, because the answer must be derivable from the event alone. "Whoever
// is in the recipients field" would let a producer decide who gets told, which
// is how a tenant ends up receiving another tenant's security alert.
type Audience uint8

const (
	// AudienceSubject is the data subject the event is about — the person whose
	// password changed, whose session was created. Taken from Metadata.SubjectIDs.
	AudienceSubject Audience = iota + 1

	// AudienceActor is whoever caused it, when that differs from the subject:
	// an admin who removed someone else's access.
	AudienceActor

	// AudienceOrgOwner is the single owner who holds the org's payment
	// relationship (workspace.md §2).
	AudienceOrgOwner

	// AudienceOrgAdmins is every administrator of the org.
	AudienceOrgAdmins

	// AudienceOperator is the people running the system. Never a tenant, and
	// never carrying tenant personal data.
	AudienceOperator
)

func (a Audience) String() string {
	switch a {
	case AudienceSubject:
		return "subject"
	case AudienceActor:
		return "actor"
	case AudienceOrgOwner:
		return "org_owner"
	case AudienceOrgAdmins:
		return "org_admins"
	case AudienceOperator:
		return "operator"
	default:
		return "unknown"
	}
}

// Spec declares that one event type produces one notification.
//
// This is the whole mapping, in one place: which event, which wording, which
// class, and to whom. Nothing else in the system decides any of it, so the
// answer to "what does this event send, and to whom?" is a lookup rather than
// an investigation.
type Spec struct {
	// Event is the stored event type. Derived from the type parameter by On,
	// never typed by hand.
	Event string

	// Template names the wording.
	Template string

	// Class decides whether it is delivered at all.
	Class Class

	// Audience decides who receives it.
	Audience Audience

	// Channels restricts delivery. Empty means every channel the class and the
	// recipient's preferences allow.
	Channels []Channel

	// Data extracts template input from the decoded event. It MUST NOT return
	// personal data: the recipient is resolved separately from the vault, and
	// anything identifying that came through here would end up in the event log
	// on its way to the template (ADR-002).
	Data func(eventsourcing.Event) map[string]any
}

// Catalogue is the single source of truth for what notifies whom.
//
// It is verified rather than trusted: Verify fails if any decodable event type
// has no decision recorded, so adding an event without deciding whether it
// notifies is a test failure, not a silent gap discovered when a user asks why
// they were never told.
type Catalogue struct {
	specs  map[string]Spec
	silent map[string]string // event type → why it notifies nobody
}

func NewCatalogue() *Catalogue {
	return &Catalogue{specs: map[string]Spec{}, silent: map[string]string{}}
}

// On registers a notification for an event type.
//
// The event type comes from T, so it cannot drift from the codec registration
// or be mistyped:
//
//	notify.On[identity.PasswordChanged](cat, notify.Spec{
//	    Template: "identity.password_changed",
//	    Class:    notify.Security,
//	    Audience: notify.AudienceSubject,
//	}, func(e *identity.PasswordChanged) map[string]any {
//	    return map[string]any{"Device": e.Device, "Location": e.City}
//	})
func On[T any, PT eventsourcing.EventPtr[T]](
	c *Catalogue, spec Spec, data func(PT) map[string]any,
) {
	eventType := eventsourcing.TypeOf[T, PT]()
	c.mustBeUndecided(eventType)

	spec.Event = eventType
	if data != nil {
		spec.Data = func(e eventsourcing.Event) map[string]any {
			typed, ok := e.(PT)
			if !ok {
				// The codec returned a different Go type than the catalogue
				// registered for this event name. Returning no data would send
				// a notification with empty placeholders where the device and
				// location should be — loud is better.
				panic(fmt.Sprintf(
					"notify: %s decoded as %T but the catalogue expects %T; "+
						"the codec and the catalogue disagree about this event",
					eventType, e, PT(nil)))
			}
			return data(typed)
		}
	}
	if err := spec.validate(); err != nil {
		panic(fmt.Sprintf("notify: %s: %v", eventType, err))
	}
	c.specs[eventType] = spec
}

// Silent records that an event deliberately notifies nobody.
//
// Required, not optional. Without it "no entry" is ambiguous between "decided
// against" and "nobody thought about it", and the second is the one that ships
// a security event nobody is ever told about. The reason is stored so a reader
// gets the decision, not just its absence.
func Silent[T any, PT eventsourcing.EventPtr[T]](c *Catalogue, reason string) {
	eventType := eventsourcing.TypeOf[T, PT]()
	c.mustBeUndecided(eventType)
	if reason == "" {
		panic(fmt.Sprintf("notify: %s: Silent requires a reason", eventType))
	}
	c.silent[eventType] = reason
}

func (c *Catalogue) mustBeUndecided(eventType string) {
	if _, dup := c.specs[eventType]; dup {
		panic(fmt.Sprintf("notify: %s already notifies; a second entry would send twice", eventType))
	}
	if _, dup := c.silent[eventType]; dup {
		panic(fmt.Sprintf("notify: %s is already declared silent", eventType))
	}
}

// For looks up the notification an event produces.
func (c *Catalogue) For(eventType string) (Spec, bool) {
	s, ok := c.specs[eventType]
	return s, ok
}

// IsSilent reports whether an event was deliberately declared non-notifying,
// and why.
func (c *Catalogue) IsSilent(eventType string) (string, bool) {
	r, ok := c.silent[eventType]
	return r, ok
}

// Events lists every event type that produces a notification, sorted.
func (c *Catalogue) Events() []string { return sortedKeys(c.specs) }

// Templates lists every template the catalogue references, sorted. Used to
// assert that each one actually exists in the renderer.
func (c *Catalogue) Templates() []string {
	seen := map[string]struct{}{}
	for _, s := range c.specs {
		seen[s.Template] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// EventTypePrefixes is the subscription filter covering exactly the events this
// catalogue cares about, so the worker is not handed traffic it will discard.
func (c *Catalogue) EventTypePrefixes() []string { return c.Events() }

// Verify reports every decodable event type with no decision recorded.
//
// Call it with the codec's registered types in a test. This is the mechanism
// that makes the mapping deterministic rather than aspirational: a new event
// type fails here until someone decides, in the catalogue, whether it notifies.
func (c *Catalogue) Verify(known []string) error {
	var undecided []string
	for _, t := range known {
		if _, ok := c.specs[t]; ok {
			continue
		}
		if _, ok := c.silent[t]; ok {
			continue
		}
		undecided = append(undecided, t)
	}
	if len(undecided) == 0 {
		return nil
	}
	sort.Strings(undecided)
	return fmt.Errorf(
		"notify: %d event type(s) have no notification decision: %v\n"+
			"Every event must be declared either notifying (notify.On) or deliberately "+
			"silent (notify.Silent with a reason). Leaving one out means nobody is told "+
			"and nothing says so",
		len(undecided), undecided)
}

// Orphans reports catalogue entries for event types the codec cannot decode —
// a renamed or retired event whose notification was left behind.
func (c *Catalogue) Orphans(known []string) []string {
	index := make(map[string]struct{}, len(known))
	for _, t := range known {
		index[t] = struct{}{}
	}
	var out []string
	for t := range c.specs {
		if _, ok := index[t]; !ok {
			out = append(out, t)
		}
	}
	for t := range c.silent {
		if _, ok := index[t]; !ok {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

func (s Spec) validate() error {
	switch {
	case s.Template == "":
		return fmt.Errorf("template is required")
	case s.Class == 0:
		return fmt.Errorf("class is required")
	case s.Audience == 0:
		return fmt.Errorf("audience is required — who receives this must not be implicit")
	case s.Class == Operator && s.Audience != AudienceOperator:
		return fmt.Errorf("operator-class notifications must have the operator audience")
	case s.Class != Operator && s.Audience == AudienceOperator:
		return fmt.Errorf("the operator audience requires the operator class, " +
			"or tenant wording would be sent to operators")
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
