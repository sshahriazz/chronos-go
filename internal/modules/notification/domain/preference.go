// Package domain holds notification's invariants: what a person may switch off,
// what they may never switch off, and what a browser endpoint has to look like
// before this system will post to it.
//
// It is PURE. No driver, no protobuf, no clock of its own — every time comes in
// as an argument (CONVENTIONS §2). It imports `platform/notify` for one reason
// and it is the important one: the class vocabulary and the predicate that
// decides whether a class consults preferences at all live there, and a second
// copy of that predicate here would eventually disagree with the one the
// dispatcher enforces. A disagreement about THAT predicate is a security alert
// nobody receives.
package domain

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/chronos/chronos-go/internal/modules/notification/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

// ErrNotGovernable is a channel a person does not control.
var ErrNotGovernable = errors.New("notification: that channel is not a user preference")

// Governable lists the channels a person may switch, in a stable order.
//
// Three, and the realtime stream is deliberately not among them: it carries
// transient signals rather than notifications, and a browser holding an open
// subscription to it has already said it wants them. Adding a fourth here is the
// only way to grow the settings screen, which keeps "what can a person switch
// off" answerable by reading one slice.
func Governable() []notify.Channel {
	return []notify.Channel{notify.ChannelEmail, notify.ChannelInApp, notify.ChannelWebPush}
}

// IsGovernable reports whether a channel is one a person controls.
func IsGovernable(ch notify.Channel) bool { return slices.Contains(Governable(), ch) }

// Classes is every notification class this system has, in a stable order.
//
// Enumerated here rather than derived, because Go has no way to range over the
// values of a constant block — and the enumeration is CHECKED: a class added to
// platform/notify and not added here fails TestEveryClassIsPartitioned, which is
// what stops a new class from silently defaulting into neither list below.
func Classes() []notify.Class {
	return []notify.Class{
		notify.Security, notify.Transactional,
		notify.Activity, notify.Product, notify.Operator,
	}
}

// GovernedClasses is what a channel toggle actually reaches.
//
// Computed from notify.Class.IgnoresPreferences — the SAME predicate the
// dispatcher applies before it consults any preference — and never from a list
// written out by hand. That is what makes "you may turn off product mail but not
// the message telling you your second factor was removed" enforceable rather
// than documented: the API's own answer about what a toggle governs is derived
// from the runtime rule, so the two cannot drift apart. If someone made Security
// preference-respecting, this function would immediately report Security as
// governed and the tests that assert otherwise would fail — instead of the
// change landing silently and disabling the account-takeover tripwire.
//
// Operator never appears: an operator alert has no tenant recipient, so there is
// nobody whose preference could apply to it.
func GovernedClasses() []notify.Class {
	out := make([]notify.Class, 0, len(Classes()))
	for _, c := range Classes() {
		if c == notify.Operator {
			continue
		}
		if !c.IgnoresPreferences() {
			out = append(out, c)
		}
	}
	return out
}

// AlwaysDeliveredClasses is what no toggle can suppress.
//
// The complement of GovernedClasses over the tenant-facing classes, computed the
// same way and for the same reason.
func AlwaysDeliveredClasses() []notify.Class {
	out := make([]notify.Class, 0, len(Classes()))
	for _, c := range Classes() {
		if c == notify.Operator {
			continue
		}
		if c.IgnoresPreferences() {
			out = append(out, c)
		}
	}
	return out
}

// Setting is one channel switched on or off.
type Setting struct {
	Channel notify.Channel
	Enabled bool
}

// Preferences is one person's channel toggles in one organization.
//
// The aggregate exists to make two things true that a bare table cannot:
//
//   - Concurrent saves are ORDERED. All of one person's changes in one
//     organization live on one stream, so two settings screens saving at the
//     same moment collide on the stream's revision and one of them is told to
//     retry — rather than both landing and leaving a state that is half of each.
//   - A no-op records NOTHING. Turning email off when it is already off appends
//     no event, so the log is a history of changes rather than of saves, and
//     "when did they turn this off" has one answer.
//
// It stores channel booleans and nothing else. There is no field for a class and
// no field for a template, which is the structural half of why a preference can
// never silence a security alert: the aggregate has nowhere to put such a
// preference even if a caller could express one.
type Preferences struct {
	eventsourcing.Base

	subjectID string
	orgID     string

	// enabled holds only what was explicitly SET. A missing key means the person
	// never touched that channel, which reads as enabled — so a failure to write
	// a default cannot silence anyone.
	enabled map[notify.Channel]bool
}

var _ eventsourcing.Root = (*Preferences)(nil)

// NewPreferences returns an empty aggregate for the repository to rebuild into.
func NewPreferences() *Preferences {
	return &Preferences{enabled: map[notify.Channel]bool{}}
}

// Apply replays one event. Pure, and it validates nothing: it runs during
// rebuild over events that are already facts, and refusing one there would make
// the stream unloadable.
func (p *Preferences) Apply(e eventsourcing.Event) {
	if set, ok := e.(*contract.ChannelPreferenceSet); ok {
		if p.enabled == nil {
			p.enabled = map[notify.Channel]bool{}
		}
		p.subjectID = set.SubjectID
		p.orgID = set.OrgID
		p.enabled[notify.Channel(set.Channel)] = set.Enabled
	}
}

// Enabled reports the state of one channel. Absent means enabled.
func (p *Preferences) Enabled(ch notify.Channel) bool {
	if v, ok := p.enabled[ch]; ok {
		return v
	}
	return true
}

// Current is every governable channel with its state, in Governable order.
//
// All three are always returned, including channels the person has never
// touched. A settings screen showing only what was explicitly set would render
// two switches on a fresh account and leave the third invisible.
func (p *Preferences) Current() []Setting {
	out := make([]Setting, 0, len(Governable()))
	for _, ch := range Governable() {
		out = append(out, Setting{Channel: ch, Enabled: p.Enabled(ch)})
	}
	return out
}

// Set applies a batch of toggles, recording one event per channel that actually
// changed.
//
// The batch is all-or-nothing at the VALIDATION step: an ungovernable channel
// anywhere in the batch refuses the whole call and records nothing, so a save
// cannot half-apply because one switch in it was nonsense.
//
// subjectID and orgID are passed in rather than taken from the aggregate,
// because the aggregate is empty until its first event and the first save has to
// establish them. They are the CALLER'S, resolved from the session and the
// request scope; nothing in a Setting can change who this is about.
func (p *Preferences) Set(
	subjectID, orgID string, settings []Setting, at time.Time,
) error {
	switch {
	case subjectID == "":
		return errors.New("notification: setting preferences needs a subject")
	case orgID == "":
		// Preferences are per person PER ORGANIZATION, and the row is scoped by
		// org under RLS. An empty org would write a row no policy admits.
		return errors.New("notification: setting preferences needs an organization")
	case len(settings) == 0:
		return errors.New("notification: a preference change with no channels changes nothing")
	}
	if p.subjectID != "" && p.subjectID != subjectID {
		// The repository loads this stream by a key derived from the subject and
		// the org, so reaching here means the derivation and the caller disagree.
		// Refused rather than overwritten: the alternative writes one person's
		// preference into another person's stream.
		return fmt.Errorf("notification: this preference stream belongs to another subject")
	}
	if p.orgID != "" && p.orgID != orgID {
		return fmt.Errorf("notification: this preference stream belongs to another organization")
	}

	seen := make(map[notify.Channel]struct{}, len(settings))
	for _, s := range settings {
		if !IsGovernable(s.Channel) {
			return fmt.Errorf("%w: %q", ErrNotGovernable, string(s.Channel))
		}
		if _, dup := seen[s.Channel]; dup {
			// Two entries for one channel means the batch contains its own
			// contradiction, and whichever came last would silently win.
			return fmt.Errorf("notification: channel %q appears twice in one change",
				string(s.Channel))
		}
		seen[s.Channel] = struct{}{}
	}

	for _, s := range settings {
		if p.Enabled(s.Channel) == s.Enabled && p.explicit(s.Channel) {
			// Already in that state, explicitly. Recording it again would put a
			// change in the log that nothing changed.
			continue
		}
		if s.Enabled && !p.explicit(s.Channel) {
			// Enabling a channel that was never switched off. The row does not
			// exist, absence already means enabled, and writing one would record
			// a decision the person did not make.
			continue
		}
		eventsourcing.Record(p, &contract.ChannelPreferenceSet{
			SubjectID: subjectID,
			OrgID:     orgID,
			Channel:   string(s.Channel),
			Enabled:   s.Enabled,
			ChangedAt: at.UTC(),
		})
	}
	return nil
}

func (p *Preferences) explicit(ch notify.Channel) bool {
	_, ok := p.enabled[ch]
	return ok
}
