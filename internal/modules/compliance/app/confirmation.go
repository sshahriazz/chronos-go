package app

import (
	"context"
	"fmt"

	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

// ConfirmationTemplate is the wording. Permanent: it appears in metrics, logs
// and operator overrides.
const ConfirmationTemplate = "compliance.erasure_complete"

// Notifier delivers one notification. The platform dispatcher satisfies it.
type Notifier interface {
	Dispatch(ctx context.Context, n notify.Notification) error
}

// MailConfirmation sends the erasure confirmation.
//
// # Why this is not a notification-catalogue entry
//
// Every other mail in this system is data: an event type maps to a template and
// an audience, and one reactor sends them all. This one cannot be, and the
// reason is ordering rather than taste.
//
// The catalogue fires on an EVENT. The only event that could carry this is
// `UserErased`, which is appended AFTER the key is destroyed — and by then the
// vault answers a tombstone for this subject, so there is no address to resolve.
// NOTIFICATIONS §4 is explicit that a send to an erased subject is SKIPPED
// rather than failed, which means a catalogue entry here would silently send
// nothing, forever, and look like it worked.
//
// So it is dispatched directly, from inside the erasure, one step before the
// destroy. That is also the only place that knows what was retained.
type MailConfirmation struct{ notifier Notifier }

func NewMailConfirmation(notifier Notifier) (*MailConfirmation, error) {
	if notifier == nil {
		return nil, fmt.Errorf("compliance: a notifier is required; the erasure " +
			"confirmation is the one message that cannot be sent afterwards, because " +
			"afterwards there is no address to send it to")
	}
	return &MailConfirmation{notifier: notifier}, nil
}

// SendErasureComplete tells the person their account is gone, and what survives.
//
// Transactional, and it carries no OrgID: by this point the account is being
// erased and its organization membership is not what the message is about.
//
// # The exemptions are template DATA, and they arrive structured
//
// The list and the reasons live in one place — the retention schedule the
// erasure resolved them from — instead of being duplicated across every locale's
// wording. What changed when the schedule became data is that each entry now
// carries its period and its ARTICLE separately, so the template renders a legal
// basis as a legal basis rather than as part of a sentence somebody wrote.
//
// compliance.md §7 asks for exactly that: the DSAR response says what is
// retained and why, "rather than implying total deletion". A translator working
// from a `[]string` could not have produced the "why" in their own language,
// because it was inside the English sentence.
func (m *MailConfirmation) SendErasureComplete(
	ctx context.Context, subjectID string, retained []domain.RetentionPolicy,
) error {
	if subjectID == "" {
		return fmt.Errorf("compliance: an erasure confirmation needs a subject")
	}
	if len(retained) == 0 {
		// Refused rather than sent with an empty list. A confirmation that
		// listed nothing would imply total deletion, and compliance.md §7 is
		// explicit that implying total deletion when tax records survive is a
		// misleading statement about processing.
		return fmt.Errorf("compliance: an erasure confirmation must state what is retained")
	}
	return m.notifier.Dispatch(ctx, notify.Notification{
		Template:  ConfirmationTemplate,
		Class:     notify.Transactional,
		Recipient: notify.Recipient{SubjectID: subjectID},
		Data:      map[string]any{"Retained": retainedForTemplate(retained)},
	})
}

// retainedForTemplate flattens the policies into what a template ranges over.
//
// A map per entry rather than the domain type itself, and the reason is the same
// one that keeps proto out of `domain`: a template is a wire format. Handing it
// the aggregate's own type would make every future field of RetentionPolicy —
// an internal note, a jurisdiction filter, a review date — reachable from a
// `.tmpl` file that nobody reviews as code, and the first one that should not
// reach a data subject would reach them.
//
// So the four fields a person is entitled to read are named here, once.
func retainedForTemplate(retained []domain.RetentionPolicy) []map[string]string {
	out := make([]map[string]string, 0, len(retained))
	for _, p := range retained {
		out = append(out, map[string]string{
			"DataClass":  string(p.Class),
			"Period":     p.Period,
			"LegalBasis": p.LegalBasis,
			"Reason":     p.Reason,
		})
	}
	return out
}
