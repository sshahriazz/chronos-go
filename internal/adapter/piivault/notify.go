package piivault

import (
	"context"
	"errors"
	"fmt"

	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// NotifyVault resolves a pseudonym to contact details for the notification
// system.
//
// The single point at which personal data enters the outbound path. Everything
// upstream — the event, the catalogue, the dispatcher — has carried only a
// SubjectID, and this is where it becomes a name and an address, at the last
// possible moment (NOTIFICATIONS §4).
type NotifyVault struct {
	vault    pii.Vault
	locale   string
	timezone string
}

var _ notify.Vault = (*NotifyVault)(nil)

// NewNotifyVault adapts the PII vault. The defaults apply when a subject has no
// locale or timezone recorded — a person who never chose one still gets mail.
func NewNotifyVault(v pii.Vault, defaultLocale, defaultTimezone string) *NotifyVault {
	if defaultLocale == "" {
		defaultLocale = "en"
	}
	if defaultTimezone == "" {
		defaultTimezone = "UTC"
	}
	return &NotifyVault{vault: v, locale: defaultLocale, timezone: defaultTimezone}
}

// Resolve returns the recipient's contact details.
//
// An erased subject is reported as notify.ErrSubjectErased, which the dispatcher
// treats as a correct outcome rather than a failure: someone who exercised
// erasure has no address, and retrying cannot conjure one (NOTIFICATIONS §4).
func (n *NotifyVault) Resolve(ctx context.Context, subjectID string) (notify.Recipient, error) {
	profile, err := n.vault.Profile(ctx, pii.SubjectID(subjectID))
	switch {
	case errors.Is(err, pii.ErrErased):
		return notify.Recipient{}, fmt.Errorf("%w: %s", notify.ErrSubjectErased, subjectID)
	case errors.Is(err, pii.ErrNoSubject):
		// No record at all. Distinct from erased: nobody asked to be forgotten,
		// the subject simply is not there — which is a data fault worth seeing
		// rather than a silent skip.
		return notify.Recipient{}, fmt.Errorf("%w: %s", notify.ErrNoAddress, subjectID)
	case err != nil:
		// The vault may be unreachable. Retryable, and deliberately NOT
		// reported as "no address": guessing that would skip a security alert.
		return notify.Recipient{}, fmt.Errorf("resolving subject %s: %w", subjectID, err)
	}

	address := profile.Get(pii.FieldEmail)
	if address == "" {
		return notify.Recipient{}, fmt.Errorf("%w: %s has no email address",
			notify.ErrNoAddress, subjectID)
	}

	r := notify.Recipient{
		SubjectID: subjectID,
		Address:   address,
		Name:      profile.Get(pii.FieldName),
		Locale:    profile.Get(pii.FieldLocale),
		Timezone:  profile.Get(pii.FieldTimezone),
	}
	if r.Locale == "" {
		r.Locale = n.locale
	}
	if r.Timezone == "" {
		r.Timezone = n.timezone
	}
	return r, nil
}
