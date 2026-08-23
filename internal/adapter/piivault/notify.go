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
//
// `which` is where the platform's address choice becomes a vault field. It is
// mapped here rather than named in `notify` because `notify` does not import
// `pii`: the platform decides WHICH address in its own terms, and this is the
// only place that has to know what the vault calls it.
func (n *NotifyVault) Resolve(
	ctx context.Context, subjectID string, which notify.AddressChoice,
) (notify.Recipient, error) {
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

	field := pii.FieldEmail
	switch which {
	case notify.AddressPending:
		field = pii.FieldPendingEmail
	case notify.AddressPrevious:
		field = pii.FieldPreviousEmail
	}
	address := profile.Get(field)
	if address == "" {
		// NO FALLBACK to the primary, and the absence of one is the point.
		//
		// The only notification that asks for the previous address is the one
		// telling somebody their address was changed and offering the revert
		// (identity.md §12). Falling back would send it to the address it was
		// changed TO — the attacker's, in the attack the revert window exists to
		// defeat — and it would do so precisely when something has already gone
		// wrong. Failing is the safe direction: the notice is retried, and if it
		// never succeeds nobody is told anything false.
		return notify.Recipient{}, fmt.Errorf("%w: %s has no %s address",
			notify.ErrNoAddress, subjectID, which)
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
