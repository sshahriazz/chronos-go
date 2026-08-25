package domain

import (
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// FederatedClaim is the uniqueness mechanism for one provider identity.
//
// One aggregate per (issuer, subject), on a stream named from the pair. That
// naming is the entire design, and it is `EmailReservation`'s (ADR-044): two
// accounts linking one Google identity contend on the SAME STREAM, so the
// expected-revision check refuses one of them. Uniqueness holds at the moment of
// the write.
//
// identity.md §7 rule 4. The alternative — check a projection, then write —
// fails in the way that is hardest to notice: the projection is behind the log
// by construction, so under concurrency both reads say "free", both succeed, and
// one provider identity signs into two accounts.
type FederatedClaim struct {
	eventsourcing.Base

	issuer    contract.Issuer
	subject   string
	subjectID string
	held      bool
}

// NewFederatedClaim builds an empty aggregate for the repository.
func NewFederatedClaim() *FederatedClaim { return &FederatedClaim{} }

func (c *FederatedClaim) Held() bool        { return c.held }
func (c *FederatedClaim) SubjectID() string { return c.subjectID }

// Apply is the pure transition.
func (c *FederatedClaim) Apply(e eventsourcing.Event) {
	switch ev := e.(type) {
	case *contract.FederatedIdentityClaimed:
		c.issuer, c.subject = ev.Issuer, ev.ProviderSubject
		c.subjectID, c.held = ev.SubjectID, true

	case *contract.FederatedIdentityReleased:
		c.subjectID, c.held = "", false
	}
}

// Claim records that this provider identity belongs to a subject.
//
// Idempotent for the SAME subject: a retried callback must not fail. Refused for
// every OTHER subject, which is rule 4 — and the refusal is what a second
// account linking the same Google identity gets.
func (c *FederatedClaim) Claim(
	issuer contract.Issuer, subject, subjectID string, at time.Time,
) error {
	switch {
	case issuer == "":
		return errs.ValidationFailedf("an issuer is required")
	case subject == "":
		return errs.ValidationFailedf("a provider subject is required")
	case subjectID == "":
		return errs.ValidationFailedf("a subject id is required")
	case c.held && c.issuer != "" && (c.issuer != issuer || c.subject != subject):
		// The stream is named from the pair, so this cannot happen through the
		// repository — but it can through a hand-built aggregate, and silently
		// overwriting would move a claim between two identities.
		return errs.Internalf("this claim is for a different provider identity")
	}

	if c.held {
		if c.subjectID == subjectID {
			return nil // already ours
		}
		// ANOTHER ACCOUNT HOLDS IT. Deliberately the same message whoever asks:
		// telling a caller that a provider identity is already linked elsewhere
		// says that some account here is associated with that Google login,
		// which is an account-existence oracle keyed on a third party.
		return errs.Conflictf("this account could not be linked")
	}

	eventsourcing.Record(c, &contract.FederatedIdentityClaimed{
		Issuer:          issuer,
		ProviderSubject: subject,
		SubjectID:       subjectID,
		ClaimedAt:       at.UTC(),
	})
	return nil
}

// Release frees the identity to be claimed again.
//
// Without it a provider identity would be held forever by an account that
// removed the link — or was erased — and the same person could never re-link the
// same provider.
func (c *FederatedClaim) Release(subjectID, reason string, at time.Time) error {
	if !c.held {
		return nil // already free; releasing twice is not an error
	}
	if c.subjectID != subjectID {
		return errs.Conflictf("this provider identity is linked to another account")
	}
	switch reason {
	case contract.UnlinkByHolder, contract.UnlinkPasswordReset, contract.UnlinkErased:
	default:
		return errs.ValidationFailedf("a release must state a known reason")
	}

	eventsourcing.Record(c, &contract.FederatedIdentityReleased{
		Issuer:          c.issuer,
		ProviderSubject: c.subject,
		SubjectID:       subjectID,
		Reason:          reason,
		ReleasedAt:      at.UTC(),
	})
	return nil
}
