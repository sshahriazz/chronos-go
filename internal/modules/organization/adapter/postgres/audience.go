package postgres

import (
	"context"
	"fmt"

	organizationdb "github.com/chronos/chronos-go/gen/sqlc/organization"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

// MaxOrgAudience is how many members one notification may fan out to.
//
// A REFUSAL rather than a page, and the difference is the whole point. A
// notification that reaches the first N members and silently omits the rest is
// worse than one that fails loudly: the omission is invisible from every side —
// the sender saw a success, and the people who were left out have nothing to
// notice. So hitting the cap parks the event for somebody to look at.
//
// 5000 is far above any organization this system is built for and far below the
// number at which one event becomes an unbounded fan-out.
const MaxOrgAudience = 5000

// MemberAudience answers "everyone in this organization" from
// `org_member_index`.
//
// # The first audience that needs a read model
//
// notify.SubjectAudiences answers the roles derivable from the event alone —
// subject, actor, operator — and REFUSES the organization roles rather than
// guessing at them. This is what replaces the refusal, and it lives in the
// organization module because that is where `org_member_index` is read
// (its writer is workspace's projection; CONVENTIONS §8, ADR-020).
type MemberAudience struct{ system db.SystemTX }

var _ notify.Audiences = (*MemberAudience)(nil)

func NewMemberAudience(system db.SystemTX) (*MemberAudience, error) {
	if system == nil {
		return nil, fmt.Errorf("organization: a system transaction source is required")
	}
	return &MemberAudience{system: system}, nil
}

// Resolve returns every member of the event's organization.
//
// # A SYSTEM transaction, and why that is not a shortcut
//
// This runs in a REACTOR: there is no request, no gate 1, and therefore no
// `app.org_id` to set — a tenant transaction would match nothing, which would
// look exactly like "this organization has no members" and silently notify
// nobody. The isolation the row security policy would give is supplied instead
// by the WHERE clause, and the organization id comes from the envelope of an
// event that was appended to that organization's own stream.
func (m *MemberAudience) Resolve(
	ctx context.Context, a notify.Audience, env eventsourcing.Envelope,
) ([]notify.Recipient, error) {
	if a != notify.AudienceOrgMembers {
		// Registered for one audience and asked for another. Refused rather
		// than answered, because answering would make every audience this
		// resolver was not written for silently resolve to "every member of the
		// organization" — which is the widest possible wrong answer.
		return nil, fmt.Errorf("%w: %s is not %s",
			notify.ErrAudienceUnsupported, a, notify.AudienceOrgMembers)
	}
	if env.Meta.OrgID == "" {
		return nil, fmt.Errorf("%w: the event records no organization, so its members "+
			"cannot be resolved", notify.ErrAudienceUnsupported)
	}

	var out []notify.Recipient
	err := m.system.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		// One MORE than the cap, so "did this hit the limit" is answered by the
		// query rather than guessed from a full result.
		rows, err := q.Query(ctx, organizationdb.OrgMemberSubjects,
			env.Meta.OrgID, int32(MaxOrgAudience+1))
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var subjectID, role string
			if err := rows.Scan(&subjectID, &role); err != nil {
				return err
			}
			out = append(out, notify.Recipient{SubjectID: subjectID, OrgID: env.Meta.OrgID})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("organization: resolving the members of %s: %w",
			env.Meta.OrgID, err)
	}

	if len(out) > MaxOrgAudience {
		return nil, fmt.Errorf("%w: organization %s has more than %d members; refusing to "+
			"send a partial fan-out, because the members left out have no way to notice",
			notify.ErrAudienceUnsupported, env.Meta.OrgID, MaxOrgAudience)
	}
	return out, nil
}
