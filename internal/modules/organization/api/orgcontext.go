package api

import (
	"context"
	"errors"
	"fmt"

	orgpg "github.com/chronos/chronos-go/internal/modules/organization/adapter/postgres"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

// OrgHeader is how a request names which organization it is acting in.
const OrgHeader = "X-Chronos-Org"

// Memberships is what the resolver verifies against.
type Memberships interface {
	RoleIn(ctx context.Context, orgID, subjectID string) (string, error)
	OrgsFor(ctx context.Context, subjectID string) ([]string, error)
}

// OrgResolver is gate 1: which organization is this request in.
type OrgResolver struct{ members Memberships }

var _ interceptor.OrgResolver = (*OrgResolver)(nil)

func NewOrgResolver(members Memberships) (*OrgResolver, error) {
	if members == nil {
		return nil, fmt.Errorf("organization: a membership source is required; gate 1 must " +
			"VERIFY the organization a request names, not trust it")
	}
	return &OrgResolver{members: members}, nil
}

// Resolve attaches the tenant scope every later gate and query depends on.
//
// # The header is a CLAIM, never an answer
//
// A request names an organization and this verifies the caller belongs to it.
// Trusting the header would make the tenant boundary a client-supplied string —
// every RLS predicate in the system reads `app.org_id`, so a forged header would
// be a cross-tenant read with no other control in its way.
//
// # An unnamed organization resolves only when it is unambiguous
//
// With exactly one membership there is nothing to guess, and requiring a header
// would be ceremony. With several, the request has to say which: picking one
// would silently act in the wrong tenant, and that is worse than an error.
//
// # Both failures answer NOT_FOUND
//
// "No such organization" and "not yours" are the same answer, deliberately.
// Distinguishing them turns this into an existence oracle: anybody could
// enumerate organization ids by watching which ones came back as forbidden
// rather than missing (ADR-036).
func (r *OrgResolver) Resolve(
	ctx context.Context, p interceptor.Principal, header interceptor.Header,
) (context.Context, error) {
	subject := p.Subject.ID
	if subject == "" {
		return ctx, errs.Unauthenticatedf("this request has not authenticated")
	}

	orgID := header.Get(OrgHeader)
	if orgID == "" {
		orgs, err := r.members.OrgsFor(ctx, subject)
		if err != nil {
			return ctx, errs.Internalf("resolving the caller's organizations").Wrap(err)
		}
		switch len(orgs) {
		case 0:
			return ctx, errs.NotFoundf("not found")
		case 1:
			orgID = orgs[0]
		default:
			return ctx, errs.ValidationFailedf(
				"this request did not name an organization and you belong to %d; set the %s "+
					"header", len(orgs), OrgHeader)
		}
	}

	// The role is read only to PROVE membership, and deliberately discarded.
	// Gate 2 asks OpenFGA what the caller may do; the graph is the authority and
	// a projection is not (access.md §7). Carrying the role forward from here
	// would invite a later handler to trust it, which is the "never authorize
	// from a projection" rule broken by convenience.
	if _, err := r.members.RoleIn(ctx, orgID, subject); err != nil {
		if errors.Is(err, orgpg.ErrNotAMember) {
			return ctx, errs.NotFoundf("not found")
		}
		return ctx, errs.Internalf("verifying membership").Wrap(err)
	}

	// The scope every later gate, every handler and every RLS predicate reads.
	// UserID as well as OrgID, because `SET LOCAL app.user_id` is part of the
	// same tenant context (ADR-011) and a query scoped to an organization but
	// not a user is one row-level security cannot narrow.
	return db.WithTenant(ctx, db.Tenant{
		OrgID:  orgID,
		UserID: subject,
	}), nil
}
