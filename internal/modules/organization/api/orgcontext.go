package api

import (
	"context"
	"errors"
	"fmt"

	orgpg "github.com/chronos/chronos-go/internal/modules/organization/adapter/postgres"
	"github.com/chronos/chronos-go/internal/platform/authz"
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
	// The principal the MEMBERSHIP question is about.
	//
	// For a session the two are the same value. For a machine credential the
	// subject is the key and the acting principal is its owner — and membership
	// is a fact about the owner, because a key has no membership of its own and
	// never will: identity.md §10 revokes a key when its owner loses the
	// organization, which is only expressible if the owner is who gets checked.
	acting := p.Subject.Acting()
	subject := acting.ID
	if subject == "" {
		return ctx, errs.Unauthenticatedf("this request has not authenticated")
	}

	// A machine credential names its own organization, IMMUTABLY, chosen when it
	// was minted (identity.md §10, review D2). So there is nothing for this gate
	// to resolve and everything for it to enforce.
	//
	// The header is still read, and a header naming a DIFFERENT organization is
	// refused rather than ignored. Ignoring it would mean a client that believed
	// it was acting in org B, and was told nothing, silently acted in org A —
	// which is the same class of failure as honouring the header, arrived at from
	// the other direction. Refusing makes the disagreement visible on the first
	// request.
	//
	// The refusal is NOT_FOUND, like every other failure here, so a caller cannot
	// use it to discover which organization a key they hold is bound to by
	// probing headers until one stops failing.
	if p.BoundOrg != "" {
		if named := header.Get(OrgHeader); named != "" && named != p.BoundOrg {
			return ctx, errs.NotFoundf("not found")
		}
		return r.scopeFor(ctx, p.BoundOrg, acting, subject)
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

	return r.scopeFor(ctx, orgID, acting, subject)
}

// scopeFor verifies the principal belongs in the organization and attaches the
// tenant scope.
//
// # A service account is NOT checked for membership, and that is not a hole
//
// `org_member_index` records PEOPLE. A service account is owned by the
// organization rather than a member of it, so `RoleIn` would answer "not a
// member" for every one of them and every service-account key in the system
// would be refused here — which reads as a permission bug and is really a
// category error.
//
// What replaces the check is stronger, not weaker: the key's organization
// binding is IMMUTABLE and was written when the key was minted, the service
// account's own organization is immutable too, and the key-issuing command
// refuses an owner that is not visible in the caller's tenant — a check
// row-level security answers, so a service account in another organization is
// indistinguishable there from one that does not exist. The binding is
// established once, by an admin who passed every gate at AAL2, rather than
// re-derived from a projection on each request.
//
// A USER-owned key IS checked, and the check is load-bearing: identity.md §10
// requires a key to be revoked when its owner loses membership of the bound
// organization, and names a reactor on `MemberRemoved` as the mechanism. That
// reactor is not built. This check closes the same window SYNCHRONOUSLY and does
// not depend on it — an ex-member's personal access token stops working at the
// next request rather than when a reactor catches up — so building the reactor
// later removes the row, and this removes the access.
func (r *OrgResolver) scopeFor(
	ctx context.Context, orgID string, acting authz.Principal, subject string,
) (context.Context, error) {
	if acting.Kind != authz.KindServiceAccount {
		// The role is read only to PROVE membership, and deliberately discarded.
		// Gate 2 asks OpenFGA what the caller may do; the graph is the authority
		// and a projection is not (access.md §7). Carrying the role forward from
		// here would invite a later handler to trust it, which is the "never
		// authorize from a projection" rule broken by convenience.
		if _, err := r.members.RoleIn(ctx, orgID, subject); err != nil {
			if errors.Is(err, orgpg.ErrNotAMember) {
				return ctx, errs.NotFoundf("not found")
			}
			return ctx, errs.Internalf("verifying membership").Wrap(err)
		}
	}

	// The scope every later gate, every handler and every RLS predicate reads.
	// UserID as well as OrgID, because `SET LOCAL app.user_id` is part of the
	// same tenant context (ADR-011) and a query scoped to an organization but
	// not a user is one row-level security cannot narrow.
	//
	// The UserID is the ACTING principal — the key's owner, not the key — because
	// that is the identifier every RLS predicate keyed on a person compares
	// against, and a service account's `svc_` id in that slot would match no row
	// rather than matching the wrong one.
	return db.WithTenant(ctx, db.Tenant{
		OrgID:  orgID,
		UserID: subject,
	}), nil
}
