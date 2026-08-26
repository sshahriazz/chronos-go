package app

import (
	"context"
	"time"

	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/page"
)

// ---------------------------------------------------------------------------
// The read side
// ---------------------------------------------------------------------------

// ServiceAccountSummary is one non-human principal, as a management screen shows
// it.
type ServiceAccountSummary struct {
	ID   ids.ServiceAccountID
	Name string

	// CreatedBy is the pseudonym of the admin who created it. Rendered by
	// resolving it against the vault at read time, like every other pseudonym in
	// this system — the projection holds the pseudonym and never a name
	// (compliance.md §1).
	CreatedBy string

	CreatedAt time.Time
}

// APIKeySummary is one key, as a management screen shows it.
//
// There is no field here that could hold a secret, and that is structural rather
// than a convention this type happens to follow: the statement behind it selects
// no digest column, so there is nothing for a future field to be populated from.
type APIKeySummary struct {
	ID ids.APIKeyID

	// OwnerKind and OwnerID are the tagged pair. Strings rather than
	// domain.APIKeyOwner because this is a read model: a row written by an older
	// build carrying a kind this one does not recognise must be DISPLAYABLE, and
	// a typed value would have to refuse it and take the whole page down with it.
	OwnerKind string
	OwnerID   string

	Scopes    []string
	ExpiresAt time.Time

	// RevokedAt, RotatedAt and LastUsedAt are zero when they have not happened.
	// The zero time rather than a pointer, because every consumer renders
	// "never" for an absent value and IsZero cannot be dereferenced by mistake.
	RevokedAt  time.Time
	RotatedAt  time.Time
	LastUsedAt time.Time

	CreatedBy string
	CreatedAt time.Time
}

// APIKeyDirectory is the read side of identity.md §14's `api_key_view`, plus the
// service account roster.
//
// Declared by the consumer and READ-ONLY, like every other port `Queries` holds:
// these tables are written by the projector from the event log, and a query
// handler that could write one would put state in PostgreSQL that no replay
// could reproduce — which the next rebuild would then delete (ADR-019).
//
// Neither method takes an organization. It comes from the tenant scope gate 1
// established, and row-level security applies it; a method that took an org id
// would be a second tenant filter that can disagree with the policy, and the
// dangerous direction is the one where somebody removes the policy and the query
// still appears to work.
type APIKeyDirectory interface {
	Keys(ctx context.Context, cursor page.Keyset, limit int32) ([]APIKeySummary, error)
	ServiceAccounts(
		ctx context.Context, cursor page.Keyset, limit int32,
	) ([]ServiceAccountSummary, error)
}

// Sort columns for the two org-scoped lists, and the query ids that bind a
// cursor to one of them.
//
// Both lists are (created_at DESC, id DESC) over the same tenant, so a token
// minted for one would DECODE against the other — the columns would even match
// in arity and type. The query id is what makes it fail instead: a service
// account cursor presented to the key list is a decode failure rather than a
// position in a list it was never taken from.
var (
	apiKeySortColumns         = []string{"created_at", "key_id"}
	serviceAccountSortColumns = []string{"created_at", "service_account_id"}
)

func apiKeysQueryID(orgID string) page.QueryID {
	return page.QueryID("identity.api_keys:org=" + orgID + ":created_at desc,key_id desc")
}

func serviceAccountsQueryID(orgID string) page.QueryID {
	return page.QueryID("identity.service_accounts:org=" + orgID +
		":created_at desc,service_account_id desc")
}

func apiKeyCursor(k APIKeySummary) page.Keyset {
	ks, err := page.NewKeyset(
		page.Key{Column: apiKeySortColumns[0], Value: k.CreatedAt.UTC()},
		page.Key{Column: apiKeySortColumns[1], Value: k.ID.String(), Unique: true},
	)
	if err != nil {
		// Swallowed into a zero Keyset for the reason sessionCursor gives:
		// page.Of takes no error, and a zero Keyset is not silently harmless —
		// Encode refuses to write a token for the start position, so the failure
		// surfaces as an error from the page builder rather than as a token that
		// restarts the list.
		return page.Keyset{}
	}
	return ks
}

func serviceAccountCursor(s ServiceAccountSummary) page.Keyset {
	ks, err := page.NewKeyset(
		page.Key{Column: serviceAccountSortColumns[0], Value: s.CreatedAt.UTC()},
		page.Key{Column: serviceAccountSortColumns[1], Value: s.ID.String(), Unique: true},
	)
	if err != nil {
		return page.Keyset{}
	}
	return ks
}

// ListAPIKeys returns one page of the tenant's keys, newest first.
//
// The organization is a parameter only because the cursor is BOUND to it — the
// rows themselves are filtered by row-level security, from the scope gate 1
// established. Binding the org into the query id means a page token minted in
// one tenant is a decode failure in another rather than a position in a list it
// was never taken from, and the two controls then fail independently.
func (q *Queries) ListAPIKeys(
	ctx context.Context, orgID string, pageToken page.Token, pageSizeRequested int,
) (page.Page[APIKeySummary], error) {
	if orgID == "" {
		return page.Page[APIKeySummary]{}, errs.Internalf(
			"no organization in scope for an API key listing")
	}
	size, err := pageSize(pageSizeRequested)
	if err != nil {
		return page.Page[APIKeySummary]{}, err
	}
	queryID := apiKeysQueryID(orgID)
	cursor, err := resumeAt(pageToken, queryID, apiKeySortColumns)
	if err != nil {
		return page.Page[APIKeySummary]{}, err
	}

	// Limit(), not size: one extra row is asked for and page.Of trims it, which
	// is how "is there another page" is answered without a COUNT(*) whose answer
	// was true a moment ago.
	rows, err := q.keys.Keys(ctx, cursor, size.Limit())
	if err != nil {
		return page.Page[APIKeySummary]{}, errs.Internalf("listing API keys").Wrap(err)
	}
	out, err := page.Of(rows, size, queryID, apiKeyCursor)
	if err != nil {
		return page.Page[APIKeySummary]{}, errs.Internalf("building an API key page token").Wrap(err)
	}
	return out, nil
}

// ListServiceAccounts returns one page of the tenant's non-human principals,
// newest first. See ListAPIKeys for why the organization is a parameter.
func (q *Queries) ListServiceAccounts(
	ctx context.Context, orgID string, pageToken page.Token, pageSizeRequested int,
) (page.Page[ServiceAccountSummary], error) {
	if orgID == "" {
		return page.Page[ServiceAccountSummary]{}, errs.Internalf(
			"no organization in scope for a service account listing")
	}
	size, err := pageSize(pageSizeRequested)
	if err != nil {
		return page.Page[ServiceAccountSummary]{}, err
	}
	queryID := serviceAccountsQueryID(orgID)
	cursor, err := resumeAt(pageToken, queryID, serviceAccountSortColumns)
	if err != nil {
		return page.Page[ServiceAccountSummary]{}, err
	}

	rows, err := q.keys.ServiceAccounts(ctx, cursor, size.Limit())
	if err != nil {
		return page.Page[ServiceAccountSummary]{}, errs.Internalf("listing service accounts").Wrap(err)
	}
	out, err := page.Of(rows, size, queryID, serviceAccountCursor)
	if err != nil {
		return page.Page[ServiceAccountSummary]{}, errs.Internalf(
			"building a service account page token").Wrap(err)
	}
	return out, nil
}
