package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	operatordb "github.com/chronos/chronos-go/gen/sqlc/operator"
	"github.com/chronos/chronos-go/internal/operator/app"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// DirectoryStore reads operator_customer_list.
//
// A SEPARATE type from Store, and not only to avoid a method-name collision.
// The directory is the one store here that reads about TENANTS rather than
// about us, so it is the one whose surface a reviewer should be able to take in
// on its own — and keeping it apart means "what can the operator plane learn
// about a customer" is answered by one file.
type DirectoryStore struct{ tx db.SystemTX }

// NewDirectory builds the reader.
func NewDirectory(tx db.SystemTX) (*DirectoryStore, error) {
	if tx == nil {
		return nil, fmt.Errorf("operator postgres: the directory needs a transaction source")
	}
	return &DirectoryStore{tx: tx}, nil
}

var _ app.Directory = (*DirectoryStore)(nil)

// Get reads one organization's record.
func (s *DirectoryStore) Get(ctx context.Context, orgID string) (app.Customer, error) {
	var c app.Customer
	err := s.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		return scanCustomer(q.QueryRow(ctx, operatordb.GetCustomer, orgID), &c)
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return app.Customer{}, app.ErrNoSuchCustomer
	case err != nil:
		return app.Customer{}, fmt.Errorf("operator postgres: reading a customer: %w", err)
	}
	return c, nil
}

// List pages the directory.
//
// One row is fetched BEYOND the requested limit, and dropped. That is how the
// "is there a next page" question is answered without a second COUNT over a
// table that spans every tenant we have — and without the lie a cursor returned
// on the last page would be.
func (s *DirectoryStore) List(
	ctx context.Context, query, lifecycleState, pageToken string, limit int32,
) (app.CustomerPage, error) {
	cursorAt, cursorID, err := decodeCursor(pageToken)
	if err != nil {
		// A malformed cursor is the caller's, so it is refused rather than
		// silently treated as "start from the beginning" — which would hand
		// somebody page one when they asked for page nine and look like data
		// loss.
		return app.CustomerPage{}, err
	}

	var (
		qArg  *string
		stArg *string
		cAt   *time.Time
		cID   *string
	)
	if q := strings.TrimSpace(query); q != "" {
		escaped := escapeLike(q)
		qArg = &escaped
	}
	if lifecycleState != "" {
		stArg = &lifecycleState
	}
	if cursorID != "" {
		cAt = &cursorAt
		cID = &cursorID
	}

	out := make([]app.Customer, 0, limit)
	err = s.tx.InSystemTx(ctx, func(ctx context.Context, qr db.Querier) error {
		rows, err := qr.Query(ctx, operatordb.ListCustomers, qArg, stArg, cAt, cID, int32(limit)+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c app.Customer
			if err := scanCustomer(rows, &c); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return app.CustomerPage{}, fmt.Errorf("operator postgres: listing customers: %w", err)
	}

	page := app.CustomerPage{Customers: out}
	// len(out) is at most limit+1 by construction — the query's LIMIT — so this
	// comparison is on a value bounded by MaxPageSize, not by anything the
	// database could return unbounded.
	if len(out) > int(limit) {
		last := out[limit-1]
		page.Customers = out[:limit]
		page.NextPageToken = encodeCursor(last.CreatedAt, last.OrgID)
	}
	return page, nil
}

func scanCustomer(row scanner, c *app.Customer) error {
	var (
		planID, planVersionID, subStatus, signupSource, suspensionReason *string
		trialEndsAt, lastActiveAt, suspendedAt                           *time.Time
	)
	if err := row.Scan(&c.OrgID, &c.Slug, &c.OrgName, &c.LifecycleState,
		&planID, &planVersionID, &subStatus, &trialEndsAt,
		&c.WorkspaceCount, &c.MemberCount, &lastActiveAt, &signupSource,
		&suspendedAt, &suspensionReason, &c.CreatedAt); err != nil {
		return err
	}
	c.PlanID = deref(planID)
	c.PlanVersionID = deref(planVersionID)
	c.SubscriptionStatus = deref(subStatus)
	c.SignupSource = deref(signupSource)
	c.SuspensionReason = deref(suspensionReason)
	c.TrialEndsAt = trialEndsAt
	c.LastActiveAt = lastActiveAt
	c.SuspendedAt = suspendedAt
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// escapeLike neutralises the wildcards in a search term.
//
// Without it, an operator typing `%` matches every customer we have, which is
// the bulk listing operator.md §2 excludes — reached by accident, through a
// search box. `\` is escaped first, or escaping the others would double-escape
// it.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}

// The cursor is (created_at, org_id), base64url over a fixed separator.
//
// Keyset rather than OFFSET, because an OFFSET page boundary shifts when a new
// organization signs up mid-listing — which silently SKIPS a customer, and the
// operator has no way to tell.
const cursorSep = "\x00"

func encodeCursor(at time.Time, orgID string) string {
	raw := at.UTC().Format(time.RFC3339Nano) + cursorSep + orgID
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeCursor(token string) (time.Time, string, error) {
	if token == "" {
		return time.Time{}, "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("operator: this page token is not readable")
	}
	parts := strings.SplitN(string(raw), cursorSep, 2)
	if len(parts) != 2 {
		return time.Time{}, "", fmt.Errorf("operator: this page token is not readable")
	}
	at, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, "", fmt.Errorf("operator: this page token is not readable")
	}
	return at, parts[1], nil
}
