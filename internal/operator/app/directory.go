package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

// DefaultPageSize and MaxPageSize bound the directory.
//
// The ceiling matters more than the default. This endpoint reads across every
// tenant we have, so an unbounded page is a bulk export of the customer base —
// which operator.md §2 lists as explicitly out of scope. A hundred is a screen
// of results, and an operator who needs more pages.
const (
	DefaultPageSize = 25
	MaxPageSize     = 100
)

// Directory reads the customer directory, auditing every read.
type Customers struct {
	dir     Directory
	vault   VaultReader
	auditor *Auditor
	log     *slog.Logger
}

// NewCustomers builds the use case.
func NewCustomers(dir Directory, vault VaultReader, auditor *Auditor, log *slog.Logger) (*Customers, error) {
	switch {
	case dir == nil:
		return nil, errors.New("operator: the directory needs a read model")
	case vault == nil:
		return nil, errors.New("operator: the directory needs a vault reader")
	case auditor == nil:
		return nil, errors.New("operator: the directory needs an auditor")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Customers{dir: dir, vault: vault, auditor: auditor, log: log}, nil
}

// List pages the directory.
//
// # The audit is written BEFORE the read, on every path
//
// Not after, and not only on success. operator.md §5's rule is that looking is
// processing, and an operator who ran a search that then failed still ran the
// search — the query itself is the thing the tenant is entitled to know about.
// Auditing after a successful read would silently omit exactly the accesses
// somebody investigating an incident cares most about.
//
// A failure to audit fails the call. That ordering is what makes the audit log
// complete rather than best-effort.
func (c *Customers) List(
	ctx context.Context, actor Actor, method, query, lifecycleState, pageToken string, pageSize int32,
) (CustomerPage, error) {
	if _, err := c.auditor.RecordView(ctx, actor, method, ""); err != nil {
		return CustomerPage{}, fmt.Errorf("recording the read: %w", err)
	}

	limit := pageSize
	switch {
	case limit <= 0:
		limit = DefaultPageSize
	case limit > MaxPageSize:
		limit = MaxPageSize
	}

	page, err := c.dir.List(ctx, query, lifecycleState, pageToken, limit)
	if err != nil {
		return CustomerPage{}, fmt.Errorf("reading the directory: %w", err)
	}
	return page, nil
}

// Get reads one organization's record.
func (c *Customers) Get(ctx context.Context, actor Actor, method, orgID string) (Customer, error) {
	// Audited with the ORG NAMED, unlike List: a drill-in is an access to one
	// tenant's record, and that tenant's own history should show it.
	//
	// Recorded before the row is read, so a request for a customer that does
	// not exist is audited too. That is deliberate: enumerating org ids to see
	// which exist is a reconnaissance pattern, and it is invisible in a log
	// that only records successful reads.
	if _, err := c.auditor.RecordView(ctx, actor, method, orgID); err != nil {
		return Customer{}, fmt.Errorf("recording the read: %w", err)
	}

	cust, err := c.dir.Get(ctx, orgID)
	switch {
	case errors.Is(err, ErrNoSuchCustomer):
		return Customer{}, ErrNoSuchCustomer
	case err != nil:
		return Customer{}, fmt.Errorf("reading the customer: %w", err)
	}
	return cust, nil
}

// RevealResult is one subject's resolved fields, and the entry that recorded
// the access.
type RevealResult struct {
	Fields       map[string]string
	AuditEntryID string
}

// Reveal resolves one subject's vault fields, with a recorded justification.
//
// # The order is the security property
//
//	audit → vault → answer
//
// The audit entry is appended FIRST and a failure to append fails the call, so
// there is no reachable state in which personal data was disclosed and the
// disclosure was not recorded. Reversing the two would make "the audit write
// failed after we returned the address" an ordinary consequence of a database
// hiccup, and it is the one failure this endpoint must not have.
//
// The justification is enforced three times over and that is not redundancy for
// its own sake: protovalidate refuses an empty or trivial one at the edge with
// a useful message, the audit aggregate refuses to RECORD one without it, and
// the database's own CHECK constraint refuses to store the row. Each layer
// catches a different mistake — a client bug, a second caller added later, and
// a projector bug respectively.
func (c *Customers) Reveal(
	ctx context.Context, actor Actor, method, subjectID, orgID string,
	fields []string, reason string,
) (RevealResult, error) {
	entryID, err := c.auditor.RecordPersonalDataView(ctx, actor, method, subjectID, orgID, fields, reason)
	if err != nil {
		return RevealResult{}, fmt.Errorf("recording the access: %w", err)
	}

	resolved, err := c.vault.Resolve(ctx, subjectID, fields)
	if err != nil {
		// The access is already recorded and stays recorded. An audit entry for
		// an attempt that failed is correct: the operator asked, which is the
		// fact the trail exists to hold.
		c.log.WarnContext(ctx, "an operator personal-data read could not be resolved",
			"operator_id", actor.OperatorID, "audit_entry_id", entryID, "error", err)
		return RevealResult{}, fmt.Errorf("resolving the subject: %w", err)
	}

	return RevealResult{Fields: resolved, AuditEntryID: entryID}, nil
}
