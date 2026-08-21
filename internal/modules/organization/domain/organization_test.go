package domain_test

import (
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/organization/contract"
	"github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

var at = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

func created(t *testing.T) *domain.Organization {
	t.Helper()
	o := domain.NewOrganization()
	if err := o.Create("org_01ARZ3NDEKTSV4RRFFQ69G5FAV", "Acme", "acme", "sub_alice", at); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return o
}

func trialing(t *testing.T) *domain.Organization {
	t.Helper()
	o := created(t)
	if err := o.StartTrial("cus_1", "sub_1", at.AddDate(0, 0, 14), at); err != nil {
		t.Fatalf("StartTrial: %v", err)
	}
	return o
}

// EVERY transition, legal and illegal, driven through the real commands.
//
// # Why exhaustive rather than a handful of cases
//
// organization.md §13 asks for "the full lifecycle transition table, including
// every illegal transition". Status gates the entire tenant, so an illegal
// transition that is silently permitted is a tenant in a state the enforcement
// table has no column for — and gate 3 then answers a question nobody designed
// an answer to.
//
// The table below is the SPECIFICATION, written independently of
// domain.transitions. Deriving the expectation from the map under test would
// make both agree by construction and assert nothing.
func TestEveryLifecycleTransition(t *testing.T) {
	t.Parallel()

	legal := map[domain.Status]map[domain.Status]bool{
		domain.StatusProvisioning: {domain.StatusTrialing: true, domain.StatusClosed: true},
		domain.StatusTrialing: {
			domain.StatusActive: true, domain.StatusSuspended: true, domain.StatusClosed: true,
		},
		domain.StatusActive: {
			domain.StatusPastDue: true, domain.StatusSuspended: true, domain.StatusClosed: true,
		},
		domain.StatusPastDue: {
			domain.StatusActive: true, domain.StatusSuspended: true, domain.StatusClosed: true,
		},
		domain.StatusSuspended: {domain.StatusActive: true, domain.StatusClosed: true},
		domain.StatusClosed:    {},
	}

	for from, allowed := range legal {
		for _, to := range domain.Statuses() {
			if to == domain.StatusUnknown || to == domain.StatusProvisioning {
				continue // nothing transitions INTO these; creation produces them
			}
			name := from.String() + "->" + to.String()
			t.Run(name, func(t *testing.T) {
				o := at_(t, from)
				err := move(o, to)
				if allowed[to] {
					if err != nil {
						t.Errorf("%s is a legal transition and was refused: %v", name, err)
					}
					if o.Status() != to {
						t.Errorf("after %s the status is %s", name, o.Status())
					}
					return
				}
				if err == nil {
					t.Errorf("%s is ILLEGAL and was permitted; the tenant is now in a state "+
						"the enforcement table has no column for", name)
				}
				if o.Status() != from {
					t.Errorf("a refused transition still changed the status to %s", o.Status())
				}
			})
		}
	}
}

// at_ builds an organization sitting in the given status.
func at_(t *testing.T, s domain.Status) *domain.Organization {
	t.Helper()
	o := created(t)
	if s == domain.StatusProvisioning {
		return o
	}
	if err := o.StartTrial("cus_1", "sub_1", at.AddDate(0, 0, 14), at); err != nil {
		t.Fatalf("StartTrial: %v", err)
	}
	switch s {
	case domain.StatusTrialing:
	case domain.StatusActive:
		mustDo(t, o.Activate(at))
	case domain.StatusPastDue:
		mustDo(t, o.Activate(at))
		mustDo(t, o.MarkPastDue(at.AddDate(0, 0, 7), at))
	case domain.StatusSuspended:
		mustDo(t, o.Suspend(contract.TrialEnded, at))
	case domain.StatusClosed:
		mustDo(t, o.Close(at))
	default:
		t.Fatalf("no route to %s", s)
	}
	if o.Status() != s {
		t.Fatalf("fixture landed in %s, want %s", o.Status(), s)
	}
	return o
}

func move(o *domain.Organization, to domain.Status) error {
	switch to {
	case domain.StatusTrialing:
		return o.StartTrial("cus_2", "sub_2", at.AddDate(0, 0, 14), at)
	case domain.StatusActive:
		return o.Activate(at)
	case domain.StatusPastDue:
		return o.MarkPastDue(at.AddDate(0, 0, 7), at)
	case domain.StatusSuspended:
		return o.Suspend(contract.PaymentFailed, at)
	case domain.StatusClosed:
		return o.Close(at)
	}
	return nil
}

func mustDo(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("building the fixture: %v", err)
	}
}

// The zero value denies, like every other fail-closed type in this system.
func TestAnUnloadedOrganizationIsNotUsable(t *testing.T) {
	t.Parallel()

	o := domain.NewOrganization()
	if o.Status().Usable() {
		t.Error("an organization with no events loaded reports itself usable; a failed load " +
			"would then grant the tenant everything (ADR-010)")
	}
	if o.Exists() {
		t.Error("an empty aggregate reports that it exists")
	}
	if err := o.Activate(at); err == nil {
		t.Error("an organization that does not exist was activated")
	}
}

// The OWNER cannot be removed as an admin, and the error says what to do.
//
// ADR-027: exactly one owner, always — never zero, never two. The cardinality is
// the invariant; the person is transferable, but only through a transfer the
// recipient accepts. Losing the owner by way of an admin removal would leave an
// organization nobody can administer and nobody can pay for, and no event would
// look wrong.
func TestTheOwnerCannotBeRemovedAsAnAdmin(t *testing.T) {
	t.Parallel()

	o := trialing(t)
	if err := o.RemoveAdmin("sub_alice", at); err == nil {
		t.Fatal("the owner was removed as an admin; the organization now has no owner, and " +
			"nothing in the log looks wrong")
	} else if !contains(err.Error(), "Transfer ownership") {
		t.Errorf("the refusal does not say what to do instead: %v", err)
	}
	if o.OwnerID() != "sub_alice" || !o.IsAdmin("sub_alice") {
		t.Error("the refused removal changed the aggregate anyway")
	}
}

// Adding the owner as an admin is a no-op, not an event.
//
// If it recorded one, the owner would enter the admin SET — and RemoveAdmin
// would then strip their administration while leaving them owner, which is the
// same lost-owner outcome by a longer route.
func TestAddingTheOwnerAsAnAdminRecordsNothing(t *testing.T) {
	t.Parallel()

	o := trialing(t)
	before := len(o.Uncommitted())
	if err := o.AddAdmin("sub_alice", at); err != nil {
		t.Fatalf("AddAdmin(owner): %v", err)
	}
	if len(o.Uncommitted()) != before {
		t.Error("adding the owner as an admin recorded an event; the owner is now in the " +
			"admin set and can be removed from it")
	}
	if len(o.Admins()) != 0 {
		t.Errorf("the admin set holds %v; the owner administers by being the owner", o.Admins())
	}
}

func TestAdminsCanBeAddedAndRemoved(t *testing.T) {
	t.Parallel()

	o := trialing(t)
	mustDo(t, o.AddAdmin("sub_bob", at))
	if !o.IsAdmin("sub_bob") {
		t.Fatal("bob was added and does not administer")
	}
	// Idempotent: adding twice records one event.
	before := len(o.Uncommitted())
	mustDo(t, o.AddAdmin("sub_bob", at))
	if len(o.Uncommitted()) != before {
		t.Error("adding an existing admin recorded a second event")
	}

	mustDo(t, o.RemoveAdmin("sub_bob", at))
	if o.IsAdmin("sub_bob") {
		t.Error("bob was removed and still administers")
	}
}

// Admins() hands out a copy, so the invariant-bearing set cannot be edited from
// outside the aggregate.
func TestAdminsCannotBeMutatedThroughTheAccessor(t *testing.T) {
	t.Parallel()

	o := trialing(t)
	mustDo(t, o.AddAdmin("sub_bob", at))
	got := o.Admins()
	got[0] = "sub_mallory"
	if o.IsAdmin("sub_mallory") {
		t.Error("editing the slice returned by Admins() changed who administers the org")
	}
}

// Rebuilding from the log reaches the same state as issuing the commands.
//
// The aggregate is only ever loaded by replay, so a decide method that updates
// state without recording the matching event — or an Apply that ignores one —
// produces an aggregate that behaves correctly exactly once and wrongly ever
// after.
func TestReplayReachesTheSameState(t *testing.T) {
	t.Parallel()

	live := trialing(t)
	mustDo(t, live.AddAdmin("sub_bob", at))
	mustDo(t, live.Activate(at))
	mustDo(t, live.MarkPastDue(at.AddDate(0, 0, 7), at))

	replayed := domain.NewOrganization()
	for _, e := range live.Uncommitted() {
		replayed.Apply(e)
	}

	if replayed.Status() != live.Status() {
		t.Errorf("replayed status %s, live %s", replayed.Status(), live.Status())
	}
	if replayed.OwnerID() != live.OwnerID() {
		t.Errorf("replayed owner %q, live %q", replayed.OwnerID(), live.OwnerID())
	}
	if !replayed.IsAdmin("sub_bob") {
		t.Error("the admin grant did not survive replay")
	}
	if replayed.StripeSubscriptionID() != live.StripeSubscriptionID() {
		t.Error("the Stripe subscription id did not survive replay; every webhook is matched " +
			"to an organization by it")
	}
}

// A trial with no end is a free-forever account, and nothing alarms on it.
func TestATrialMustHaveAnEnd(t *testing.T) {
	t.Parallel()

	o := created(t)
	if err := o.StartTrial("cus_1", "sub_1", time.Time{}, at); err == nil {
		t.Fatal("a trial with no end was accepted")
	}
	if err := o.StartTrial("", "sub_1", at.AddDate(0, 0, 14), at); err == nil {
		t.Fatal("a trial with no Stripe customer was accepted; no webhook could ever be " +
			"matched back to this organization")
	}
}

var _ eventsourcing.Root = domain.NewOrganization()

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
