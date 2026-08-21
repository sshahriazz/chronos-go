//go:build integration

package protocolit_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	organizationv1 "github.com/chronos/chronos-go/gen/proto/chronos/organization/v1"
	"github.com/chronos/chronos-go/internal/platform/errs"
)

// Creating an organization, over the wire, with its two uniqueness rules.
//
// # What this proves that a unit test cannot
//
// Both rules are enforced by ONE atomic append with a `NoStream` precondition on
// three streams. That mechanism only exists when a real KurrentDB is deciding
// the race — a fake appender that ignores `Expected` would let every assertion
// here pass while the invariant did not hold, which is the failure this
// repository has already had once, in identity's reset tests.
func TestCreateOrganization(t *testing.T) {
	t.Run("the happy path returns a provisioning organization", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
		defer cancel()

		account := h.disposableAccount(t, "org-create")
		res, err := h.organization.CreateOrganization(ctx,
			authed(&organizationv1.CreateOrganizationRequest{
				Name: "Acme Corporation", Slug: h.freshSlug(),
			}, account.bearer))
		if err != nil {
			t.Fatalf("CreateOrganization: %v\n%s", err, h.serverLogs())
		}
		if !strings.HasPrefix(res.Msg.GetOrgId(), "org_") {
			t.Errorf("the organization id %q is not a prefixed ULID (ADR-030)", res.Msg.GetOrgId())
		}
		// Provisioning, not trialing: the Stripe subscription is created by a
		// reactor, and the trial starts when the mirror lands.
		if got := res.Msg.GetStatus(); got != "provisioning" {
			t.Errorf("a new organization is %q, want provisioning — the trial cannot have "+
				"started before its subscription exists", got)
		}
	})

	t.Run("a person may own only one organization", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
		defer cancel()

		account := h.disposableAccount(t, "org-one")
		if _, err := h.organization.CreateOrganization(ctx,
			authed(&organizationv1.CreateOrganizationRequest{
				Name: "First", Slug: h.freshSlug(),
			}, account.bearer)); err != nil {
			t.Fatalf("the first organization was refused: %v\n%s", err, h.serverLogs())
		}

		// A DIFFERENT slug, so the only precondition that can fail is the owner
		// reservation. Reusing the slug would prove slug uniqueness instead and
		// leave this rule untested.
		_, err := h.organization.CreateOrganization(ctx,
			authed(&organizationv1.CreateOrganizationRequest{
				Name: "Second", Slug: h.freshSlug(),
			}, account.bearer))
		if err == nil {
			t.Fatal("one person created two organizations. organization.md §1 makes the " +
				"organization the tenant and the customer contract, and a second one means " +
				"two subscriptions, two seat pools and two bills for one customer")
		}
		got, ok := reasonOf(err)
		if !ok {
			t.Fatalf("the refusal carries no chronos.errors.v1.ErrorDetail, so a client "+
				"cannot tell a duplicate organization from a validation failure: %v", err)
		}
		if got != string(errs.Conflict) {
			t.Errorf("the second creation was refused with reason %q, want %q", got, errs.Conflict)
		}
	})

	t.Run("a slug is claimed by exactly one organization", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
		defer cancel()

		slug := h.freshSlug()
		first := h.disposableAccount(t, "org-slug-a")
		second := h.disposableAccount(t, "org-slug-b")

		if _, err := h.organization.CreateOrganization(ctx,
			authed(&organizationv1.CreateOrganizationRequest{
				Name: "First", Slug: slug,
			}, first.bearer)); err != nil {
			t.Fatalf("the first claim was refused: %v\n%s", err, h.serverLogs())
		}

		_, err := h.organization.CreateOrganization(ctx,
			authed(&organizationv1.CreateOrganizationRequest{
				Name: "Second", Slug: slug,
			}, second.bearer))
		if err == nil {
			t.Fatalf("two organizations claimed the slug %q; both would answer at the same "+
				"URL", slug)
		}
	})

	t.Run("a reserved slug is refused", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
		defer cancel()

		account := h.disposableAccount(t, "org-reserved")
		_, err := h.organization.CreateOrganization(ctx,
			authed(&organizationv1.CreateOrganizationRequest{
				Name: "Impostor", Slug: "billing",
			}, account.bearer))
		if err == nil {
			t.Fatal("an organization claimed the slug `billing`, which collides with an " +
				"operator route and lets it impersonate one")
		}
	})
}

// Two concurrent creations by ONE person produce exactly one organization.
//
// # Why this is the test that justifies the whole mechanism
//
// A double-clicked button, or two tabs, is the ordinary case — not an attack.
// The check-then-create shape everybody writes first would let both requests
// read "this person owns nothing", both append, and one customer end up with two
// subscriptions. A projection cannot close that window because it is behind the
// log by construction (ADR-052).
//
// What closes it is the `NoStream` precondition on the owner reservation stream,
// evaluated by KurrentDB at the moment of the write. This drives both requests
// at once against the real server and requires exactly one winner.
//
// Distinct idempotency keys, deliberately: with the same key the IDEMPOTENCY
// GATE would collapse the second request and the reservation would never be
// tested. This has to be two genuine attempts.
func TestTwoConcurrentCreationsByOnePersonProduceOneOrganization(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	account := h.disposableAccount(t, "org-race")

	type outcome struct {
		orgID string
		err   error
	}
	results := make([]outcome, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup

	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // release both at once
			res, err := h.organization.CreateOrganization(ctx,
				authed(&organizationv1.CreateOrganizationRequest{
					Name: "Race", Slug: h.freshSlug(),
				}, account.bearer))
			if err != nil {
				results[i] = outcome{err: err}
				return
			}
			results[i] = outcome{orgID: res.Msg.GetOrgId()}
		}(i)
	}
	close(start)
	wg.Wait()

	won := 0
	for _, r := range results {
		if r.err == nil {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("%d of 2 concurrent creations succeeded, want exactly 1. Results: %+v.\n"+
			"With 2 winners this person now owns two organizations — two subscriptions and "+
			"two bills for one customer. With 0, the precondition is refusing a request that "+
			"should have won.", won, results)
	}
}
