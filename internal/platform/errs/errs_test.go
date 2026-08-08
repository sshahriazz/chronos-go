package errs_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/errs"
)

func TestReasonOf_UnclassifiedErrorsAreInternal(t *testing.T) {
	// Never let an unrecognised failure reach a client wearing a specific code.
	if got := errs.ReasonOf(errors.New("boom")); got != errs.Internal {
		t.Fatalf("got %s want INTERNAL", got)
	}
	if got := errs.ReasonOf(nil); got != errs.Internal {
		t.Fatalf("nil: got %s want INTERNAL", got)
	}
}

func TestWrap_KeepsTheCauseServerSideOnly(t *testing.T) {
	cause := errors.New("pq: duplicate key value violates unique constraint")
	e := errs.Conflictf("workspace already exists").Wrap(cause)

	if !errors.Is(e, cause) {
		t.Fatal("cause must remain reachable via errors.Is for logging")
	}
	// ADR-015: the client-safe message must not carry driver text.
	if strings.Contains(e.Message, "pq:") {
		t.Fatalf("driver text leaked into the safe message: %q", e.Message)
	}
}

// ADR-036: the disclosure ladder. Below the authz gate every failure is
// indistinguishable; at or above it the caller has proven they belong.
func TestDisclose_Ladder(t *testing.T) {
	tests := []struct {
		name          string
		err           *errs.Error
		parentVisible bool
		want          errs.Reason
	}{
		{"authn failure is hidden", errs.Unauthenticatedf("no session"), false, errs.NotFound},
		{"org-context failure is hidden", errs.New(errs.NotFound, "x"), false, errs.NotFound},

		{"authz denial with an invisible parent hides existence",
			errs.AccessDeniedf("no"), false, errs.NotFound},
		{"authz denial with a visible parent tells the truth",
			errs.AccessDeniedf("no"), true, errs.AccessDenied},

		{"subscription failure is specific",
			errs.OrgSuspendedf("past due"), false, errs.OrgSuspended},
		{"entitlement failure is specific",
			errs.PlanUpgradeRequiredf("pro required"), false, errs.PlanUpgradeRequired},
		{"quota failure is specific",
			errs.QuotaExceededf("no seats"), false, errs.QuotaExceeded},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := errs.Disclose(tc.err, tc.parentVisible)
			if got.Reason != tc.want {
				t.Fatalf("got %s want %s", got.Reason, tc.want)
			}
		})
	}
}

// The two gates whose confusion is a product bug: they must never collapse
// into one another (entitlement.md — "ask an admin" vs "upgrade your plan").
func TestDisclose_KeepsAccessAndEntitlementDistinct(t *testing.T) {
	access := errs.Disclose(errs.AccessDeniedf("no"), true)
	plan := errs.Disclose(errs.PlanUpgradeRequiredf("no"), true)
	if access.Reason == plan.Reason {
		t.Fatal("ACCESS_DENIED and PLAN_UPGRADE_REQUIRED must stay distinct")
	}
}

func TestDisclose_HiddenErrorKeepsTheCauseButDropsMetadata(t *testing.T) {
	orig := errs.AccessDeniedf("workspace ws_123 denied").
		WithMeta(map[string]string{"workspace": "ws_123"})

	hidden := errs.Disclose(orig, false)

	if hidden.Meta != nil {
		t.Fatalf("metadata must not survive hiding: %v", hidden.Meta)
	}
	if strings.Contains(hidden.Message, "ws_123") {
		t.Fatalf("hidden message leaked an identifier: %q", hidden.Message)
	}
	if !errors.Is(hidden, orig) {
		t.Fatal("the real cause must remain available server-side")
	}
}

func TestDisclose_NilIsNil(t *testing.T) {
	if got := errs.Disclose(nil, true); got != nil {
		t.Fatalf("got %v want nil", got)
	}
}

func TestIs_MatchesByReason(t *testing.T) {
	if !errors.Is(errs.NotFoundf("a"), errs.NotFoundf("b")) {
		t.Fatal("errors.Is must match on Reason")
	}
	if errors.Is(errs.NotFoundf("a"), errs.Conflictf("b")) {
		t.Fatal("different reasons must not match")
	}
}

func TestGate_DisclosureBoundary(t *testing.T) {
	for _, g := range []errs.Gate{errs.GateNone, errs.GateAuthn, errs.GateOrgContext} {
		if g.DisclosesDetail() {
			t.Errorf("gate %v must not disclose detail", g)
		}
	}
	for _, g := range []errs.Gate{errs.GateAuthz, errs.GateSubscription, errs.GateEntitlement, errs.GateHandler} {
		if !g.DisclosesDetail() {
			t.Errorf("gate %v must disclose detail", g)
		}
	}
}

// Every Reason must be a stable, uppercase, machine-readable token: it is
// published as part of the API contract (CONVENTIONS §7.1).
func TestReasons_AreWellFormed(t *testing.T) {
	all := []errs.Reason{
		errs.Unauthenticated, errs.StepUpRequired, errs.AccessDenied,
		errs.PlanUpgradeRequired, errs.QuotaExceeded, errs.OrgSuspended,
		errs.NotFound, errs.Conflict, errs.ValidationFailed,
		errs.RateLimited, errs.Internal,
	}
	seen := map[errs.Reason]bool{}
	for _, r := range all {
		s := string(r)
		if s != strings.ToUpper(s) || strings.ContainsAny(s, " -") {
			t.Errorf("reason %q must be UPPER_SNAKE", s)
		}
		if seen[r] {
			t.Errorf("duplicate reason %q", s)
		}
		seen[r] = true
	}
}
