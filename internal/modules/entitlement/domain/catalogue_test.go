package domain_test

import (
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/entitlement/domain"
)

// The off-by-one that decides whether a customer gets what they paid for.
//
// Gate 4 does not ask "are we over the limit", it asks "may ONE MORE be taken".
// A plan of 3 with 3 used must refuse the fourth and must have allowed the
// third. Getting this wrong in one direction sells 3 and delivers 2; in the
// other it sells 3 and delivers 4.
func TestPermitsIsAboutOneMore(t *testing.T) {
	t.Parallel()

	trial := domain.Trial()

	for _, tc := range []struct {
		used int
		want bool
	}{
		{0, true}, // the first
		{1, true},
		{2, true},  // the third, which the plan sells
		{3, false}, // the fourth, which it does not
		{4, false}, // already over, somehow
	} {
		if got := trial.Permits(domain.WorkspacesCount, tc.used); got != tc.want {
			t.Errorf("with %d of 3 workspaces used, one more permitted=%t, want %t",
				tc.used, got, tc.want)
		}
	}
}

// A limit the plan does not mention is REFUSED, not treated as unlimited.
//
// An RPC declaring an entitlement no plan grants is a configuration mistake.
// Answering "unlimited" would silently ungate that RPC for every customer, and
// the only way anybody would find out is a bill.
func TestAnUnknownLimitIsRefused(t *testing.T) {
	t.Parallel()

	sparse := domain.Allowance{
		Name:   "sparse",
		Limits: map[domain.LimitKey]int{domain.WorkspacesCount: 5},
	}
	if sparse.Permits(domain.SeatsMember, 0) {
		t.Fatal("a limit the plan never mentions was permitted. An RPC declaring an " +
			"entitlement no plan grants would be ungated for every customer")
	}
	if _, known := sparse.Of(domain.SeatsMember); known {
		t.Error("a limit the plan does not mention reports as known")
	}
}

// Zero and absent are different answers.
//
// The trial grants no guest seats, and says so with a zero rather than by
// omitting the key. A missing key means "this plan has no opinion", which is a
// configuration error; zero means "none", which is a product decision.
func TestZeroIsNotTheSameAsAbsent(t *testing.T) {
	t.Parallel()

	trial := domain.Trial()

	limit, known := trial.Of(domain.SeatsGuest)
	if !known {
		t.Fatal("the trial does not mention guest seats; a plan with no opinion on a limit " +
			"cannot be enforced, and this one has an opinion — none")
	}
	if limit != 0 {
		t.Errorf("the trial grants %d guest seats, want 0", limit)
	}
	if trial.Permits(domain.SeatsGuest, 0) {
		t.Error("a limit of zero permitted the first consumer")
	}
}

// Unlimited is a sentinel, and it permits.
func TestUnlimitedPermitsAnything(t *testing.T) {
	t.Parallel()

	generous := domain.Allowance{
		Name:   "enterprise",
		Limits: map[domain.LimitKey]int{domain.WorkspacesCount: domain.Unlimited},
	}
	for _, used := range []int{0, 1, 1000, 1_000_000} {
		if !generous.Permits(domain.WorkspacesCount, used) {
			t.Errorf("an unlimited plan refused the next consumer at %d", used)
		}
	}
}

// The trial's numbers are the ones the scope document settled on.
//
// Asserted explicitly because they are a product decision rather than an
// implementation detail: they are also the anti-abuse bound on a cardless trial,
// and changing them silently changes what a free signup costs to run.
func TestTheTrialGrantsTheAgreedCaps(t *testing.T) {
	t.Parallel()

	trial := domain.Trial()
	for key, want := range map[domain.LimitKey]int{
		domain.WorkspacesCount: 3,
		domain.SeatsMember:     5,
		domain.SeatsGuest:      0,
	} {
		got, known := trial.Of(key)
		if !known {
			t.Errorf("the trial plan does not grant %q at all", key)
			continue
		}
		if got != want {
			t.Errorf("the trial grants %d of %q, want %d (ORG-WORKSPACE-SCOPE §3)",
				got, key, want)
		}
	}
}

// A plan granting a limit this build cannot reserve against is refused.
//
// A number with no enforcement behind it reads as a working cap and is not one.
func TestAPlanGrantingAnUnknownLimitIsRefused(t *testing.T) {
	t.Parallel()

	_, err := domain.NewCatalogue(domain.Allowance{
		Name:   "typo",
		Limits: map[domain.LimitKey]int{"workspace.count": 3}, // singular: a typo
	})
	if err == nil {
		t.Fatal("a plan granting an unknown limit was accepted; the cap would appear in the " +
			"catalogue and nothing would ever reserve against it")
	}
	if !strings.Contains(err.Error(), "workspace.count") {
		t.Errorf("the error does not name the offending key: %v", err)
	}
}

func TestTheCatalogueLooksUpPlans(t *testing.T) {
	t.Parallel()

	cat, err := domain.NewCatalogue(domain.Trial())
	if err != nil {
		t.Fatalf("NewCatalogue: %v", err)
	}
	if _, err := cat.Plan("trial"); err != nil {
		t.Errorf("the trial plan is not in the catalogue: %v", err)
	}
	if _, err := cat.Plan("enterprise"); err == nil {
		t.Error("an unknown plan resolved; the organization would be gated against a plan " +
			"this build invented")
	}
}

func TestTwoPlansCannotShareAName(t *testing.T) {
	t.Parallel()

	_, err := domain.NewCatalogue(
		domain.Allowance{Name: "trial", Limits: map[domain.LimitKey]int{domain.WorkspacesCount: 3}},
		domain.Allowance{Name: "trial", Limits: map[domain.LimitKey]int{domain.WorkspacesCount: 9}},
	)
	if err == nil {
		t.Fatal("two plans share a name; which allowance a customer gets depends on map order")
	}
}
