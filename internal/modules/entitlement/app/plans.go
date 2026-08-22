package app

import (
	"context"
	"fmt"

	"github.com/chronos/chronos-go/internal/modules/entitlement/domain"
)

// OrgPlans resolves which plan an organization is on.
//
// # Why every organization is on the trial plan today
//
// It is the only plan that exists. billing's plan catalogue (billing.md §2) is
// what will publish the rest, and until it does there is nothing else to
// resolve TO — an organization that converts is on a paid plan this build cannot
// name.
//
// Stated as a type rather than a hard-coded call so the shape is already right:
// when the catalogue lands, this reads the organization's subscription and looks
// the plan up, and no caller changes.
type OrgPlans struct {
	catalogue *domain.Catalogue
	planName  string
}

var _ Plans = (*OrgPlans)(nil)

func NewOrgPlans(catalogue *domain.Catalogue, planName string) (*OrgPlans, error) {
	if catalogue == nil {
		return nil, fmt.Errorf("entitlement: a catalogue is required")
	}
	if planName == "" {
		return nil, fmt.Errorf("entitlement: a default plan name is required")
	}
	if _, err := catalogue.Plan(planName); err != nil {
		return nil, fmt.Errorf("entitlement: the default plan is not in the catalogue: %w", err)
	}
	return &OrgPlans{catalogue: catalogue, planName: planName}, nil
}

// AllowanceFor returns what this organization is entitled to.
func (p *OrgPlans) AllowanceFor(_ context.Context, orgID string) (domain.Allowance, error) {
	if orgID == "" {
		return domain.Allowance{}, fmt.Errorf("entitlement: no organization to price")
	}
	return p.catalogue.Plan(p.planName)
}
