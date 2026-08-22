// Package domain is the entitlement vocabulary: what a plan grants, and the
// arithmetic that decides whether one more is allowed.
//
// No Stripe types appear anywhere in this domain (ADR-001, ADR-025). What a
// customer BOUGHT is billing's business; what that entitles them to is this
// module's, and gate 4 must keep answering during a Stripe incident.
package domain

import (
	"fmt"
	"sort"
)

// LimitKey names a ceiling. Declared per RPC in the .proto as
// `(chronos.options.v1.entitlement)`, and looked up here.
type LimitKey string

const (
	// WorkspacesCount is how many workspaces an organization may have.
	WorkspacesCount LimitKey = "workspaces.count"

	// SeatsMember and SeatsGuest are INDEPENDENT pools (ADR-027), reserved
	// separately. Exhausting guest seats must never block hiring, and a guest
	// promoted to member crosses pools rather than staying put.
	SeatsMember LimitKey = "seats.member"
	SeatsGuest  LimitKey = "seats.guest"
)

// LimitKeys is every limit this build knows, for exhaustive tests and for the
// startup check that a declared entitlement is one the catalogue can answer.
// PerSubject reports whether a limit is counted ONE PER PERSON.
//
// Seats are; resources are not. The distinction is the whole of "a seat is per
// person per organization, not per membership" (workspace.md §2) expressed where
// the reservation store can act on it — and it has to be here rather than at the
// call sites, because there are now two independent paths that take a seat.
// Somebody can hold a pending invitation to one workspace and be added directly
// to another, and each path's own conditional check is blind to the other's
// reservation: the invitation holds a seat that no membership row reflects.
//
// `workspaces.count` is deliberately NOT per-subject. Gate 4 records the CREATOR
// as its subject_ref, so one admin opening three workspaces is three units of
// one limit — treating that as per-subject would cap every organization at one
// workspace per admin.
func (k LimitKey) PerSubject() bool {
	return k == SeatsMember || k == SeatsGuest
}

func LimitKeys() []LimitKey {
	return []LimitKey{WorkspacesCount, SeatsMember, SeatsGuest}
}

// Unlimited is the ceiling for a plan that does not cap a limit.
//
// A sentinel rather than an absent entry, because "the plan does not mention
// this" and "the plan allows none of these" are opposite answers and a missing
// map key cannot tell them apart. Zero means zero.
const Unlimited = -1

// Allowance is what one plan grants, per limit.
//
// A value type: it is derived from a plan version and never mutated. entitlement
// md §2 has the snapshot computed from the plan, overrides and org status, and
// this is the plan's half.
type Allowance struct {
	Name   string
	Limits map[LimitKey]int
}

// Of returns the ceiling for a limit, and whether the plan mentions it.
//
// The two are distinguished deliberately: a limit the plan does not name is a
// question the catalogue cannot answer, and gate 4 must refuse rather than
// invent a number. An RPC declaring an entitlement no plan grants is a
// configuration error, and inventing Unlimited there would silently ungate it.
func (a Allowance) Of(key LimitKey) (int, bool) {
	v, ok := a.Limits[key]
	return v, ok
}

// Permits reports whether `used` consumers plus one more fits.
//
// The `+1` is the whole question gate 4 asks: not "are we over" but "may one
// more be taken". A limit of 3 with 3 used refuses the fourth, which is the
// off-by-one that decides whether a customer gets what they paid for.
func (a Allowance) Permits(key LimitKey, used int) bool {
	limit, known := a.Of(key)
	switch {
	case !known:
		return false
	case limit == Unlimited:
		return true
	case limit <= 0:
		return false
	default:
		return used < limit
	}
}

// Trial is the allowance a cardless trial gets.
//
// The numbers are ORG-WORKSPACE-SCOPE.md §3's decision, and they are a real plan
// rather than a special case in the derivation. That distinction matters: if the
// trial subscribed to a paid plan and the caps were applied by an "if trialing"
// branch, entitlement derivation would carry a second code path — and the second
// path is where the bugs live (billing.md §2 makes the same argument for why a
// free plan gets a real $0 Price).
func Trial() Allowance {
	return Allowance{
		Name: "trial",
		Limits: map[LimitKey]int{
			WorkspacesCount: 3,
			SeatsMember:     5,
			// No guest seats on a trial. Zero, not absent: the plan has an
			// opinion, and it is "none".
			SeatsGuest: 0,
		},
	}
}

// Catalogue answers "what does this plan grant".
//
// One plan today. It is a lookup rather than a hard-coded Trial() call so that
// the plan catalogue billing will publish can replace the map without changing
// a single caller.
type Catalogue struct{ plans map[string]Allowance }

// NewCatalogue builds one from the plans a build knows.
func NewCatalogue(plans ...Allowance) (*Catalogue, error) {
	if len(plans) == 0 {
		return nil, fmt.Errorf("entitlement: a catalogue with no plans answers no question")
	}
	byName := make(map[string]Allowance, len(plans))
	for _, p := range plans {
		if p.Name == "" {
			return nil, fmt.Errorf("entitlement: a plan with no name cannot be looked up")
		}
		if _, taken := byName[p.Name]; taken {
			return nil, fmt.Errorf("entitlement: two plans are both named %q", p.Name)
		}
		for key := range p.Limits {
			if !known(key) {
				return nil, fmt.Errorf("entitlement: plan %q grants %q, which is not a limit "+
					"this build knows; a limit nothing reserves against is a number with no "+
					"enforcement behind it", p.Name, key)
			}
		}
		byName[p.Name] = p
	}
	return &Catalogue{plans: byName}, nil
}

// Plan returns an allowance by name.
func (c *Catalogue) Plan(name string) (Allowance, error) {
	a, ok := c.plans[name]
	if !ok {
		return Allowance{}, fmt.Errorf("entitlement: no plan named %q; the organization is "+
			"subscribed to something this build cannot price", name)
	}
	return a, nil
}

// Plans lists every plan name, sorted, for diagnostics.
func (c *Catalogue) Plans() []string {
	out := make([]string, 0, len(c.plans))
	for name := range c.plans {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func known(key LimitKey) bool {
	for _, k := range LimitKeys() {
		if k == key {
			return true
		}
	}
	return false
}
