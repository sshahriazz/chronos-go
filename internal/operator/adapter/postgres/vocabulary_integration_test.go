//go:build integration

package postgres_test

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/operator/contract"
	"github.com/chronos/chronos-go/internal/operator/domain"
)

// Two vocabularies in this plane live in three artefacts each — Go, a protobuf
// declaration, and a CHECK constraint — and none of the three can absorb the
// others: one is generated code, one is a migration, one is hand-written Go.
//
// So each PAIR gets a test. The proto ↔ Go pair is in internal/operator/api;
// these are the Go ↔ SQL pair, and they read the constraint out of
// `pg_constraint` rather than out of the migration file.
//
// # Why the live constraint and not the .sql
//
// Because the migration is what was WRITTEN and the constraint is what is
// RUNNING. Migrations are append-only, so a later one can widen a constraint an
// earlier one created — which is exactly what 00042, 00043 and 00044 each did —
// and a test reading the first would pass while describing a schema that has
// not existed for three migrations.

// checkDefinition returns the source of one CHECK constraint as PostgreSQL
// holds it.
func checkDefinition(t *testing.T, name string) string {
	t.Helper()

	var def string
	err := operatorPool(t).QueryRow(t.Context(), `
		SELECT pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conname = $1`, name).Scan(&def)
	if err != nil {
		t.Fatalf("reading the %s constraint: %v\n\n"+
			"A vocabulary test that cannot find its constraint is a vocabulary test "+
			"that would pass on a database with no constraint at all.", name, err)
	}
	return def
}

// literals pulls the quoted strings out of a constraint definition.
//
// `pg_get_constraintdef` renders an IN list as `('a'::text, 'b'::text, ...)`,
// so the quoted values are the vocabulary and everything else is punctuation.
var literals = regexp.MustCompile(`'([^']*)'`)

func admitted(t *testing.T, constraint string) []string {
	t.Helper()

	def := checkDefinition(t, constraint)
	matches := literals.FindAllStringSubmatch(def, -1)
	if len(matches) == 0 {
		t.Fatalf("the %s constraint admits no literal values:\n  %s\n\n"+
			"Either it is not an IN list any more, or this test is reading the wrong "+
			"constraint — and both mean it is checking nothing.", constraint, def)
	}

	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m[1])
	}
	sort.Strings(out)
	return out
}

// TestTheAuditActionConstraintMatchesTheDomain is the Go ↔ SQL half of the
// audit vocabulary.
//
// # Both directions, and each catches a different failure
//
// An action the constraint does NOT admit is a projection that stops: the
// insert fails, the projector halts, and the audit log silently stops growing
// while every log line says the projection is running. That is the worse
// direction, and it is the one an added action without a migration produces.
//
// An action the constraint admits that Go does NOT know is dead vocabulary — a
// word the database would accept that nothing writes. Harmless today and a
// signal that a migration widened the set for something that was never built,
// or that a rename left the old value behind.
func TestTheAuditActionConstraintMatchesTheDomain(t *testing.T) {
	inSQL := admitted(t, "operator_audit_action_known")

	inGo := make([]string, 0, len(domain.AuditActions()))
	for _, a := range domain.AuditActions() {
		inGo = append(inGo, string(a))
	}
	sort.Strings(inGo)

	for _, a := range inGo {
		if !contains(inSQL, a) {
			t.Errorf("the database refuses the action %q.\n\n"+
				"The projection writes it, so the insert fails, the projector halts, "+
				"and operator_audit_log silently stops growing while every log line "+
				"says the projection is running. Add a migration widening "+
				"operator_audit_action_known.", a)
		}
	}
	for _, a := range inSQL {
		if !contains(inGo, a) {
			t.Errorf("the database admits the action %q, which no Go constant names. "+
				"Either a migration widened the set for something never built, or a "+
				"rename left the old value behind.", a)
		}
	}
}

// TestTheRoleConstraintMatchesTheDomain is the same pair for the OTHER
// vocabulary.
//
// The four roles appear as Go constants, as a protovalidate pattern on two
// request fields, and here. The proto half is asserted by
// TestTheRoleFieldPatternMatchesTheDomain in internal/operator/policy; this is
// the storage half.
//
// The failure it catches is the same shape and lands somewhere worse: a role Go
// knows and the database refuses is an operator who cannot be PROJECTED. They
// would be provisioned successfully — the event appends — and then never appear
// in operator_account, so they could never sign in, and the only symptom would
// be a stalled projection.
func TestTheRoleConstraintMatchesTheDomain(t *testing.T) {
	inSQL := admitted(t, "operator_account_role_known")

	inGo := make([]string, 0, len(domain.Roles()))
	for _, r := range domain.Roles() {
		inGo = append(inGo, string(r))
	}
	sort.Strings(inGo)

	for _, r := range inGo {
		if !contains(inSQL, r) {
			t.Errorf("the database refuses the role %q, so an operator granted it would "+
				"be provisioned successfully and never projected — they could never "+
				"sign in, and the only symptom would be a stalled projection", r)
		}
	}
	for _, r := range inSQL {
		if !contains(inGo, r) {
			t.Errorf("the database admits the role %q, which domain.Roles() does not "+
				"list — so it holds no capabilities and granting it does nothing", r)
		}
	}
}

// TestEveryJustifiedActionHasAConstraintEnforcingIt is the third leg of a rule
// this plane states three times.
//
// A justification is required by protovalidate at the edge, by the audit
// aggregate in the domain, and by a CHECK constraint in the database. Each
// catches a different mistake — a client bug, a second caller added later, and
// a projector bug — and the third is the one nobody notices missing, because
// the first two pass.
//
// So this asserts the constraint EXISTS for each of the three, by name. It does
// not parse the predicate: what matters is that somebody wrote one, and the
// aggregate's own tests already prove what it must say.
func TestEveryJustifiedActionHasAConstraintEnforcingIt(t *testing.T) {
	constraints := map[domain.AuditAction]string{
		domain.ActionViewedPersonalData: "operator_audit_personal_data_justified",
		domain.ActionElevated:           "operator_audit_elevation_justified",
		domain.ActionChangedTenant:      "operator_audit_tenant_write_justified",
	}

	for _, action := range domain.JustifiedActions() {
		name, ok := constraints[action]
		if !ok {
			t.Errorf("%q requires a justification and this test names no constraint for "+
				"it, so the database half of the rule is unasserted", action)
			continue
		}

		def := checkDefinition(t, name)
		if !strings.Contains(def, string(action)) {
			t.Errorf("%s does not mention %q:\n  %s", name, action, def)
		}
		if !strings.Contains(def, "reason") {
			t.Errorf("%s does not mention `reason`, so it is not enforcing a "+
				"justification:\n  %s", name, def)
		}
	}
}

// TestTheContractRolesAndTheDomainRolesAgree is cheap and closes a gap the two
// tests above cannot.
//
// `contract.Role*` are the strings stored in events; `domain.Roles()` is what
// the capability table knows. A role declared in the contract and missing from
// the table holds NOTHING — which is fail-closed and therefore silent, and
// exactly what an operator granted it would experience as "my access does not
// work".
func TestTheContractRolesAndTheDomainRolesAgree(t *testing.T) {
	declared := []contract.Role{
		contract.RoleSupport,
		contract.RoleBillingOps,
		contract.RoleCatalogueAdmin,
		contract.RoleOperatorAdmin,
	}

	known := map[contract.Role]bool{}
	for _, r := range domain.Roles() {
		known[r] = true
	}

	for _, r := range declared {
		if !known[r] {
			t.Errorf("contract declares the role %q and domain.Roles() omits it, so it "+
				"holds no capabilities and granting it does nothing", r)
		}
		if !domain.ValidRole(r) {
			t.Errorf("contract declares the role %q and the capability table has no row "+
				"for it", r)
		}
	}
	if len(declared) != len(domain.Roles()) {
		t.Errorf("the contract declares %d roles and the domain knows %d",
			len(declared), len(domain.Roles()))
	}
}

func contains(list []string, want string) bool {
	for _, x := range list {
		if x == want {
			return true
		}
	}
	return false
}
