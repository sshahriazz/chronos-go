package domain_test

import (
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
)

// These are compliance.md §16's test plan, applied to the retention schedule:
// "invoices survive erasure; session logs do not". That sentence is a statement
// about two rows of one table, and it could not be asserted at all while the
// exemptions were three hand-written sentences in a []string.

// TestInvoicesSurviveAnErasureAndSessionLogsDoNot is the §16 line, directly.
//
// The two halves matter for opposite reasons. If invoices stopped being an
// exemption, the erasure confirmation would imply total deletion while tax
// records were retained — the misleading statement §7 names. If session logs
// BECAME one, we would be telling people we keep their sign-in history when we
// destroy it, which is the same wrong pointing the other way.
func TestInvoicesSurviveAnErasureAndSessionLogsDoNot(t *testing.T) {
	invoices, err := domain.RetentionPolicyFor(domain.ClassInvoices)
	if err != nil {
		t.Fatalf("invoices are not in the retention schedule: %v", err)
	}
	if !invoices.Disposition.Retained() {
		t.Errorf("invoices have disposition %q; tax law requires their retention and "+
			"Article 17(3)(b) permits it, so an erasure that destroyed them would break "+
			"an obligation we cannot decline", invoices.Disposition)
	}

	sessions, err := domain.RetentionPolicyFor(domain.ClassSessionLogs)
	if err != nil {
		t.Fatalf("session logs are not in the retention schedule: %v", err)
	}
	if sessions.Disposition.Retained() {
		t.Errorf("session logs have disposition %q; they are erased with the subject, and "+
			"listing them as retained tells somebody we keep a sign-in history we destroy",
			sessions.Disposition)
	}
}

// TestEveryRetainedClassStatesALegalBasis.
//
// compliance.md §7 requires the DSAR response to say what is retained AND why,
// "rather than implying total deletion". Under the GDPR the "why" for keeping
// data past an erasure request is an ARTICLE — 17(3) is the only thing that
// permits it at all — so a retained class with no basis is either a retention
// that should not be happening or a statement the person cannot check.
func TestEveryRetainedClassStatesALegalBasis(t *testing.T) {
	for _, p := range domain.RetentionExemptions() {
		if p.Disposition == domain.DispositionPseudonymised && p.LegalBasis == "" {
			// Pseudonymisation of the event log is the one entry with no article,
			// because it is not a retention exception at all: the data stops
			// identifying anybody, which is what Article 17 asked for. It is
			// stated so the person is not surprised by it later, and this branch
			// exists so that the exemption is deliberate rather than a gap.
			if p.Class == domain.ClassEventLog {
				continue
			}
		}
		if p.LegalBasis == "" {
			t.Errorf("%q survives an erasure and states no legal basis; the person is "+
				"told we keep it and given no ground they can check", p.Class)
		}
	}
}

// TestEveryClassInTheScheduleIsExplainedToThePerson.
//
// Every row reaches a data subject — in an erasure confirmation, an export
// manifest, or both. A row with no period is one that cannot answer Article
// 15(1)(d)'s "envisaged period"; a row with no reason is a machine token in a
// message to a person.
func TestEveryClassInTheScheduleIsExplainedToThePerson(t *testing.T) {
	schedule := domain.RetentionSchedule()
	if len(schedule) == 0 {
		t.Fatal("the retention schedule is empty, so every erasure confirmation would be " +
			"refused and no export could state what is retained")
	}
	for _, p := range schedule {
		if p.Class == "" {
			t.Error("a retention policy names no data class")
		}
		if p.Period == "" {
			t.Errorf("%q states no retention period; Article 15(1)(d) asks for the "+
				"envisaged period and 'we keep some of it' does not answer that", p.Class)
		}
		if p.Reason == "" {
			t.Errorf("%q states no reason; the data class is a machine token and the "+
				"person reading it is not a machine", p.Class)
		}
		if p.Disposition == "" {
			t.Errorf("%q states no disposition. The zero value reports Retained() == "+
				"true, so a class with no decision recorded would silently become an "+
				"exemption with nothing to say about it", p.Class)
		}
	}
}

// TestTheExemptionsAreExactlyTheClassesThatSurvive.
//
// The two answers are derived from one table so they cannot disagree. This
// asserts the derivation rather than the table: a filter that inverted, or that
// used == DispositionRetained and dropped the pseudonymised classes, would
// produce a plausible list that omits the event log — which is the one entry
// that applies to absolutely everybody.
func TestTheExemptionsAreExactlyTheClassesThatSurvive(t *testing.T) {
	var want int
	for _, p := range domain.RetentionSchedule() {
		if p.Disposition != domain.DispositionErased {
			want++
		}
	}
	got := domain.RetentionExemptions()
	if len(got) != want {
		t.Fatalf("the schedule has %d surviving classes and the exemption list has %d",
			want, len(got))
	}
	for _, p := range got {
		if p.Disposition == domain.DispositionErased {
			t.Errorf("%q is listed as an exemption and is erased", p.Class)
		}
	}

	var hasEventLog bool
	for _, p := range got {
		if p.Class == domain.ClassEventLog {
			hasEventLog = true
		}
	}
	if !hasEventLog {
		t.Error("the event log is not among the exemptions. It survives every erasure — " +
			"pseudonymised, never rewritten (ADR-002) — and it applies to everybody, so " +
			"an exemption set without it can never be empty by accident and is wrong when " +
			"it is")
	}
}

// TestAnUnknownDataClassIsAnError.
//
// The zero RetentionPolicy has an empty disposition, which `Retained` reports as
// TRUE. So a lookup that returned the zero value for a typo would turn a
// misspelled class into an exemption with no period, no basis and no sentence,
// and the person would be told something survived without being told what.
func TestAnUnknownDataClassIsAnError(t *testing.T) {
	_, err := domain.RetentionPolicyFor(domain.DataClass("invoces"))
	if err == nil {
		t.Fatal("a data class that is not in the schedule was resolved; a typo would " +
			"become an exemption with nothing to say about it")
	}
	if !strings.Contains(err.Error(), "invoces") {
		t.Errorf("the error does not name the class: %v", err)
	}
}

// TestTheScheduleCannotBeRewrittenByACaller.
//
// It is the published retention policy of a running system, and it feeds the
// erasure confirmation. A caller that could append to or reorder the returned
// slice would be changing what data subjects are told by assigning to a
// variable.
func TestTheScheduleCannotBeRewrittenByACaller(t *testing.T) {
	first := domain.RetentionSchedule()
	if len(first) == 0 {
		t.Fatal("empty schedule")
	}
	original := first[0]
	first[0] = domain.RetentionPolicy{Class: "tampered", Disposition: domain.DispositionErased}

	second := domain.RetentionSchedule()
	if second[0].Class != original.Class {
		t.Fatalf("mutating one caller's slice changed the schedule for the next: it now "+
			"starts with %q", second[0].Class)
	}
}
