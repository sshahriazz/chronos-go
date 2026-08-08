package errs_test

import (
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/errs"
)

// The frontend must be able to mark the offending control. "Invalid request"
// is not an error message.
func TestInvalid_CarriesPerFieldDetail(t *testing.T) {
	err := errs.Invalid(
		errs.Violation{Field: "email", Constraint: "email", Message: "must be a valid email address"},
		errs.Violation{Field: "members[2].role", Constraint: "one_of", Message: "must be admin, member or guest"},
	)

	if got := errs.ReasonOf(err); got != errs.ValidationFailed {
		t.Fatalf("reason: got %s want VALIDATION_FAILED", got)
	}

	vs, ok := errs.Violations(err)
	if !ok {
		t.Fatal("violations must be extractable from the error")
	}
	if len(vs) != 2 {
		t.Fatalf("got %d violations want 2", len(vs))
	}
	for _, v := range vs {
		if v.Field == "" {
			t.Error("every violation must name a field, or the client cannot mark it")
		}
		if v.Constraint == "" {
			t.Error("every violation must carry a machine-readable constraint for localisation")
		}
		if v.Message == "" {
			t.Error("every violation must carry a human-readable fallback")
		}
	}
	// Indexed paths must survive so array items can be marked individually.
	if vs[1].Field != "members[2].role" {
		t.Errorf("indexed field path lost: %q", vs[1].Field)
	}
}

func TestInvalid_SummaryIsUseful(t *testing.T) {
	one := errs.Invalid(errs.Violation{Field: "email", Constraint: "required", Message: "required"})
	if !strings.Contains(one.Err.Message, "email") {
		t.Errorf("a single-field failure should name the field, got %q", one.Err.Message)
	}
	many := errs.Invalid(
		errs.Violation{Field: "a", Constraint: "required", Message: "required"},
		errs.Violation{Field: "b", Constraint: "required", Message: "required"},
	)
	if !strings.Contains(many.Err.Message, "2") {
		t.Errorf("a multi-field failure should say how many, got %q", many.Err.Message)
	}
}

func TestViolations_AbsentOnOtherErrors(t *testing.T) {
	if _, ok := errs.Violations(errs.AccessDeniedf("no")); ok {
		t.Fatal("only validation errors carry violations")
	}
}

// Field-level detail is safe to disclose: the caller supplied the input.
func TestInvalid_SurvivesDisclosure(t *testing.T) {
	err := errs.Invalid(errs.Violation{Field: "email", Constraint: "email", Message: "invalid"})
	got := errs.Disclose(err.Err, true)
	if got.Reason != errs.ValidationFailed {
		t.Fatalf("validation detail must survive the ladder, got %s", got.Reason)
	}
}
