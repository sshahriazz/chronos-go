// Package errs defines the single error vocabulary every domain speaks
// (CONVENTIONS §5). Domains never construct transport errors; the API layer
// maps a Reason to a Connect code exactly once.
//
// The Reason is the contract. Clients branch on it — PLAN_UPGRADE_REQUIRED and
// ACCESS_DENIED lead to completely different journeys ("upgrade" versus "ask an
// admin"), so collapsing both into a generic 403 is a product bug, not a
// shortcut.
package errs

import (
	"errors"
	"fmt"
	"maps"
)

// Reason is the machine-readable error code. It is part of the public API and
// is published in the generated documentation (CONVENTIONS §7.1).
type Reason string

const (
	Unauthenticated     Reason = "UNAUTHENTICATED"
	StepUpRequired      Reason = "STEP_UP_REQUIRED"
	AccessDenied        Reason = "ACCESS_DENIED"
	PlanUpgradeRequired Reason = "PLAN_UPGRADE_REQUIRED"
	QuotaExceeded       Reason = "QUOTA_EXCEEDED"
	OrgSuspended        Reason = "ORG_SUSPENDED"
	NotFound            Reason = "NOT_FOUND"
	Conflict            Reason = "CONFLICT"
	ValidationFailed    Reason = "VALIDATION_FAILED"
	RateLimited         Reason = "RATE_LIMITED"
	Internal            Reason = "INTERNAL"
)

// Gate is the enforcement stage that rejected a request (ADR-021). It drives
// the disclosure ladder in ADR-036: below Authz every failure is
// indistinguishable; at or above it the caller has proven they belong.
type Gate int

const (
	GateNone Gate = iota
	GateAuthn
	GateOrgContext
	GateAuthz
	GateSubscription
	GateEntitlement
	GateHandler
)

// DisclosesDetail reports whether a failure at this gate may return a specific
// reason. Only Authz and above; everything below returns NOT_FOUND (ADR-036).
func (g Gate) DisclosesDetail() bool { return g >= GateAuthz }

// Error is the domain error. It carries a Reason, a safe message, structured
// metadata, and the gate that produced it.
//
// The message is safe to return to a client. Anything unsafe — SQL, driver
// text, stack traces — belongs in the wrapped error, which stays server-side
// (ADR-015).
type Error struct {
	Reason   Reason
	Message  string
	Gate     Gate
	Meta     map[string]string
	internal error
}

func (e *Error) Error() string {
	if e.internal != nil {
		return fmt.Sprintf("%s: %s: %v", e.Reason, e.Message, e.internal)
	}
	return fmt.Sprintf("%s: %s", e.Reason, e.Message)
}

// Unwrap exposes the internal cause to errors.Is/As, never to a client.
func (e *Error) Unwrap() error { return e.internal }

// Is compares by Reason so errors.Is(err, errs.NotFoundError()) works.
func (e *Error) Is(target error) bool {
	var t *Error
	return errors.As(target, &t) && t.Reason == e.Reason
}

// New builds an error. Prefer the named constructors below.
func New(r Reason, msg string) *Error { return &Error{Reason: r, Message: msg} }

// Wrap attaches an internal cause that is never disclosed outward.
func (e *Error) Wrap(cause error) *Error { e.internal = cause; return e }

// WithMeta attaches structured, client-safe detail — a limit that was exceeded,
// a field that failed validation. Never personal data (ADR-002).
func (e *Error) WithMeta(kv map[string]string) *Error {
	if e.Meta == nil {
		e.Meta = make(map[string]string, len(kv))
	}
	maps.Copy(e.Meta, kv)
	return e
}

func (e *Error) atGate(g Gate) *Error { e.Gate = g; return e }

// Constructors. Each pins the gate that can produce it, so the disclosure
// ladder cannot be bypassed by constructing an error at the wrong stage.
func Unauthenticatedf(f string, a ...any) *Error {
	// Branch inline rather than through a helper: passing the variadic slice to
	// another function forces it to escape, costing an allocation on the path
	// that actually formats. Measured, not assumed.
	if len(a) == 0 {
		return New(Unauthenticated, f).atGate(GateAuthn)
	}
	return New(Unauthenticated, fmt.Sprintf(f, a...)).atGate(GateAuthn)
}

func StepUpRequiredf(f string, a ...any) *Error {
	if len(a) == 0 {
		return New(StepUpRequired, f).atGate(GateAuthz)
	}
	return New(StepUpRequired, fmt.Sprintf(f, a...)).atGate(GateAuthz)
}

func AccessDeniedf(f string, a ...any) *Error {
	if len(a) == 0 {
		return New(AccessDenied, f).atGate(GateAuthz)
	}
	return New(AccessDenied, fmt.Sprintf(f, a...)).atGate(GateAuthz)
}

func PlanUpgradeRequiredf(f string, a ...any) *Error {
	if len(a) == 0 {
		return New(PlanUpgradeRequired, f).atGate(GateEntitlement)
	}
	return New(PlanUpgradeRequired, fmt.Sprintf(f, a...)).atGate(GateEntitlement)
}

func QuotaExceededf(f string, a ...any) *Error {
	if len(a) == 0 {
		return New(QuotaExceeded, f).atGate(GateEntitlement)
	}
	return New(QuotaExceeded, fmt.Sprintf(f, a...)).atGate(GateEntitlement)
}

func OrgSuspendedf(f string, a ...any) *Error {
	if len(a) == 0 {
		return New(OrgSuspended, f).atGate(GateSubscription)
	}
	return New(OrgSuspended, fmt.Sprintf(f, a...)).atGate(GateSubscription)
}

func NotFoundf(f string, a ...any) *Error {
	if len(a) == 0 {
		return New(NotFound, f).atGate(GateHandler)
	}
	return New(NotFound, fmt.Sprintf(f, a...)).atGate(GateHandler)
}

func Conflictf(f string, a ...any) *Error {
	if len(a) == 0 {
		return New(Conflict, f).atGate(GateHandler)
	}
	return New(Conflict, fmt.Sprintf(f, a...)).atGate(GateHandler)
}

func ValidationFailedf(f string, a ...any) *Error {
	if len(a) == 0 {
		return New(ValidationFailed, f).atGate(GateHandler)
	}
	return New(ValidationFailed, fmt.Sprintf(f, a...)).atGate(GateHandler)
}

func RateLimitedf(f string, a ...any) *Error {
	if len(a) == 0 {
		return New(RateLimited, f).atGate(GateAuthn)
	}
	return New(RateLimited, fmt.Sprintf(f, a...)).atGate(GateAuthn)
}

func Internalf(f string, a ...any) *Error {
	if len(a) == 0 {
		return New(Internal, f).atGate(GateHandler)
	}
	return New(Internal, fmt.Sprintf(f, a...)).atGate(GateHandler)
}

// Disclose applies the ADR-036 ladder.
//
// parentVisible answers "can this principal see the resource's parent?" — it is
// only consulted for an authorization failure, and only on the denial path.
//
//   - failure below the authz gate            → NOT_FOUND, always
//   - authz failure, parent NOT visible       → NOT_FOUND (existence is hidden)
//   - authz failure, parent visible           → the specific reason
//   - failure at or above subscription        → the specific reason
func Disclose(err *Error, parentVisible bool) *Error {
	if err == nil {
		return nil
	}
	if !err.Gate.DisclosesDetail() {
		return hide(err)
	}
	if err.Gate == GateAuthz && !parentVisible {
		return hide(err)
	}
	return err
}

// hide collapses an error into an indistinguishable NOT_FOUND, preserving the
// cause for server-side logs but discarding metadata that could leak existence.
func hide(err *Error) *Error {
	return (&Error{
		Reason:  NotFound,
		Message: "not found",
		Gate:    err.Gate,
	}).Wrap(err)
}

// As extracts a *Error from any error, reporting whether one was present.
//
// The type assertion is a fast path: errors.As walks the chain reflectively,
// and the common case is an error we constructed ourselves one frame earlier.
func As(err error) (*Error, bool) {
	// nolint:errorlint // Deliberate fast path, not a substitute for errors.As:
	// the reflective walk below still runs for wrapped errors. Worth 54ns -> 2.7ns
	// on the hottest classification call in the system (ADR-038).
	if e, ok := err.(*Error); ok { //nolint:errorlint
		return e, true
	}
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

// ReasonOf returns the Reason of err, or INTERNAL if it is not a domain error.
// An unrecognised error is always INTERNAL — never leak an unclassified failure
// to a client with a specific-looking code.
func ReasonOf(err error) Reason {
	if e, ok := As(err); ok {
		return e.Reason
	}
	return Internal
}

// ---------------------------------------------------------------------------
// Published catalogue
//
// Clients branch on Reason — PLAN_UPGRADE_REQUIRED and ACCESS_DENIED drive
// completely different UI. If the codes are not published, every client
// hardcodes strings scraped out of live responses. So the catalogue is
// generated from this table into the API documentation, and a test asserts
// that every declared Reason appears here (CONVENTIONS §7.1).
// ---------------------------------------------------------------------------

// Doc describes one Reason for the published API documentation.
type Doc struct {
	Reason       Reason
	ConnectCode  string
	HTTPStatus   int
	Meaning      string
	ClientShould string
	Retryable    bool
}

// Catalogue is the published error contract, in disclosure-ladder order.
func Catalogue() []Doc {
	return []Doc{
		{Unauthenticated, "unauthenticated", 401,
			"No session, or the access token is invalid or expired.",
			"Refresh the token; if that fails, sign in again.", true},
		{StepUpRequired, "permission_denied", 403,
			"The session is authenticated but below the assurance level this operation requires.",
			"Prompt for step-up (MFA or passkey), then retry.", true},
		{AccessDenied, "permission_denied", 403,
			"Authenticated and visible, but this principal lacks the required relation.",
			"Ask a workspace or organization admin for access. Do NOT offer an upgrade.", false},
		{PlanUpgradeRequired, "failed_precondition", 412,
			"The capability is not included in the organization's current plan.",
			"Offer an upgrade. Do NOT tell the user to ask an admin.", false},
		{QuotaExceeded, "failed_precondition", 412,
			"A plan limit has been reached — seats, workspaces, or a metered dimension.",
			"Show what is exhausted and offer to reduce usage or upgrade.", false},
		{OrgSuspended, "failed_precondition", 412,
			"The organization's subscription is suspended, so writes are blocked.",
			"Direct the owner to billing. Reads, billing and export remain available.", false},
		{NotFound, "not_found", 404,
			"The resource does not exist, or the caller may not learn that it does.",
			"Treat as absent. This response is deliberately indistinguishable from a cross-tenant denial.", false},
		{Conflict, "aborted", 409,
			"Optimistic concurrency: the resource changed between read and write.",
			"Re-read and retry. Expected under concurrency, not an error condition.", true},
		{ValidationFailed, "invalid_argument", 400,
			"The request failed schema or domain validation.",
			"Fix the input; the metadata names the offending field.", false},
		{RateLimited, "resource_exhausted", 429,
			"Too many requests.",
			"Back off and retry with jitter.", true},
		{Internal, "internal", 500,
			"An unclassified server failure. Detail is deliberately withheld.",
			"Retry with backoff; report the trace id if it persists.", true},
	}
}

// ---------------------------------------------------------------------------
// Validation detail
//
// A validation failure must tell the frontend WHICH field failed and WHY, or
// the user is left hunting through a form for an unmarked error. "Invalid
// request" is not an error message; it is an apology.
// ---------------------------------------------------------------------------

// Violation is one field-level validation failure, shaped for direct rendering
// beside a form control.
type Violation struct {
	// Field is the request path, e.g. "member.email" or "items[2].quantity".
	// Dotted and indexed so a client can map it to a control without parsing.
	Field string
	// Constraint is the machine-readable rule that failed, e.g. "required",
	// "email", "max_len". Clients localise on this, never on Message.
	Constraint string
	// Message is a human-readable fallback in the server's default locale.
	Message string
}

// ValidationError carries per-field violations alongside the reason.
//
// Err is a named field, not an embedded *Error: embedding would name the field
// "Error", which shadows the promoted Error() method and quietly stops the type
// satisfying the error interface.
type ValidationError struct {
	Err        *Error
	Violations []Violation
}

func (v *ValidationError) Error() string { return v.Err.Error() }
func (v *ValidationError) Unwrap() error { return v.Err }

// Invalid builds a validation failure from field violations. The summary
// message names how many fields failed; the detail says which.
func Invalid(violations ...Violation) *ValidationError {
	e := New(ValidationFailed, validationSummary(violations)).atGate(GateHandler)
	return &ValidationError{Err: e, Violations: violations}
}

func validationSummary(v []Violation) string {
	switch len(v) {
	case 0:
		return "the request is not valid"
	case 1:
		return "1 field is not valid: " + v[0].Field
	default:
		return fmt.Sprintf("%d fields are not valid", len(v))
	}
}

// Violations extracts field-level detail from err, if it carries any.
func Violations(err error) ([]Violation, bool) {
	var v *ValidationError
	if errors.As(err, &v) && len(v.Violations) > 0 {
		return v.Violations, true
	}
	return nil, false
}
