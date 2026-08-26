// Package contract is the operator plane's event surface (operator.md §8).
//
// # Why reads are events here, and nowhere else
//
// Everywhere else in this system a read is a read: it touches no aggregate, it
// appends nothing, and the only trace it leaves is a log line that ages out.
// The operator plane inverts that, because under GDPR looking IS processing.
// An employee opening a customer's billing page is a processing activity
// performed on that customer's data, and the tenant is entitled to be shown
// that it happened.
//
// A log line cannot serve that purpose. Logs are sampled, rotated, and
// writable by whoever holds the node; an audit record that an operator could
// quietly drop is not an audit record. So the operator plane's reads append to
// the event log, which is append-only and inherits ADR-013's tamper-evidence,
// and the projection that answers "who looked at us" is built from those
// events like any other read model.
//
// # No personal data, including the operator's own
//
// ADR-002 applies to this stream exactly as it does to every other, and it
// applies in BOTH directions. The tenant side is obvious — an audit entry names
// `org_id` and `SubjectID`, never an address. The operator side is the one
// that is easy to get wrong: an operator is a natural person too, their work
// address is personal data, and operator.md §5 requires audit records to be
// retained beyond their employment. An audit log holding employee emails
// forever is a retention problem wearing an audit badge.
//
// So an operator is identified in every event by `OperatorID` and by the vault
// pseudonym `SubjectID`. Erasure destroys the key and the record survives as a
// non-identifying fact: "operator opr_… viewed billing for org_… at T" stays
// true and provable while the person is no longer identifiable from it.
package contract

import "time"

// Role is what an operator may do (operator.md §3).
//
// A string rather than an integer because it is stored in events: a numeric
// rank would make INSERTING a role between two existing ones a rewrite of
// history, and the ordering is a property of the code rather than of the
// recorded fact.
type Role string

// The four roles, least privilege first. Every one of these strings is
// permanent — it appears in stored events.
const (
	// RoleSupport is read-only: the customer list, status, payment state.
	RoleSupport Role = "support"

	// RoleBillingOps adds refunds, coupons and subscription repair.
	RoleBillingOps Role = "billing_ops"

	// RoleCatalogueAdmin adds plan versions and subscriber migrations.
	RoleCatalogueAdmin Role = "catalogue_admin"

	// RoleOperatorAdmin adds operator account management — the role that can
	// grant roles, which is why every change to it is itself an audited event.
	RoleOperatorAdmin Role = "operator_admin"
)

// OperatorProvisioned records that an employee gained access to this plane.
//
// # The IdP binding is here, and the address is not
//
// Sign-in is SSO-only (operator.md §3), so what identifies an operator to the
// system is their provider identity: the issuer, and the provider's immutable
// subject. Neither is an address, and that distinction is the same one
// identity.md §7 rule 5 draws for tenants — an identifier that can change is
// not an identity, and matching on the address is the takeover the rule exists
// to prevent.
//
// The employee's actual address lives in the vault under SubjectID, resolved at
// display time by the same path that resolves a tenant's.
type OperatorProvisioned struct {
	OperatorID string

	// SubjectID is the vault pseudonym for this employee. Every later event
	// about them carries it, and erasure on it is what makes the retained audit
	// trail non-identifying.
	SubjectID string

	// Issuer is the operator IdP's issuer URL. Recorded per operator rather
	// than assumed global because it is what a future second IdP would vary,
	// and an event that assumed one issuer would have to be upcast to admit a
	// second.
	Issuer string

	// ProviderSubject is the IdP's own immutable identifier for the employee —
	// `sub` for a Google Workspace account.
	ProviderSubject string

	Role Role

	// ProvisionedBy is the OperatorID of whoever granted this access, empty for
	// the FIRST operator, which no operator can have provisioned. That bootstrap
	// case is the one an auditor will ask about, so it is visible as an empty
	// field rather than hidden behind a synthetic "system" actor.
	ProvisionedBy string

	ProvisionedAt time.Time
}

func (*OperatorProvisioned) EventType() string { return "operator.OperatorProvisioned.v1" }

// OperatorRoleChanged records a privilege change (operator.md §3).
//
// Both the old and the new role are carried. The old one is derivable by
// replaying the stream, and carrying it anyway is deliberate: the question an
// audit asks is "was this an escalation", and answering it from a single record
// rather than from a fold is what makes the alert on escalation cheap enough to
// actually run.
type OperatorRoleChanged struct {
	OperatorID string
	SubjectID  string

	PreviousRole Role
	NewRole      Role

	// ChangedBy is the operator_admin who made the change. Never empty: the
	// bootstrap exemption exists for provisioning only, and a role change with
	// no actor is the shape of a change nobody made.
	ChangedBy string

	ChangedAt time.Time
}

func (*OperatorRoleChanged) EventType() string { return "operator.OperatorRoleChanged.v1" }

// OperatorDisabled records offboarding (operator.md §3).
//
// "Offboarding is immediate and verified — an operator account outliving
// employment is a breach waiting to happen." Immediate means the projection
// that authenticates a session reads this, so the operator's live sessions stop
// working as the event projects rather than when they expire.
//
// It is not erasure and not deletion: the account stays in the stream and the
// audit entries keep pointing at it, because "who did this" must still have an
// answer after the person leaves.
type OperatorDisabled struct {
	OperatorID string
	SubjectID  string

	// DisabledBy is the operator_admin who offboarded them, or empty when the
	// disable came from an automated offboarding feed rather than from a
	// person.
	DisabledBy string

	DisabledAt time.Time
}

func (*OperatorDisabled) EventType() string { return "operator.OperatorDisabled.v1" }

// OperatorSignedIn records a completed sign-in — BOTH factors.
//
// It is appended after the WebAuthn assertion, never after the SSO step. A
// sign-in event emitted at the SSO step would record as "signed in" a session
// that cannot yet call anything, and the alerting built on this stream would
// then fire on half-completed logins and be turned off within a week.
type OperatorSignedIn struct {
	OperatorID string
	SubjectID  string

	SessionID string

	// CredentialID is the WebAuthn credential that completed the sign-in. An
	// operator with several authenticators leaves a different value here per
	// device, which is what makes "signed in from a credential we have not seen
	// before" answerable.
	CredentialID string

	// FromIP is the address the sign-in came from, kept because operator access
	// is IP-restricted to internal ranges (operator.md §3) and an entry with no
	// origin cannot evidence that the restriction held.
	//
	// It is personal data about the employee in the strict reading, and it is
	// retained anyway on the security basis that operator.md §5 already names
	// for anomaly detection. That is a deliberate exception, recorded here so it
	// is visible rather than assumed.
	FromIP string

	SignedInAt time.Time
}

func (*OperatorSignedIn) EventType() string { return "operator.OperatorSignedIn.v1" }

// OperatorViewedCustomer records a READ of one tenant's operator-plane record.
//
// This is the event that makes operator.md §5 real. It carries no field list
// and no result: what was returned is determined by the projection's schema,
// which minimisation already bounds (§4), so recording the payload would be
// copying tenant data into a second permanent store to prove we had looked at
// it once.
type OperatorViewedCustomer struct {
	OperatorID string
	SubjectID  string

	// OrgID is the tenant looked at. Present on the drill-in; EMPTY on a list
	// view, which is why the field is not required — a list is an org-level
	// aggregate over many tenants and naming one of them would be a lie.
	OrgID string

	// Method is the RPC's full name. The audit's unit is the action, and the
	// action is the method that was called.
	Method string

	FromIP string

	ViewedAt time.Time
}

func (*OperatorViewedCustomer) EventType() string { return "operator.OperatorViewedCustomer.v1" }

// OperatorViewedPersonalData records a vault read, and it is the one event in
// this package that carries a REASON.
//
// # Why this one is separate from OperatorViewedCustomer
//
// Because the two are different processing activities with different legal
// footing, and collapsing them would make the more sensitive one invisible.
// Reading `operator_customer_list` returns aggregates that name no person.
// Resolving a SubjectID through the vault returns an address belonging to a
// named individual, and operator.md §4 permits it "only on explicit, justified
// access".
//
// # Why the justification is stored, when nothing else free-text is
//
// ADR-002 keeps free text out of the log because it is where personal data
// hides. The exception is deliberate and narrow: the justification is what
// makes the access lawful, so a record of the access without it would document
// that a rule was followed while omitting the only evidence that it was. The
// text is written by an employee about a support task, and the RPC bounds it —
// but the honest statement is that this field is the one place an operator
// could type something they should not, and the projection is therefore in
// scope for the same review as any other free-text store.
type OperatorViewedPersonalData struct {
	OperatorID string
	SubjectID  string

	// TargetSubjectID is the person whose data was resolved — a pseudonym, so
	// this event stays non-identifying after their erasure exactly as the rest
	// do.
	TargetSubjectID string

	// OrgID is the tenant the access was performed in the context of, which is
	// what lets the tenant be shown their own operator-access history.
	OrgID string

	// Fields names which vault fields were resolved, so "they looked up an
	// address" and "they read everything held about the person" are
	// distinguishable. Field NAMES only — never values.
	Fields []string

	// Reason is the operator's recorded justification. Mandatory: the use case
	// refuses the call without one rather than substituting a default, because
	// a default justification is an audit trail that says nothing.
	Reason string

	Method string

	FromIP string

	ViewedAt time.Time
}

func (*OperatorViewedPersonalData) EventType() string {
	return "operator.OperatorViewedPersonalData.v1"
}

// ---------------------------------------------------------------------------
// Two events operator.md §8 does not list, and why they are here anyway
//
// §8 enumerates thirteen events. Neither of the two below is among them, and
// adding to a spec's list is a decision that should be visible rather than
// discovered later in a diff.
//
// Both exist because §3 states a requirement that §8's list cannot express.
// "SSO-only with mandatory hardware-backed MFA (WebAuthn)" needs an operator to
// HAVE a WebAuthn credential, and nothing in the thirteen records one being
// enrolled — so a build with only those events would either store credentials
// outside the log, which makes "which authenticator did this employee register,
// and when" unanswerable, or invent a back-channel, which operator.md §7
// explicitly forbids for writes.
//
// "Sessions are short and non-extendable" needs an end, and expiry alone is not
// one: an operator who realises they are on a shared machine must be able to
// end the session NOW, and a session that can only time out makes the safe
// action unavailable for as long as its remaining life.
// ---------------------------------------------------------------------------

// OperatorCredentialEnrolled records that an operator registered an
// authenticator.
//
// # Enrolment is bootstrapped, and the window is narrow
//
// A freshly provisioned operator has passed SSO and holds no credential, so the
// second factor they must present is one they cannot yet have. That is the same
// deadlock `bootstrap_min_aal` resolves on the tenant plane, resolved the same
// way and with the same three properties: the condition is a fact read
// server-side (this operator has zero credentials), it is one-way (enrolling
// the first closes the window and losing every credential does NOT re-open it —
// recovery is an operator_admin re-provisioning, which is an audited act by a
// second person), and it is refused outright for a disabled operator.
//
// The one-way property is the part that matters. Re-opening on zero credentials
// would mean an attacker who can delete an operator's authenticators can then
// enrol their own, which turns credential loss into account takeover.
type OperatorCredentialEnrolled struct {
	OperatorID string
	SubjectID  string

	// CredentialID is the WebAuthn credential id, base64url. Not personal data:
	// it is an opaque handle minted by the authenticator.
	CredentialID string

	// AAGUID identifies the authenticator MODEL, not the device. Recorded
	// because operator.md §3 requires HARDWARE-backed MFA, and the model is
	// what a policy asserting that would have to be written against.
	AAGUID string

	// BackupEligible reports whether the credential is SYNCABLE — a passkey
	// that leaves the hardware it was created on. Recorded rather than refused
	// here: the refusal, if we make one, belongs in a policy that can be
	// tightened without rewriting history, and the fact has to be in the log
	// before any such policy can be evidenced.
	BackupEligible bool

	EnrolledAt time.Time
}

func (*OperatorCredentialEnrolled) EventType() string {
	return "operator.OperatorCredentialEnrolled.v1"
}

// OperatorSignedOut records a deliberately ended session.
//
// Distinct from expiry, which appends nothing: an expired session is a fact
// about the clock and is derivable from the sign-in, whereas a sign-out is an
// action somebody took and belongs in the trail beside the sign-in it ends.
type OperatorSignedOut struct {
	OperatorID string
	SubjectID  string

	SessionID string

	SignedOutAt time.Time
}

func (*OperatorSignedOut) EventType() string { return "operator.OperatorSignedOut.v1" }

// ---------------------------------------------------------------------------
// Break-glass elevation (operator.md §5)
// ---------------------------------------------------------------------------

// OperatorElevated records that an operator took a capability their role does
// not hold.
//
// # What elevation is for, and what it is not
//
// It is not a convenience for a role that was scoped too tightly — that is a
// role change, and it goes through OperatorRoleChanged where a second person
// grants it. Elevation is for the case where the right answer is "yes, once,
// now, and everybody should know": an incident at 3am, a customer on the phone,
// a support engineer who needs one action they normally must not take.
//
// So it carries a deadline and a justification, and neither is optional. An
// elevation with no deadline is a role change nobody reviewed; one with no
// justification is a role change nobody can audit.
type OperatorElevated struct {
	OperatorID string
	SubjectID  string

	// SessionID scopes the elevation to ONE session, not to the operator.
	//
	// That is the difference between "this person may do X for ten minutes" and
	// "this browser tab may". An operator holding two sessions elevates one of
	// them, and a stolen bearer from the other is unaffected — which matters
	// because elevation is exactly when the stakes are highest.
	SessionID string

	// Capability is the single capability granted. One, never a set: an
	// elevation that granted several would be a role change with a timer, and
	// the audit entry would not say which of them the operator actually needed.
	Capability string

	// Reason is the recorded justification. Mandatory, and stored verbatim for
	// the same reason OperatorViewedPersonalData's is — it is the evidence that
	// makes the act reviewable, and a record of a break-glass with no account
	// of why is a record that says only that somebody broke the glass.
	Reason string

	ElevatedAt time.Time

	// ExpiresAt is minutes away, not hours (operator.md §5). It is ABSOLUTE and
	// nothing extends it: a second elevation is a second event, with its own
	// justification and its own alert, which is the point.
	ExpiresAt time.Time
}

func (*OperatorElevated) EventType() string { return "operator.OperatorElevated.v1" }

// OperatorElevationExpired records that a break-glass window closed.
//
// # Why expiry is an EVENT when it is derivable from a timestamp
//
// Because "did anything happen while the glass was broken" is the question an
// incident review asks, and answering it from a deadline alone means computing
// which actions fell inside a window nobody recorded closing. A pair of events
// bounds the window explicitly.
//
// It is appended by a SWEEP rather than by a timer per elevation, and the
// distinction is ADR-045's: a timer that fires is a promise, and a promise that
// is lost when a process restarts leaves the log claiming a window is still
// open. The sweep is idempotent and finds what the timers missed.
//
// It does NOT gate anything. Whether an elevation is live is decided by
// comparing the deadline in SQL, so a sweep that is late costs an audit record
// its punctuality and never grants a capability past its window — the failure
// mode ADR-045 names for revocation tombstones, avoided the same way.
type OperatorElevationExpired struct {
	OperatorID string
	SubjectID  string
	SessionID  string

	Capability string

	// Used reports whether the capability was actually exercised before the
	// window closed. An elevation nobody used is a false alarm worth seeing as
	// distinct from one that was needed.
	Used bool

	ExpiredAt time.Time
}

func (*OperatorElevationExpired) EventType() string {
	return "operator.OperatorElevationExpired.v1"
}

// OperatorAccessManaged records a change to who may use this plane.
//
// # It is an AUDIT event, and it duplicates a domain event on purpose
//
// Provisioning, a role change and an offboarding each already append their own
// event to the operator's stream. This adds a fourth, on the audit stream,
// naming the same act.
//
// The duplication earns its place because the two answer different questions.
// The operator's stream answers "what happened to this person's access", folded
// per operator. The audit log answers "who changed access, and when", indexed
// by ACTOR and by time — and the actor is what the domain events carry as a
// field rather than as a key, so answering it from them means scanning every
// operator's stream.
//
// It is also what keeps the audit rule absolute. Every method on this plane
// records an entry; a management RPC that recorded only a domain event would be
// the exception, and an audit trail with one exception has as many as somebody
// later argues for.
type OperatorAccessManaged struct {
	OperatorID string
	SubjectID  string

	// TargetOperatorID is whose access changed. EMPTY on a list, which changes
	// nobody's — the same shape OperatorViewedCustomer uses for a page.
	TargetOperatorID string

	// Change is what was done, in words: "provisioned support", "role changed
	// to billing_ops", "offboarded", "listed operators".
	//
	// A rendered string rather than a discriminated union, because this record
	// exists to be READ by a person reviewing access changes — and the
	// machine-readable form is the domain event on the operator's own stream,
	// which is where anything computing on it should look.
	Change string

	FromIP string

	ManagedAt time.Time
}

func (*OperatorAccessManaged) EventType() string { return "operator.OperatorAccessManaged.v1" }

// OperatorChangedTenant records an operator write against a tenant
// (operator.md §7).
//
// # It is the AUDIT record, not the change
//
// The change itself is a tenant event on the tenant's own stream, appended
// through the tenant's own aggregate — §7 is explicit that "operator writes go
// through the same domain commands as everything else" and that "there is no
// privileged back-channel that skips domain rules".
//
// So this does not duplicate the change. It records WHO made it and WHY, which
// the tenant's event deliberately does not carry: `OrganizationSuspended` names
// a closed-enum reason because it is read by a template that mails every member
// of the organization, and the operator's free-text justification has no
// business in that mail.
//
// The split means "you have been suspended" and "why did we suspend them" are
// answered in two places with two audiences and two access controls, which is
// the correct shape for both.
type OperatorChangedTenant struct {
	OperatorID string
	SubjectID  string

	// OrgID is the tenant that was changed, when the change was scoped to an
	// organization — a suspension, a reinstatement.
	OrgID string

	// TargetSubjectID is the person the change was about, when it was scoped to
	// a SUBJECT rather than to an organization — a legal hold.
	//
	// Exactly one of OrgID and TargetSubjectID is set, and the domain enforces
	// it: a change scoped to neither names nobody, and one scoped to both is two
	// changes wearing one record.
	TargetSubjectID string

	// Change is what was done: "suspended", "reinstated". A closed vocabulary
	// in practice, kept as a string for the same reason
	// OperatorAccessManaged.Change is — the machine-readable form is the tenant
	// event, and this exists to be read by a person.
	Change string

	// Reason is the operator's justification, verbatim and MANDATORY.
	//
	// It is the whole point of this event. The tenant's own event carries an
	// enum; this carries the sentence somebody will be asked to defend.
	Reason string

	FromIP string

	ChangedAt time.Time
}

func (*OperatorChangedTenant) EventType() string { return "operator.OperatorChangedTenant.v1" }
