// Package app is the operator plane's use cases.
//
// Every port here is declared by this package and implemented by an adapter, in
// the direction ADR-001 requires. The ports are narrow on purpose: an operator
// use case that could reach an arbitrary store is one that could reach a tenant
// table, and "it does not, today" is not the guarantee this plane needs.
package app

import (
	"context"
	"errors"
	"time"

	"github.com/chronos/chronos-go/internal/operator/contract"
	"github.com/chronos/chronos-go/internal/operator/domain"
)

// Errors the use cases return. Each is mapped to a wire error by the API layer.
var (
	// ErrNotAnOperator means the IdP authenticated somebody who has no operator
	// account, or whose account is disabled.
	//
	// ONE error for both, deliberately. Distinguishing them would tell whoever
	// completed the SSO step whether a named colleague is or was an operator,
	// and "who works on the back office" is not a question a successful
	// Workspace login should answer.
	ErrNotAnOperator = errors.New("operator: this identity has no usable operator account")

	// ErrCeremonyRefused means a sign-in step did not verify. Deliberately one
	// error for every cause, for the reason the WebAuthn adapter gives: naming
	// the failed check tells an attacker which one to work on.
	ErrCeremonyRefused = errors.New("operator: this sign-in could not be completed")

	// ErrSessionRefused means the presented bearer is absent, expired, ended,
	// at the wrong stage, or belongs to a disabled operator.
	ErrSessionRefused = errors.New("operator: this session is not usable")

	// ErrForbidden means the operator's role does not hold the capability the
	// method declares.
	ErrForbidden = errors.New("operator: this role does not permit that")

	// ErrNoSuchCustomer means the org is not in the directory.
	ErrNoSuchCustomer = errors.New("operator: no such customer")
)

// Stage is how far a session has got through sign-in.
type Stage string

const (
	// StageSSOOnly has passed the IdP and not the authenticator. It may call
	// the WebAuthn pair and nothing else.
	StageSSOOnly Stage = "sso_only"

	// StageLive has passed both.
	StageLive Stage = "live"
)

// OperatorRecord is one row of operator_account.
type OperatorRecord struct {
	OperatorID      string
	SubjectID       string
	Issuer          string
	ProviderSubject string
	Role            contract.Role
	DisabledAt      *time.Time
	ProvisionedAt   time.Time
}

// Disabled reports whether this operator has been offboarded.
func (r OperatorRecord) Disabled() bool { return r.DisabledAt != nil }

// Accounts reads operator_account.
//
// Read-only. The projection writes it, and a use case that could write it would
// be a use case that could grant itself a role without an event.
type Accounts interface {
	// ByBinding resolves an operator from what the IdP asserted. Returns
	// ErrNotAnOperator when there is no such account.
	ByBinding(ctx context.Context, issuer, providerSubject string) (OperatorRecord, error)

	// ByID resolves an operator by their own id.
	ByID(ctx context.Context, operatorID string) (OperatorRecord, error)

	// All lists every operator, oldest first.
	All(ctx context.Context, includeDisabled bool) ([]OperatorRecord, error)
}

// StoredCredential is one operator authenticator, as the database holds it.
type StoredCredential struct {
	ID             string
	PublicKey      []byte
	SignCount      uint32
	AAGUID         []byte
	Transports     []string
	BackupEligible bool
	BackupState    bool
}

// NewCredential is an enrolment about to be stored.
type NewCredential struct {
	ID             string
	OperatorID     string
	PublicKey      []byte
	SignCount      uint32
	AAGUID         []byte
	Transports     []string
	BackupEligible bool
	BackupState    bool
	Label          string
}

// Credentials is operator_credential — authoritative, not a projection.
type Credentials interface {
	List(ctx context.Context, operatorID string) ([]StoredCredential, error)
	Count(ctx context.Context, operatorID string) (int64, error)

	// Get resolves one credential across EVERY operator, which is what makes
	// the discoverable path work: the authenticator names the credential and
	// the server learns who is signing in from the row.
	Get(ctx context.Context, credentialID string) (StoredCredential, string, error)

	// Insert stores a new enrolment. It must fail rather than replace on a
	// duplicate credential id — WebAuthn L3 §7.1 step 27.
	Insert(ctx context.Context, c NewCredential) error

	// Advance moves the signature counter forward atomically and reports
	// whether it moved. False means the presented counter did not exceed the
	// stored one, which is the clone signal.
	Advance(ctx context.Context, credentialID string, to uint32) (bool, error)

	// Touch records use without moving the counter, for the authenticators that
	// report 0 permanently. Every synced passkey does.
	Touch(ctx context.Context, credentialID string) error

	// FlagClone records a counter regression.
	FlagClone(ctx context.Context, credentialID string) error
}

// SessionRecord is a resolved bearer.
type SessionRecord struct {
	SessionID    string
	OperatorID   string
	SubjectID    string
	Role         contract.Role
	Stage        Stage
	ExpiresAt    time.Time
	CredentialID string

	// Elevation is the break-glass grant on THIS session, if any.
	//
	// Its zero value grants nothing, so a session read that failed to populate
	// it, a store that does not set it, and an expired window all produce the
	// same answer — denial. That is the same construction `authz.Decision` uses
	// and the reason it is a value rather than a pointer.
	Elevation domain.Elevation
}

// NewSession is a session about to be stored.
type NewSession struct {
	Digest       []byte
	SessionID    string
	OperatorID   string
	Stage        Stage
	ExpiresAt    time.Time
	FromIP       string
	CredentialID string
}

// ExpiredElevation is a break-glass window that has closed and whose expiry has
// not yet been recorded in the log.
type ExpiredElevation struct {
	SessionID  string
	OperatorID string
	SubjectID  string
	Capability string
	ExpiredAt  time.Time

	// Used reports whether the capability was actually exercised. An elevation
	// nobody used is a false alarm, and telling it apart from one that was
	// needed is the difference between an alert people act on and one they mute.
	Used bool
}

// Sessions is operator_session — authoritative, like the tenant plane's
// session_token.
type Sessions interface {
	Issue(ctx context.Context, s NewSession) error

	// Elevate grants a break-glass on one session and reports whether it took.
	//
	// FALSE means a live elevation already stands, which is refused rather than
	// replaced: replacing would let an operator chain windows into an unbounded
	// grant while every individual event looked correctly time-boxed.
	Elevate(ctx context.Context, digest []byte, e domain.Elevation, now time.Time) (bool, error)

	// MarkElevationUsed records the FIRST exercise of an elevated capability.
	MarkElevationUsed(ctx context.Context, digest []byte, now time.Time) error

	// ExpiredElevations lists windows whose expiry is not yet in the log.
	ExpiredElevations(ctx context.Context, before time.Time, limit int32) ([]ExpiredElevation, error)

	// MarkElevationExpiryRecorded is the sweep's idempotency: an expiry already
	// appended is not appended again.
	MarkElevationExpiryRecorded(ctx context.Context, sessionID string, now time.Time) error

	// Resolve returns the session behind a token digest, or ErrSessionRefused.
	// It must refuse an expired session, an ended one, and one belonging to a
	// disabled operator — the last is what makes offboarding immediate.
	Resolve(ctx context.Context, digest []byte, now time.Time) (SessionRecord, error)

	// End marks a session over and reports whether this call changed anything.
	End(ctx context.Context, digest []byte, now time.Time) (bool, error)

	// EndAllFor ends every live session an operator holds and reports how many.
	//
	// The count is the verification operator.md §3 asks for: an offboarding that
	// ended no sessions while the person was signed in did not take effect.
	EndAllFor(ctx context.Context, operatorID string, now time.Time) (int64, error)
}

// CeremonyKind separates the three ceremonies a sign-in can be in.
type CeremonyKind string

// The three kinds. Each has its own consume, so a WebAuthn ceremony cannot be
// redeemed as an OIDC one.
const (
	CeremonyOIDC          CeremonyKind = "oidc"
	CeremonyWebAuthnLogin CeremonyKind = "webauthn_login"
	CeremonyWebAuthnEnrol CeremonyKind = "webauthn_enrol"
)

// Ceremonies is operator_ceremony — short-lived, single-use state.
type Ceremonies interface {
	Store(ctx context.Context, id string, kind CeremonyKind, operatorID string,
		payload []byte, expiresAt time.Time) error

	// Consume redeems a ceremony exactly once. A second call for the same id
	// must fail, and the atomicity has to be the database's rather than the
	// caller's.
	Consume(ctx context.Context, id string, kind CeremonyKind, now time.Time) (
		operatorID string, payload []byte, err error)
}

// AuditEntry is one recorded action, as the projection stores it.
type AuditEntry struct {
	EntryID         string
	OperatorID      string
	SubjectID       string
	Action          string
	Method          string
	OrgID           string
	TargetSubjectID string
	Fields          []string
	Reason          string
	FromIP          string
	OccurredAt      time.Time
}

// EventAppender appends one operator event to its own stream.
//
// Deliberately not a repository per aggregate: the operator plane's writes are
// few and each is a single-event append, so a port shaped like the thing it
// does keeps the adapter small and the use cases readable.
type EventAppender interface {
	// AppendAudit appends one audit event under a stream named by the entry id.
	AppendAudit(ctx context.Context, entryID string, ev any) error

	// AppendOperator appends to an operator's own stream, under the optimistic
	// precondition implied by the version it was loaded at.
	AppendOperator(ctx context.Context, operatorID string, ev any) error
}

// Customer is one row of operator_customer_list.
type Customer struct {
	OrgID              string
	Slug               string
	OrgName            string
	LifecycleState     string
	PlanID             string
	PlanVersionID      string
	SubscriptionStatus string
	TrialEndsAt        *time.Time
	WorkspaceCount     int32
	MemberCount        int32
	LastActiveAt       *time.Time
	SignupSource       string
	SuspendedAt        *time.Time
	SuspensionReason   string

	// OwnerSubjectID is the organization owner's pseudonym — the one person
	// operator.md §2 admits, and the only thing in this struct that can be
	// handed to RevealPersonalData. It resolves to nothing on its own.
	OwnerSubjectID string

	CreatedAt time.Time
}

// CustomerPage is one page of the directory, with the cursor for the next.
type CustomerPage struct {
	Customers     []Customer
	NextPageToken string
}

// Directory reads operator_customer_list.
//
// Read-only from the use cases. The projection writes it.
type Directory interface {
	List(ctx context.Context, query, lifecycleState, pageToken string, limit int32) (CustomerPage, error)
	Get(ctx context.Context, orgID string) (Customer, error)
}

// VaultReader resolves a subject's fields, and is the ONLY path from this plane
// to a person's data.
//
// Narrow on purpose: it takes one subject and a bounded field list, so there is
// no shape of call that returns a page of addresses. operator.md §4 — "never
// bulk-joined into a list view" — is a property of this signature rather than
// of the callers' restraint.
type VaultReader interface {
	Resolve(ctx context.Context, subjectID string, fields []string) (map[string]string, error)
}

// Clock is the time source. Injected so a test can move it.
type Clock interface{ Now() time.Time }
