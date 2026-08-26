package app

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/operator/contract"
	"github.com/chronos/chronos-go/internal/operator/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// Errors the operator-management use case returns.
var (
	// ErrNoSuchOperator means the id names nobody.
	//
	// Distinguishable from ErrNotAnOperator on purpose, unlike the sign-in
	// path's deliberate conflation: the caller here is an authenticated
	// operator_admin managing staff, and telling them an id does not exist is
	// how they find their typo. The sign-in path's ambiguity protects against
	// somebody learning who works here; this one has already passed that.
	ErrNoSuchOperator = errors.New("operator: no such operator")

	// ErrOperatorExists means that IdP identity already has an account.
	//
	// Refused rather than treated as an update. Provisioning carries a ROLE, so
	// honouring a repeat would make it a back-door role change that skips
	// OperatorRoleChanged — and the escalation would then be invisible to the
	// one query an audit runs.
	ErrOperatorExists = errors.New(
		"operator: that identity already has an operator account; change their role " +
			"rather than provisioning them again, so the change is recorded as one")

	// ErrSelfRoleChange means an operator named themselves in a role change.
	ErrSelfRoleChange = errors.New(
		"operator: an operator may not change their own role")
)

// Operators is operator account management (operator.md §3, §7).
type Operators struct {
	accounts Accounts
	sessions Sessions
	events   EventAppender
	auditor  *Auditor
	clock    Clock
	entropy  io.Reader
	log      *slog.Logger
}

// OperatorsDeps is what the use case needs.
type OperatorsDeps struct {
	Accounts Accounts
	Sessions Sessions
	Events   EventAppender
	Auditor  *Auditor
	Clock    Clock
	Entropy  io.Reader
	Log      *slog.Logger
}

// NewOperators builds the use case.
func NewOperators(d OperatorsDeps) (*Operators, error) {
	switch {
	case d.Accounts == nil || d.Sessions == nil:
		return nil, errors.New("operator: managing operators needs the account and session stores")
	case d.Events == nil || d.Auditor == nil:
		return nil, errors.New("operator: managing operators needs to record what happened")
	case d.Clock == nil:
		return nil, errors.New("operator: managing operators needs a clock")
	}
	entropy := d.Entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	return &Operators{
		accounts: d.Accounts, sessions: d.Sessions, events: d.Events,
		auditor: d.Auditor, clock: d.Clock, entropy: entropy, log: log,
	}, nil
}

// ProvisionResult names the operator that was created.
type ProvisionResult struct {
	OperatorID   string
	SubjectID    string
	AuditEntryID string
}

// Provision grants an employee access to this plane.
//
// # No address is taken, and that is the design
//
// The request carries an issuer, a provider subject and a role. It does not
// carry an email, because this plane holds no operator addresses — an operator
// is a pseudonym here so the audit trail survives their erasure, which is §5's
// own retention rule.
//
// `internal/tools/provisionoperator` optionally seeds the vault with one, for a
// display name, and it runs with credentials this plane deliberately lacks:
// chronos_operator holds SELECT on the vault and nothing more (migration
// 00038). So the asymmetry is enforced by the database rather than by this
// function's restraint.
func (o *Operators) Provision(
	ctx context.Context, actor Actor, issuer, providerSubject string, role contract.Role,
) (ProvisionResult, error) {
	if !domain.ValidRole(role) {
		return ProvisionResult{}, fmt.Errorf("operator: %q is not a role", role)
	}

	// The binding is UNIQUE in the schema, so this check is a courtesy that
	// turns a constraint violation into a message. The constraint is what
	// actually holds — two concurrent provisionings of one identity both pass
	// here and one of them fails at the insert, which is correct.
	switch _, err := o.accounts.ByBinding(ctx, issuer, providerSubject); {
	case err == nil:
		return ProvisionResult{}, ErrOperatorExists
	case !errors.Is(err, ErrNotAnOperator):
		return ProvisionResult{}, fmt.Errorf("checking for an existing operator: %w", err)
	}

	now := o.clock.Now()
	operatorID := ids.New[ids.Operator](now, o.entropy).String()
	subjectID := ids.New[ids.Subject](now, o.entropy).String()

	agg := eventsourcing.NewAggregate(domain.NewOperator)
	if err := agg.Provision(operatorID, subjectID, issuer, providerSubject,
		role, actor.OperatorID, now); err != nil {
		return ProvisionResult{}, err
	}

	entryID, err := o.auditor.RecordOperatorManaged(ctx, actor, operatorID,
		"provisioned "+string(role))
	if err != nil {
		return ProvisionResult{}, fmt.Errorf("recording the grant: %w", err)
	}

	if err := o.appendOne(ctx, operatorID, agg); err != nil {
		return ProvisionResult{}, err
	}

	o.log.WarnContext(ctx, "an operator was provisioned",
		"operator_id", operatorID, "role", role, "by", actor.OperatorID)

	return ProvisionResult{OperatorID: operatorID, SubjectID: subjectID, AuditEntryID: entryID}, nil
}

// ChangeRoleResult reports the state after a role change.
type ChangeRoleResult struct {
	Changed      bool
	AuditEntryID string
}

// ChangeRole moves an operator between roles.
//
// The self-check is in the AGGREGATE, not here, and this is the second caller
// that would have had to remember it. An operator_admin holds
// `manage_operators`, so nothing in the capability table stops them raising
// themselves — the aggregate is the only place that knows the actor and the
// target are the same person.
func (o *Operators) ChangeRole(
	ctx context.Context, actor Actor, operatorID string, role contract.Role,
) (ChangeRoleResult, error) {
	if operatorID == actor.OperatorID {
		// Refused here as well, so the caller gets a message rather than a
		// generic domain error — and refused in the aggregate regardless, which
		// is what makes it hold for a caller written later.
		return ChangeRoleResult{}, ErrSelfRoleChange
	}

	agg, err := o.load(ctx, operatorID)
	if err != nil {
		return ChangeRoleResult{}, err
	}

	now := o.clock.Now()
	if err := agg.ChangeRole(role, actor.OperatorID, now); err != nil {
		return ChangeRoleResult{}, err
	}
	if len(agg.Uncommitted()) == 0 {
		// They already held it. A success, and deliberately unaudited: an entry
		// for a change that did not happen is noise in the stream an escalation
		// alert reads.
		return ChangeRoleResult{Changed: false}, nil
	}

	entryID, err := o.auditor.RecordOperatorManaged(ctx, actor, operatorID,
		"role changed to "+string(role))
	if err != nil {
		return ChangeRoleResult{}, fmt.Errorf("recording the role change: %w", err)
	}

	if err := o.appendOne(ctx, operatorID, agg); err != nil {
		return ChangeRoleResult{}, err
	}

	o.log.WarnContext(ctx, "an operator's role was changed",
		"operator_id", operatorID, "role", role, "by", actor.OperatorID)

	return ChangeRoleResult{Changed: true, AuditEntryID: entryID}, nil
}

// DisableResult reports the state after an offboarding.
type DisableResult struct {
	Changed       bool
	SessionsEnded int32
	AuditEntryID  string
}

// Disable offboards an operator and ends their live sessions.
//
// # Two mechanisms, because they close different halves of the window
//
// The sessions are ended DIRECTLY by this call, and the projection ALSO refuses
// them once OperatorDisabled lands — `ResolveOperatorSession` joins
// `operator_account` and a disabled row makes every bearer unusable.
//
// Neither alone is enough. The direct end handles the sessions that exist now,
// which is what "immediate" means when the person is signed in and the
// projection is seconds behind. The projection handles anything created between
// the append and the row landing, and it is what keeps the offboarding in force
// after a rebuild — the direct end wrote rows, and rows are derived.
func (o *Operators) Disable(
	ctx context.Context, actor Actor, operatorID string,
) (DisableResult, error) {
	agg, err := o.load(ctx, operatorID)
	if err != nil {
		return DisableResult{}, err
	}

	now := o.clock.Now()
	if err := agg.Disable(actor.OperatorID, now); err != nil {
		return DisableResult{}, err
	}
	if len(agg.Uncommitted()) == 0 {
		// Already offboarded. Their sessions are ended anyway rather than
		// skipped: a second call is what somebody makes when they are not sure
		// the first took, and answering it by doing nothing is how a
		// half-finished offboarding stays half-finished.
		ended, endErr := o.sessions.EndAllFor(ctx, operatorID, now)
		if endErr != nil {
			return DisableResult{}, fmt.Errorf("ending their sessions: %w", endErr)
		}
		return DisableResult{Changed: false, SessionsEnded: narrow(ended)}, nil
	}

	entryID, err := o.auditor.RecordOperatorManaged(ctx, actor, operatorID, "offboarded")
	if err != nil {
		return DisableResult{}, fmt.Errorf("recording the offboarding: %w", err)
	}

	if err := o.appendOne(ctx, operatorID, agg); err != nil {
		return DisableResult{}, err
	}

	// AFTER the append, and the order matters. Ending the sessions first would
	// leave a window in which the person is locked out and the log does not say
	// why — and if the append then failed, an operator with live access would
	// have been cut off by a call that recorded nothing.
	ended, err := o.sessions.EndAllFor(ctx, operatorID, now)
	if err != nil {
		// The offboarding IS recorded and the projection will refuse their
		// bearers within seconds. Reported rather than hidden, because those
		// seconds are exactly what "immediate" was supposed to remove.
		o.log.ErrorContext(ctx, "an offboarded operator's sessions could not be ended; "+
			"they remain usable until the projection catches up",
			"operator_id", operatorID, "error", err)
		return DisableResult{}, fmt.Errorf("ending their sessions: %w", err)
	}

	o.log.WarnContext(ctx, "an operator was offboarded",
		"operator_id", operatorID, "sessions_ended", ended, "by", actor.OperatorID)

	return DisableResult{Changed: true, SessionsEnded: narrow(ended), AuditEntryID: entryID}, nil
}

// List reads the roster.
func (o *Operators) List(
	ctx context.Context, actor Actor, method string, includeDisabled bool,
) ([]OperatorRecord, error) {
	// Audited BEFORE the read, like every read on this plane. The roster is a
	// list of our staff and their privileges, which is what somebody who had
	// reached this plane would want first.
	if _, err := o.auditor.RecordOperatorManaged(ctx, actor, "", "listed operators"); err != nil {
		return nil, fmt.Errorf("recording the read: %w", err)
	}
	out, err := o.accounts.All(ctx, includeDisabled)
	if err != nil {
		return nil, fmt.Errorf("listing operators: %w", err)
	}
	return out, nil
}

func (o *Operators) load(ctx context.Context, operatorID string) (*domain.Operator, error) {
	rec, err := o.accounts.ByID(ctx, operatorID)
	switch {
	case errors.Is(err, ErrNotAnOperator):
		return nil, ErrNoSuchOperator
	case err != nil:
		return nil, fmt.Errorf("resolving the operator: %w", err)
	}

	// # Rebuilt from the PROJECTION, not replayed from the stream
	//
	// The aggregate needs enough state to enforce its rules — does this
	// operator exist, what is their role, are they disabled — and the row
	// carries exactly that. Replaying the stream would be more faithful and
	// would put an event-store round trip in front of every management call.
	//
	// The cost is real and worth naming: the optimistic concurrency this
	// synthesises is against the ROW's view of the world, so two admins racing
	// a role change on a stale projection could both pass. That is D15's
	// scenario, and the append below still resolves it — the repository loads
	// the stream and appends under the version it read, so the second write
	// conflicts at the store. This shortcut affects which ERROR the loser gets,
	// not whether they lose.
	agg := eventsourcing.NewAggregate(domain.NewOperator)
	agg.Apply(&contract.OperatorProvisioned{
		OperatorID:      rec.OperatorID,
		SubjectID:       rec.SubjectID,
		Issuer:          rec.Issuer,
		ProviderSubject: rec.ProviderSubject,
		Role:            rec.Role,
		ProvisionedAt:   rec.ProvisionedAt,
	})
	if rec.Disabled() {
		agg.Apply(&contract.OperatorDisabled{
			OperatorID: rec.OperatorID,
			SubjectID:  rec.SubjectID,
			DisabledAt: *rec.DisabledAt,
		})
	}
	return agg, nil
}

// appendOne writes the single event a command produced.
func (o *Operators) appendOne(ctx context.Context, operatorID string, agg *domain.Operator) error {
	pending := agg.Uncommitted()
	if len(pending) != 1 {
		return fmt.Errorf("operator: a management command produced %d events, want 1", len(pending))
	}
	if err := o.events.AppendOperator(ctx, operatorID, pending[0]); err != nil {
		return fmt.Errorf("recording the change: %w", err)
	}
	return nil
}

// narrow bounds a session count for the wire.
//
// Unreachable in practice — an operator holds a handful of sessions and each
// expires in thirty minutes — and written anyway, because the alternative is a
// silent wrap into a negative count that the response's own `gte: 0` would then
// refuse, failing a call that actually succeeded.
func narrow(n int64) int32 {
	const maxInt32 = 1<<31 - 1
	switch {
	case n < 0:
		return 0
	case n > maxInt32:
		return maxInt32
	default:
		return int32(n)
	}
}

var _ = time.Time{}
