// Package notify is the notification kernel: what may be told to whom, through
// which channels, and under what policy.
//
// Email is ONE channel here, not the system. The others — the in-app feed, web
// push, and the realtime stream — carry the same notification and obey the same
// class policy, which is why the vocabulary lives here rather than inside any
// one transport (notification.md §2).
//
// Two rules from NOTIFICATIONS §4 are enforced by these types rather than left
// to review:
//
//   - A notification is addressed to a SubjectID, never to an address or a
//     device. Events carry pseudonyms only (ADR-002); contact details are
//     resolved from the vault at delivery time.
//   - An erased subject is SKIPPED, not failed. Someone who exercised erasure
//     has no address, and that is a correct outcome rather than an error.
package notify

import (
	"context"
	"errors"
	"time"
)

// Class decides whether a notification is delivered at all, and through which
// channels. It is a consent and suppression policy, not a priority
// (notification.md §6).
type Class uint8

const (
	// Security is account safety: a new sign-in, a password change, MFA
	// enrolment, recovery codes used. ALWAYS delivered — it ignores
	// preferences and carries no unsubscribe, because it is the durable record
	// for exactly the case where another channel is compromised.
	Security Class = iota + 1

	// Transactional is something the recipient asked for: verification, an
	// invitation, a receipt. Always delivered; no unsubscribe.
	Transactional

	// Activity is someone else's action: a mention, an assignment, a comment.
	// Per preference, and the only class whose email is suppressed when the
	// recipient reads it in-app first (ADR-026).
	Activity

	// Product is marketing. Opt-in only and always unsubscribable.
	Product

	// Operator is for the people running the system: a projection that stopped,
	// a reactor's parked backlog, a failed reconciliation. It never reaches a
	// tenant and never carries tenant personal data.
	Operator
)

func (c Class) String() string {
	switch c {
	case Security:
		return "security"
	case Transactional:
		return "transactional"
	case Activity:
		return "activity"
	case Product:
		return "product"
	case Operator:
		return "operator"
	default:
		return "unknown"
	}
}

// IgnoresPreferences reports whether the class is delivered regardless of what
// the recipient has switched off. Security and Transactional are: you cannot
// opt out of being told your password changed.
func (c Class) IgnoresPreferences() bool { return c == Security || c == Transactional || c == Operator }

// SuppressibleByRead reports whether reading in-app should cancel the email.
// Only Activity qualifies — suppressing security mail would remove the
// account-takeover tripwire (notification.md §6).
func (c Class) SuppressibleByRead() bool { return c == Activity }

// RequiresUnsubscribe reports whether delivery must offer an opt-out.
func (c Class) RequiresUnsubscribe() bool { return c == Activity || c == Product }

// Channel is a way of reaching someone.
type Channel string

const (
	ChannelEmail   Channel = "email"
	ChannelInApp   Channel = "in_app"
	ChannelWebPush Channel = "web_push"
	// ChannelRealtime is reserved for TRANSIENT signals — presence, typing —
	// that are not feed items. Notifications reach the browser through the
	// in-app feed projection's publish, so registering a realtime transport for
	// them would deliver twice.
	ChannelRealtime Channel = "realtime"
)

// Recipient is who a notification is for.
//
// SubjectID is the pseudonym. Address, Name and Devices are filled by the vault
// immediately before delivery and are empty everywhere else — which is what
// stops contact details being carried in an event by accident.
type Recipient struct {
	// SubjectID is the pseudonym (ADR-002). Required for tenant-facing
	// notifications.
	SubjectID string

	// OrgID is the organization this person belongs to, set by whichever
	// resolver produced them.
	//
	// It exists to be CHECKED, not to be used: the dispatcher compares it
	// against the event's own org and refuses a mismatch. A read model that
	// joins one column wrong returns another customer's administrators, and
	// without this that is a cross-tenant leak nothing would catch.
	OrgID string

	// Address is resolved from the vault at delivery time.
	Address string

	// Name is the display name, also from the vault. Optional.
	Name string

	// Locale selects the wording, e.g. "en", "en-GB", "de-AT".
	Locale string

	// Timezone renders timestamps in the reader's own time. Storage is always
	// UTC (ADR-008); conversion happens at delivery time only.
	Timezone string
}

// Notification is what a domain wants said, before it is rendered for any
// particular channel.
//
// It carries DATA, never rendered text: wording belongs to the renderer, so a
// copy change never touches a domain, and personal data never has to travel
// through a domain to reach a template.
type Notification struct {
	// Template names the notification, e.g. "identity.password_changed". It is
	// permanent: it appears in metrics, logs, preferences and operator
	// overrides.
	Template string

	Class     Class
	Recipient Recipient

	// Channels restricts delivery. Empty means "whatever the class and the
	// recipient's preferences allow", which is the normal case.
	Channels []Channel

	// OrgID and WorkspaceID scope the notification, so the workspace's own
	// channel policy can be consulted. Taken from the event's metadata.
	OrgID       string
	WorkspaceID string

	// Data is template input and must contain NO personal data. The recipient
	// travels separately and the vault is the only source of anything
	// identifying.
	Data map[string]any

	// OccurredAt is the UTC instant of the underlying event. Zero means now.
	OccurredAt time.Time

	// IdempotencyKey deduplicates delivery, normally the event ID, so a
	// redelivered event cannot become a second email.
	IdempotencyKey string
}

// Validate rejects notifications that could only produce something broken or
// unsafe.
func (n Notification) Validate() error {
	switch {
	case n.Template == "":
		return errors.New("notify: template is required")
	case n.Class == 0:
		return errors.New("notify: class is required — it decides whether this is delivered at all")
	case n.Class == Operator && n.Recipient.SubjectID != "":
		// Operator notifications go to the people running the system.
		// Addressing one to a tenant subject leaks operational detail.
		return errors.New("notify: operator notifications must not be addressed to a tenant subject")
	case n.Class != Operator && n.Recipient.SubjectID == "":
		return errors.New("notify: a recipient subject id is required")
	}
	return nil
}

// Vault resolves a pseudonym to contact details.
//
// The single point at which personal data enters the outbound path, backed by
// the PII vault — the only mutable system of record (ADR-013).
type Vault interface {
	// Resolve returns contact details for a subject.
	//
	// Returns ErrSubjectErased when the subject exercised erasure. That is not
	// a failure: there is nothing to deliver to, and the send is skipped.
	Resolve(ctx context.Context, subjectID string) (Recipient, error)
}

// Preferences reports what a recipient has switched off.
//
// Every user controls their own channels — email, in-app and web push are each
// a toggle they own. Nobody else can set them: not an administrator, not the
// operator. A person's notification settings are theirs.
//
// This is consulted ONLY for classes that do not ignore preferences, and that
// limit is a security property rather than a product decision. If switching off
// email could stop a security alert, an attacker who gains access to an account
// would simply switch it off and silence the very message that reveals them —
// the account-takeover tripwire disabled by the takeover itself. The dispatcher
// checks class before it ever reaches this port (notification.md §6).
//
// Template is passed as well as channel so that finer-grained preferences —
// "mentions but not assignments" — need no port change later. An
// implementation that offers only the three channel toggles ignores it.
type Preferences interface {
	// orgID scopes the read: preferences live in an RLS-protected table like
	// every other read model. It is passed explicitly rather than carried in
	// the context, so a caller cannot forget it and silently read unscoped.
	Enabled(ctx context.Context, orgID, subjectID, template string, ch Channel) (bool, error)
}

// ReadState answers the arbitration question: did the recipient already see this
// in-app? Only Activity notifications consult it (ADR-026).
type ReadState interface {
	// ReadWithin reports whether the notification identified by key was read
	// in-app within the window. orgID scopes the read.
	ReadWithin(ctx context.Context, orgID, subjectID, key string, window time.Duration) (bool, error)
}

// Transport delivers a notification over one channel.
//
// Every channel implements this, which is what lets the dispatcher treat email,
// push and the in-app feed uniformly and apply one policy to all of them.
type Transport interface {
	// Channel reports which channel this delivers over.
	Channel() Channel

	// Deliver sends it. The recipient already has contact details resolved.
	Deliver(ctx context.Context, n Notification) error
}

var (
	// ErrSubjectErased means the subject's personal data has been destroyed.
	// Callers SKIP and record; they must not retry and must not report failure
	// (NOTIFICATIONS §4).
	ErrSubjectErased = errors.New("notify: subject has been erased")

	// ErrNoAddress means the subject exists but has no usable address on this
	// channel.
	ErrNoAddress = errors.New("notify: subject has no address for this channel")

	// ErrUnknownTemplate means nothing is registered under that name — a wiring
	// bug, not a data problem.
	ErrUnknownTemplate = errors.New("notify: no such template")
)
