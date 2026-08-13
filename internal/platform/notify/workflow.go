package notify

import "time"

// SendNotificationWorkflow is the registered name of the workflow that delivers
// one notification. It is written into workflow history, so it is PERMANENT:
// renaming it strands every in-flight execution against a worker that no longer
// answers to it.
//
// It lives here rather than in the adapter because both sides must agree — the
// reactor that starts the run and the worker that registers the handler — and
// the surest way to make two constants match is to have one.
const SendNotificationWorkflow = "chronos.notification.Send.v1"

// SendNotificationInput is what the workflow carries.
//
// It is deliberately NOT Notification. That type has a Recipient whose
// Address and Name are filled by the vault, and workflow input is written to
// HISTORY — durable, replicated, long-lived storage. Putting a resolved address
// there would place personal data somewhere crypto-shredding cannot reach, which
// is exactly the rule the event log follows (ADR-002). So the workflow carries
// the SubjectID pseudonym, and the activity resolves the address from the vault
// at the moment it sends.
//
// Fields are exported and the shape is additive-only for the same reason an
// event's is: a workflow started by the old binary is replayed by the new one.
type SendNotificationInput struct {
	// Template names the notification, e.g. "identity.password_changed".
	Template string

	// Class decides whether this is delivered at all.
	Class Class

	// SubjectID is the recipient's pseudonym. Empty for operator notifications,
	// which are addressed to the people running the system rather than to a
	// tenant subject.
	SubjectID string

	// OrgID and WorkspaceID scope the notification so workspace channel policy
	// can be consulted.
	OrgID       string
	WorkspaceID string

	// Channels restricts delivery. Empty means "whatever class and preferences
	// allow", which is the normal case.
	Channels []Channel

	// Data is template input and carries NO personal data.
	Data map[string]any

	// OccurredAt is the UTC instant of the underlying event.
	OccurredAt time.Time

	// IdempotencyKey is normally the event id. It deduplicates at the transport,
	// so a workflow retried after a partial failure cannot become a second
	// email.
	IdempotencyKey string
}

// InputFor reduces a notification to what may cross into workflow history.
//
// It is the ONE place that reduction happens, and it drops the recipient down to
// its pseudonym. A resolved Address or Name in history is personal data that
// erasure cannot reach — history is durable and replicated, and there is no
// ciphertext to shred — so the field is not copied rather than being copied and
// hoped about.
func InputFor(n Notification) SendNotificationInput {
	return SendNotificationInput{
		Template:       n.Template,
		Class:          n.Class,
		SubjectID:      n.Recipient.SubjectID,
		OrgID:          n.OrgID,
		WorkspaceID:    n.WorkspaceID,
		Channels:       n.Channels,
		Data:           n.Data,
		OccurredAt:     n.OccurredAt,
		IdempotencyKey: n.IdempotencyKey,
	}
}

// Notification rebuilds the dispatcher's input. The recipient carries the
// pseudonym only; the vault fills the rest inside the dispatcher.
func (in SendNotificationInput) Notification() Notification {
	return Notification{
		Template:       in.Template,
		Class:          in.Class,
		Recipient:      Recipient{SubjectID: in.SubjectID, OrgID: in.OrgID},
		Channels:       in.Channels,
		OrgID:          in.OrgID,
		WorkspaceID:    in.WorkspaceID,
		Data:           in.Data,
		OccurredAt:     in.OccurredAt,
		IdempotencyKey: in.IdempotencyKey,
	}
}
