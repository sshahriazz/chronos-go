// Package api is notification's Connect handler layer: the only place in the
// module where a generated protobuf type meets a use-case type.
//
// # What this layer is for
//
// Three steps, in this order, and nothing else:
//
//  1. turn a wire DTO into an app command,
//  2. call the app service,
//  3. turn the app result into a wire DTO.
//
// It holds no business rule. Everything a handler here could be tempted to check
// is already checked somewhere with a better claim to it: the shape of a request
// by protovalidate running as an interceptor (ADR-007), the caller's identity and
// assurance level by the gate pipeline (ADR-021), what a preference may name by
// the schema, and every rule about feeds, endpoints and channels by `app` and
// `domain`.
//
// # The caller is read from the context, never from the request
//
// All seven RPCs act on the CALLER'S OWN notifications. Not one request message
// carries a subject id, and that is a property of the schema rather than an
// accident: a field naming the recipient would turn ListNotifications into
// somebody else's inbox and MarkNotificationsRead into a way to dismiss an alert
// on a victim's screen. The caller comes from `interceptor.PrincipalFrom`, which
// only the authn gate can write.
//
// # The organization DOES come from the request, and why that is safe
//
// It is the one identifier on the wire, and it is a temporary shape: gate 1 will
// resolve the organization from the request's own context, at which point the
// field is deprecated. It grants nothing in the meantime, and the argument has
// two independent halves. Every statement behind it is additionally filtered by
// the caller's own pseudonym, so naming an organization the caller does not
// belong to returns their rows in it, of which there are none. And every
// statement runs under row-level security scoped to that same organization, as a
// role that is neither owner nor superuser, so the filter is enforced twice by
// two mechanisms that fail independently.
//
// This is the same seam identity's RevokeSession sits on: a self-scoped policy
// says the caller may act on their own account, not that the object they named
// is theirs, and scoping every read and write by the principal is a handler
// obligation the gate cannot discharge (internal/server/policy).
//
// # Refusals stay undifferentiated
//
// A notification id that does not exist, one in another organization and one
// belonging to somebody else produce the identical NOT_FOUND. There is
// deliberately no switch on an app error anywhere below — a switch is how two
// indistinguishable refusals become two distinguishable Connect codes (ADR-036).
package api

import (
	"context"
	"fmt"

	"github.com/chronos/chronos-go/gen/proto/chronos/notification/v1/notificationv1connect"
	"github.com/chronos/chronos-go/internal/modules/notification/app"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/page"
	srvconnect "github.com/chronos/chronos-go/internal/server/connect"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

// ---------------------------------------------------------------------------
// Ports
//
// Declared here, by the consumer, and narrowed to the methods this layer calls
// (ADR-001, CONVENTIONS §2). They are satisfied by *app.Queries, *app.Inbox,
// *app.PushRegistry and *app.Preferences as written.
//
// Narrow interfaces rather than the concrete structs, for a reason that matters
// more than testability: a handler holding *app.Inbox can reach every method on
// it, including ones no RPC exposes. A handler holding this interface cannot.
// ---------------------------------------------------------------------------

// Queries is notification's read side.
type Queries interface {
	ListNotifications(
		ctx context.Context, orgID, subjectID string, pageToken page.Token, pageSize int,
	) (page.Page[app.FeedItem], error)
	UnreadCount(ctx context.Context, orgID, subjectID string) (int64, error)
	GetPreferences(ctx context.Context, orgID, subjectID string) (app.PreferenceView, error)
}

// Inbox is the write half of the feed.
//
// A port of its own rather than more methods on Queries, and the split is not
// cosmetic: a handler holding this interface can dismiss the caller's own
// notifications and can do nothing else. It cannot read a feed, register a
// device or change a preference.
type Inbox interface {
	MarkRead(ctx context.Context, cmd app.MarkReadCommand) (app.MarkReadResult, error)
}

// PushRegistry enrols and retires browser endpoints.
type PushRegistry interface {
	Register(ctx context.Context, cmd app.RegisterPushCommand) (app.RegisterPushResult, error)
	Remove(ctx context.Context, cmd app.RemovePushCommand) (app.RemovePushResult, error)
}

// Preferences is the settings screen's write half.
//
// A port of its own, and the narrowest in the file: a handler holding it can
// change the caller's channel toggles and can do nothing else — it cannot read
// anybody's feed, and it has no method that could ever name a class.
type Preferences interface {
	Set(ctx context.Context, cmd app.SetPreferencesCommand) (app.PreferenceView, error)
}

// Deps is everything a handler needs, one field per collaborator.
//
// A struct rather than four positional arguments, because all four are pointers
// to types whose names differ only by their role and the compiler cannot tell a
// swapped pair apart.
type Deps struct {
	Queries     Queries
	Inbox       Inbox
	Push        PushRegistry
	Preferences Preferences
}

// Service implements chronos.notification.v1.NotificationService.
//
// Every field is required and none may be nil; see New.
type Service struct {
	queries Queries
	inbox   Inbox
	push    PushRegistry
	prefs   Preferences
}

// New builds the handler, refusing a partial one.
//
// A nil collaborator is refused HERE rather than tolerated, because the
// alternative is a nil-pointer panic on the first request to whichever screen
// uses it — after the composition root has reported a healthy start, and in a
// process that answers every other RPC correctly. That is precisely the failure
// mode compile-time wiring exists to avoid, and a constructor returning
// (*Service, error) is what makes cmd/api unable to ignore it.
func New(deps Deps) (*Service, error) {
	missing := func(what string) error {
		return fmt.Errorf("notification/api: the notification handler needs %s", what)
	}
	switch {
	case deps.Queries == nil:
		return nil, missing("a read side")
	case deps.Inbox == nil:
		// Refused rather than tolerated as "dismissing is optional". A nil here
		// serves MarkNotificationsRead with a panic, and an inbox that cannot be
		// dismissed is one where the badge only ever counts up.
		return nil, missing("an inbox")
	case deps.Push == nil:
		return nil, missing("a push registry")
	case deps.Preferences == nil:
		// Refused rather than tolerated as "preferences are optional". A nil here
		// serves SetNotificationPreferences with a panic, and this is the only
		// endpoint through which a person can stop mail they did not ask for —
		// its absence shows up as people marking the product as spam.
		return nil, missing("a preference service")
	}
	return &Service{
		queries: deps.Queries,
		inbox:   deps.Inbox,
		push:    deps.Push,
		prefs:   deps.Preferences,
	}, nil
}

// ---------------------------------------------------------------------------
// The caller
// ---------------------------------------------------------------------------

// callerSubject reads the authenticated caller's pseudonym from the context.
//
// The context, and never the request. `interceptor.PrincipalFrom` is the only
// reader of a value only the authn gate can write, so a subject obtained here
// cannot have been chosen by whoever sent the request. Every RPC below starts
// with this call and uses nothing else to name a recipient.
//
// `authz.Principal.ID` is taken to be the SubjectID pseudonym, matching
// identity's own reading of it: the pseudonym is what identity's read side, the
// session projection and every notification event are keyed by, and ADR-002
// makes the pseudonym the thing that travels.
//
// A KindAPIKey or KindServiceAccount principal carries the KEY's identifier
// rather than a person's pseudonym, so reading it as a subject would answer for
// whatever account that string happened to name. Refused rather than resolved:
// these endpoints are a person's own inbox, and there is no delegation
// convention for them.
//
// Unauthenticated with a fixed message. Nothing here distinguishes "no
// principal" from "the wrong kind of principal" on the wire.
func callerSubject(ctx context.Context) (string, error) {
	principal, ok := interceptor.PrincipalFrom(ctx)
	if !ok || principal.Subject.Kind != authz.KindUser || principal.Subject.ID == "" {
		return "", errs.Unauthenticatedf("this request has not authenticated")
	}
	return principal.Subject.ID, nil
}

// idempotencyKey reads the client-generated key every mutating command needs.
//
// It comes from the SAME header gate 5 claims, so a retry the gate collapses and
// a retry that reaches the app layer derive the same event ids rather than two
// chains for one command.
//
// Absent is a REFUSAL, never a server-generated substitute. A key minted here
// would make every retry look like a new request, which is the exact failure the
// header exists to prevent, with the added insult of looking handled.
func idempotencyKey(header interceptor.Header) (string, error) {
	key := header.Get(interceptor.IdempotencyHeader)
	if key == "" {
		return "", errs.ValidationFailedf(
			"%s is required on every mutating request", interceptor.IdempotencyHeader)
	}
	return key, nil
}

// fail renders an error onto the wire.
//
// One function, used by every handler, and it does exactly one thing: hand the
// error to the transport mapping the rest of the server already uses. There is
// no branch on the error's reason here and there must not be one — the app layer
// answers "no such notification", "not in this organization" and "not yours"
// with one error, and a switch in this layer is how that single answer would
// become several distinguishable Connect codes (ADR-036).
func fail(err error) error { return srvconnect.Error(err) }

// The handler must satisfy the generated interface, and the compiler is what
// says so. Without this, omitting an RPC is a failure at the mux.Handle call in
// cmd/api — a different package and a later commit — and an RPC that is
// declared, policy-annotated and unimplemented is exactly the shape of gap
// ADR-021 exists to make impossible.
var _ notificationv1connect.NotificationServiceHandler = (*Service)(nil)
