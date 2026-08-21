// Package api is profile's Connect handler layer: the only place in the module
// where a generated protobuf type meets a use-case type.
//
// # What this layer is for
//
// Three steps, in this order, and nothing else:
//
//  1. turn a wire DTO into an app command,
//  2. call the app service,
//  3. turn the app result into a wire DTO.
//
// It holds no business rule. Everything a handler here could be tempted to
// check is already checked somewhere with a better claim to it: the shape of a
// request by protovalidate running as an interceptor (ADR-007), the caller's
// identity and assurance level by the gate pipeline (ADR-021), and every rule
// about names, tags, zones and object keys by `app` and `domain`.
//
// # The caller is read from the context, never from the request
//
// All three RPCs act on the CALLER'S OWN profile. Not one request message
// carries a subject id, and that is a property of the schema rather than an
// accident: a field naming the person would turn UpdateProfile into a way to
// rename somebody else in front of their colleagues. The caller comes from
// `interceptor.PrincipalFrom`, which only the authn gate can write.
//
// # There is no organization on this wire either
//
// notification's handlers take an `org_id` from the request, because a feed and
// a preference are per person PER ORGANIZATION. A profile is not: one display
// name, one avatar, one timezone, across every organization somebody belongs to
// — exactly as they have one account. So there is no tenant field to accept and
// none to forget to check, and the projection carries no `org_id` for one to
// scope.
//
// # The vault value goes into the response and nowhere else
//
// This is the only layer that ever holds a display name in this module, and it
// holds it for the length of one function call. It is not logged, not put on an
// event, and not written to a table (ADR-002, CONVENTIONS §11).
package api

import (
	"context"
	"fmt"

	"github.com/chronos/chronos-go/gen/proto/chronos/profile/v1/profilev1connect"
	"github.com/chronos/chronos-go/internal/modules/profile/app"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/errs"
	srvconnect "github.com/chronos/chronos-go/internal/server/connect"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

// ---------------------------------------------------------------------------
// Ports
//
// Declared here, by the consumer, and narrowed to the methods this layer calls
// (ADR-001, CONVENTIONS §2). They are satisfied by *app.Queries, *app.Updates
// and *app.Avatars as written.
//
// Narrow interfaces rather than the concrete structs, for a reason that matters
// more than testability: a handler holding *app.Updates can reach every method
// on it, including ones no RPC exposes. A handler holding this interface cannot.
// ---------------------------------------------------------------------------

// Queries is profile's read side.
type Queries interface {
	Get(ctx context.Context, subjectID string) (app.Profile, error)
}

// Updates is the write half.
type Updates interface {
	Update(ctx context.Context, cmd app.UpdateCommand) (app.Profile, error)
}

// Avatars mints upload targets. A port of its own, and the narrowest here: a
// handler holding it can issue an upload grant for the caller and can do
// nothing else — it cannot read a profile and it cannot record one.
type Avatars interface {
	Grant(ctx context.Context, cmd app.UploadGrantCommand) (app.UploadGrant, error)
}

// Deps is everything a handler needs, one field per collaborator.
type Deps struct {
	Queries Queries
	Updates Updates
	Avatars Avatars
}

// Service implements chronos.profile.v1.ProfileService.
type Service struct {
	queries Queries
	updates Updates
	avatars Avatars
}

// New builds the handler, refusing a partial one.
//
// A nil collaborator is refused HERE rather than tolerated, because the
// alternative is a nil-pointer panic on the first request to whichever screen
// uses it — after the composition root has reported a healthy start, and in a
// process that answers every other RPC correctly.
func New(deps Deps) (*Service, error) {
	missing := func(what string) error {
		return fmt.Errorf("profile/api: the profile handler needs %s", what)
	}
	switch {
	case deps.Queries == nil:
		return nil, missing("a read side")
	case deps.Updates == nil:
		return nil, missing("a write side")
	case deps.Avatars == nil:
		// Refused rather than tolerated as "avatars are optional". A nil here
		// serves CreateAvatarUpload with a panic, and it is the only endpoint
		// through which an image can ever be attached to a person.
		return nil, missing("an avatar upload service")
	}
	return &Service{queries: deps.Queries, updates: deps.Updates, avatars: deps.Avatars}, nil
}

// ---------------------------------------------------------------------------
// The caller
// ---------------------------------------------------------------------------

// callerSubject reads the authenticated caller's pseudonym from the context.
//
// The context, and never the request. `interceptor.PrincipalFrom` is the only
// reader of a value only the authn gate can write, so a subject obtained here
// cannot have been chosen by whoever sent the request. Every RPC below starts
// with this call and uses nothing else to name a person.
//
// `authz.Principal.ID` is taken to be the SubjectID pseudonym, matching
// identity's and notification's reading of it: the pseudonym is what the PII
// vault, every projection and every event are keyed by, and ADR-002 makes the
// pseudonym the thing that travels.
//
// A KindAPIKey or KindServiceAccount principal carries the KEY's identifier
// rather than a person's pseudonym, so reading it as a subject would answer for
// whatever account that string happened to name — and here it would let a
// machine credential rename a person. Refused rather than resolved: a profile
// is a person's own, and there is no delegation convention for it.
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
// has already decided what a caller may be told (ADR-036).
func fail(err error) error { return srvconnect.Error(err) }

// The handler must satisfy the generated interface, and the compiler is what
// says so. Without this, omitting an RPC is a failure at the mux.Handle call in
// cmd/api — a different package and a later commit — and an RPC that is
// declared, policy-annotated and unimplemented is exactly the shape of gap
// ADR-021 exists to make impossible.
var _ profilev1connect.ProfileServiceHandler = (*Service)(nil)
