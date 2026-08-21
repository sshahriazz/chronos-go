package api

import (
	"context"

	"connectrpc.com/connect"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/clientip"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The RPCs in this file are PUBLIC: they run before any session exists, so there
// is no principal to read and nothing in them is scoped to a caller. They are
// also the ones the gate pipeline skips entirely, which is why each of them
// reads the idempotency key from the header itself.

// Register claims an address and creates the account that claims it.
//
// The response is empty, and its emptiness is the feature: `RegisterResult.Created`
// is false when the address was already claimed, and NOTHING about that reaches
// the wire. Registration is one of the flows that leaks account existence when
// written naively, and a handler that mapped Created onto a field, a code or a
// message would reopen it.
//
// It takes no password: the request has no field for one. The credential is
// created by VerifyEmail, in the same call that proves control of the mailbox
// (IDENTITY-REVIEW C8).
//
// # What the taken branch now does, and why none of it reaches this file
//
// It mails the address holder — "somebody tried to register with your address"
// (ADR-055). That answer travels to the MAILBOX and never to the caller, which
// is the only channel entitled to carry it: reading it requires controlling the
// address, and controlling the address is the proof the empty response exists to
// demand. This handler is unchanged by it, deliberately. There is no new field,
// no new code and no new branch here, because a branch here is exactly how the
// property would be lost.
//
// The caller scope comes from the transport exactly as ResendEmailVerification's
// does; see that handler for the whole argument about X-Forwarded-For and
// API_TRUSTED_PROXY_HOPS. It is here because registration now spends from the
// same per-caller and per-address triggered-mail ceilings the resend and reset
// flows spend from — on BOTH branches, so the ceiling cannot be read as an
// answer.
func (s *Service) Register(
	ctx context.Context, req *connect.Request[identityv1.RegisterRequest],
) (*connect.Response[identityv1.RegisterResponse], error) {
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	if _, err := s.registration.Register(ctx, app.RegisterCommand{
		Email:          req.Msg.GetEmail(),
		CallerScope:    callerScope(s.callerScope, req),
		IdempotencyKey: key,
	}); err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.RegisterResponse{}), nil
}

// VerifyEmail proves control of an address, sets the account's first password,
// and makes the claim on the address permanent.
//
// Unlike registration this is not an existence oracle — presenting a valid
// single-use token IS proof of control — so the account's identifiers come back.
//
// The password rides in this request rather than the registration that preceded
// it, and that is the pre-hijacking defence rather than an ergonomic choice: the
// party holding this token is the party that reads mail at the address, and it
// is the only party entitled to choose the credential the address will be signed
// into with.
//
// The public handle rides here for a related but separate reason (ADR-051): a
// handle on RegisterRequest would let anyone pair a victim's address with a fresh
// random handle, register, and then read the answer off the public availability
// check — reopening the account-existence oracle the empty RegisterResponse
// exists to close. See app.VerifyEmailCommand.Username.
//
// A taken handle comes back as a plain CONFLICT saying so, and that is the ONE
// refusal in this file allowed to be specific. Everywhere else the app layer
// answers with one undifferentiated error and this layer renders it unexamined
// (ADR-036); here the fact being disclosed is public by design, and hiding it
// would tell the person nothing while telling an attacker nothing they could not
// read from CheckUsernameAvailability. There is still no switch below — the app
// layer produces the CONFLICT and `fail` renders whatever it is given.
func (s *Service) VerifyEmail(
	ctx context.Context, req *connect.Request[identityv1.VerifyEmailRequest],
) (*connect.Response[identityv1.VerifyEmailResponse], error) {
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	result, err := s.registration.VerifyEmail(ctx, app.VerifyEmailCommand{
		Token:          req.Msg.GetToken(),
		Password:       req.Msg.GetPassword(),
		Username:       req.Msg.GetUsername(),
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.VerifyEmailResponse{
		SubjectId: result.SubjectID,
		UserId:    result.UserID.String(),
		Changed:   result.Changed,
	}), nil
}

// ResendEmailVerification issues a new verification link for an address whose
// account has not proven it yet.
//
// # The result is dropped, and that is the whole design
//
// `app.ResendVerificationResult.Outcome` distinguishes four things — no account,
// a request appended, already verified, not in a verifiable state — and NONE of
// them reaches the wire. Mapping any of them onto a field, a code or a message
// would turn an unauthenticated endpoint into a precise account-state oracle for
// any address a prober can type. Registration solves the same problem the same
// way, one function above.
//
// # The caller scope comes from the transport, and from the header only as far
// as the operator has said to trust it
//
// `req.Peer().Addr` is what the connection says, so a caller cannot choose their
// own rate-limit bucket by editing a field. X-Forwarded-For is consulted ONLY to
// the depth API_TRUSTED_PROXY_HOPS declares, counting from the right — see
// internal/platform/clientip, which owns every rule about it. With the default
// of zero the header is not read at all and the peer address is the scope, which
// is what this handler did before the setting existed.
//
// The deployment constraint that remains is now a CONFIGURED one rather than an
// unavoidable one: a deployment behind a terminating proxy that leaves the
// setting at zero still collapses every caller into one bucket, and the rule
// becomes a global ceiling of 20 resends an hour. Setting it too high is the
// opposite and worse mistake. Both are written down in
// docs/domains/identity.md §12.1 and in the config field's own comment.
//
// The scope is not hashed or shortened here. `ratelimit` namespaces and the app
// layer passes it straight to Valkey as part of a key; an IP is not personal data
// under this system's rules in the way an address is, and it never enters an
// event, a log line or the read model.
func (s *Service) ResendEmailVerification(
	ctx context.Context, req *connect.Request[identityv1.ResendEmailVerificationRequest],
) (*connect.Response[identityv1.ResendEmailVerificationResponse], error) {
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	if _, err := s.resender.Resend(ctx, app.ResendVerificationCommand{
		Email:          req.Msg.GetEmail(),
		CallerScope:    callerScope(s.callerScope, req),
		IdempotencyKey: key,
	}); err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.ResendEmailVerificationResponse{}), nil
}

// RequestPasswordReset sends a reset link to the address a registered account
// holds.
//
// # The result is dropped, and that is the whole design
//
// `app.RequestPasswordResetResult.Outcome` distinguishes five things — no
// account, a request appended, an account with no password, a deactivated
// account, a suspended one — and NONE of them reaches the wire. Mapping any of
// them onto a field, a code or a message would turn an unauthenticated endpoint
// into a precise account-state oracle for any address a prober can type.
// Registration and ResendEmailVerification solve the same problem the same way.
//
// # The address in the request is a LOOKUP key, never a destination
//
// This handler passes it to the app layer and nothing else. The link is issued
// against the account that was found and mailed to the address the vault holds
// for it, so a request cannot redirect somebody else's reset link
// (identity.md §4.5). The property is carried by the app layer holding no way to
// address mail at all, not by a check here.
//
// The caller scope comes from the transport exactly as ResendEmailVerification's
// does; see that handler for the whole argument about X-Forwarded-For and
// API_TRUSTED_PROXY_HOPS.
func (s *Service) RequestPasswordReset(
	ctx context.Context, req *connect.Request[identityv1.RequestPasswordResetRequest],
) (*connect.Response[identityv1.RequestPasswordResetResponse], error) {
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	if _, err := s.resets.Request(ctx, app.RequestPasswordResetCommand{
		Email:          req.Msg.GetEmail(),
		CallerScope:    callerScope(s.callerScope, req),
		IdempotencyKey: key,
	}); err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.RequestPasswordResetResponse{}), nil
}

// ResetPassword redeems a reset link and replaces the account's password.
//
// # Nothing comes back, and that is a security decision
//
// `app.ResetPasswordResult` carries the subject, the user id, how many sessions
// were voided and how many tokens were swept. All of it is dropped here, and the
// wire message has no field for any of it.
//
// VerifyEmail, one function above, DOES return the account's identifiers on the
// same kind of proof — a valid single-use token — and the difference is worth
// stating because the two look like they should agree. VerifyEmail's caller is
// about to become the account holder; this one must not be advanced towards a
// session at all (ASVS 5.0 V6.4.3). A reset that handed back a session, or
// anything a client could treat as one, converts "the attacker can read the
// mailbox" into full account takeover in one step. The surest way not to write
// that is to have nothing to write it into.
//
// Every unusable link — unknown, spent, expired, or naming an account with no
// password — is one undifferentiated refusal produced by the app layer. There is
// no switch here, deliberately: a switch is how one answer becomes several
// distinguishable Connect codes (ADR-036).
func (s *Service) ResetPassword(
	ctx context.Context, req *connect.Request[identityv1.ResetPasswordRequest],
) (*connect.Response[identityv1.ResetPasswordResponse], error) {
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	if _, err := s.resets.Complete(ctx, app.ResetPasswordCommand{
		Token:          req.Msg.GetToken(),
		Password:       req.Msg.GetPassword(),
		IdempotencyKey: key,
	}); err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.ResetPasswordResponse{}), nil
}

// CheckUsernameAvailability reports whether a public handle can be claimed.
//
// # The result IS returned, and that is the whole design
//
// Every other handler in this file drops what it learned: Register, resend and
// both reset calls answer identically whether or not an account exists, because
// an address is secret and a distinguishable answer is an existence oracle. This
// one returns the answer, because a HANDLE is not secret — publication is its
// entire purpose (ADR-051) — and the same fact is readable from any page that
// renders a mention.
//
// Do not make this uniform with its neighbours. An indistinguishable answer here
// would protect nothing, and it would move the moment a person discovers their
// handle is taken to AFTER they have spent a verification link they cannot get
// back.
//
// The one distinction the app layer refuses to draw is between a taken handle
// and a tombstoned one, and it refuses it in `app`, not here — see
// app.CheckUsernameResult. This layer has no field to put it in either way.
//
// The caller scope comes from the transport exactly as ResendEmailVerification's
// does; see that handler for the whole argument about X-Forwarded-For and
// API_TRUSTED_PROXY_HOPS. It bounds how many streams one caller can make this
// process read, which is a resource question and not an information one.
func (s *Service) CheckUsernameAvailability(
	ctx context.Context, req *connect.Request[identityv1.CheckUsernameAvailabilityRequest],
) (*connect.Response[identityv1.CheckUsernameAvailabilityResponse], error) {
	// No idempotency key. It is a READ: it appends nothing, mints nothing and
	// spends nothing, so there is no second application for a key to collapse.
	result, err := s.usernames.Check(ctx, app.CheckUsernameCommand{
		Username:    req.Msg.GetUsername(),
		CallerScope: callerScope(s.callerScope, req),
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.CheckUsernameAvailabilityResponse{
		Available: result.Available,
		Username:  result.Username,
	}), nil
}

// callerScope names whoever is calling, for the per-caller ceiling.
//
// Every rule about WHICH address that is lives in clientip: this function only
// hands it the two things the transport knows — the peer address and every
// X-Forwarded-For field line, in arrival order. `Values` rather than `Get`
// because several field lines are equivalent to one comma-joined line, and
// reading only the first would let a caller hide entries behind a second header.
//
// A free function taking the resolver rather than a method, because Go methods
// cannot be generic and the connect request is.
func callerScope[T any](r clientip.Resolver, req *connect.Request[T]) string {
	return r.Scope(req.Peer().Addr, req.Header().Values(clientip.ForwardedForHeader))
}

// Authenticate verifies the factors presented and reports what remains (ADR-050).
//
// Only the two SUCCESSFUL shapes are distinguished here — a second factor is owed,
// or every factor passed. A refusal never reaches this mapping at all: the app
// layer returns one error for an unknown identifier, a wrong password, a wrong
// code, a replayed code, an unverified address, a deactivated account, a suspended
// account and a throttled attempt alike, and `fail` renders whatever it is given
// without inspecting it.
//
// `result.Proof` is deliberately dropped. It is the evidence CreateSession needs,
// it is unexported and unserializable by construction, and there is no wire field
// for it — a partial authentication that could be written down is a bearer
// credential with no storage, no deadline and no revocation.
func (s *Service) Authenticate(
	ctx context.Context, req *connect.Request[identityv1.AuthenticateRequest],
) (*connect.Response[identityv1.AuthenticateResponse], error) {
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	result, err := s.authn.Authenticate(ctx, app.AuthenticateCommand{
		Identifier:     req.Msg.GetIdentifier(),
		Password:       req.Msg.GetPassword(),
		Code:           req.Msg.GetCode(),
		DeviceID:       req.Msg.GetDeviceId(),
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.AuthenticateResponse{
		SecondFactorRequired: result.SecondFactorRequired,
		Offered:              protoMethodKinds(result.Offered),
	}), nil
}

// CreateSession completes a login and mints the bearer token.
//
// # Why this is two app calls
//
// `app.CreateSession` takes a `Proof`, and a Proof can only come from
// `app.Authenticate` returning one — it has no exported constructor and cannot be
// serialized, so there is no artifact the request could have carried (ADR-050).
// The ceremony therefore happens here, in one process, in two steps: authenticate
// with the credentials the request re-presented, then exchange the resulting Proof
// for a session. That is orchestration of one wire call onto two commands, not a
// business rule — every decision inside either step still belongs to `app`.
//
// # Why the key is namespaced
//
// Both commands derive their event ids from the idempotency key alone
// (`eventsourcing.DeriveEventID(key, seq)`), so handing the same key to both would
// have the authentication journal's first event and the session's first event
// claim the SAME id. The store collapses events by id, so one of the two appends
// would silently become a no-op. Two derived keys, both stable across retries of
// the same request, keep the collapse doing what it is for — dropping a genuine
// duplicate — without merging two different events.
//
// # A second factor that is owed is a refusal, not a response
//
// A caller arriving without a required code gets the same undifferentiated refusal
// as any other failure, which is the message's own stated contract. The refusal is
// produced by asking `app.CreateSession` with the zero Proof the incomplete
// ceremony returned: a zero Proof mints nothing and the app layer answers it with
// its own single Unauthenticated error. Branching here on
// `SecondFactorRequired` and writing a different error would be this layer
// inventing a distinguishable outcome the app layer refused to make.
func (s *Service) CreateSession(
	ctx context.Context, req *connect.Request[identityv1.CreateSessionRequest],
) (*connect.Response[identityv1.CreateSessionResponse], error) {
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	attempt, err := s.authn.Authenticate(ctx, app.AuthenticateCommand{
		Identifier:     req.Msg.GetIdentifier(),
		Password:       req.Msg.GetPassword(),
		Code:           req.Msg.GetCode(),
		DeviceID:       req.Msg.GetDeviceId(),
		IdempotencyKey: key + authenticateKeySuffix,
	})
	if err != nil {
		return nil, fail(err)
	}

	session, err := s.authn.CreateSession(ctx, app.CreateSessionCommand{
		Proof:          attempt.Proof,
		DeviceID:       req.Msg.GetDeviceId(),
		IdempotencyKey: key + sessionKeySuffix,
	})
	if err != nil {
		return nil, fail(err)
	}

	// The plaintext token is copied straight from the result into the response and
	// touched by nothing else. It is returned by this call and by no other, ever.
	return connect.NewResponse(&identityv1.CreateSessionResponse{
		SessionId:                  session.SessionID.String(),
		SubjectId:                  session.SubjectID,
		Token:                      session.Token,
		AssuranceLevel:             protoAAL(session.AAL),
		IdleExpiresAt:              timestamppb.New(session.IdleExpiresAt.UTC()),
		AbsoluteExpiresAt:          timestamppb.New(session.AbsoluteExpiresAt.UTC()),
		RequiresCredentialRotation: session.RequiresCredentialRotation,
	}), nil
}

// The two derived idempotency keys CreateSession uses. Constants rather than
// literals so the pair cannot drift apart, and suffixed rather than prefixed so
// the client's own key stays readable at the head of both.
const (
	authenticateKeySuffix = ":authenticate"
	sessionKeySuffix      = ":session"
)
