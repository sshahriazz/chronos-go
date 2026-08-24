package api

import (
	"context"

	connect "connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/errs"
)

// passkeySuffix namespaces the session's event ids when a passkey login mints
// one.
//
// The client's one key drives both the login's own append and the session's, so
// without a suffix the two would derive identical event ids and the second
// append would collapse into the first.
const passkeySuffix = ":session"

// unconfigured is the answer every passkey RPC gives when WebAuthn is not set
// up.
//
// # Why passkeys are optional when nothing else here is
//
// Every other collaborator on this service is refused as nil at construction,
// because a nil serves a panic to whoever reaches that screen. Passkeys are the
// exception, and the reason is that they cannot be given a default: the
// relying-party id is BOUND INTO every credential at registration and can never
// be changed, so a defaulted one would be a value somebody deploys without
// noticing and discovers when every passkey in the installation stops working.
//
// So an unconfigured deployment serves these six RPCs with this error rather
// than refusing to start. It names the variables, because the only person who
// can act on it is whoever configures the deployment.
func unconfigured() error {
	// NOT_FOUND rather than a new reason. The endpoint does not exist on this
	// deployment, which is what NOT_FOUND says — and adding a reason to the
	// catalogue for a configuration state would make "passkeys are off here" a
	// documented part of the API's error surface rather than a property of one
	// installation.
	return errs.NotFoundf("passkeys are not configured on this deployment; set " +
		"IDENTITY_WEBAUTHN_RP_ID and IDENTITY_WEBAUTHN_ORIGINS")
}

// BeginPasskeyRegistration starts enrolling an authenticator.
func (s *Service) BeginPasskeyRegistration(
	ctx context.Context, _ *connect.Request[identityv1.BeginPasskeyRegistrationRequest],
) (*connect.Response[identityv1.BeginPasskeyRegistrationResponse], error) {
	if s.passkeys == nil {
		return nil, fail(unconfigured())
	}
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	got, err := s.passkeys.BeginRegistration(ctx, app.BeginRegistrationCommand{
		SubjectID: subjectID,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.BeginPasskeyRegistrationResponse{
		CeremonyId:  got.ChallengeID,
		OptionsJson: string(got.Options),
		ExpiresAt:   timestamppb.New(got.ExpiresAt.UTC()),
	}), nil
}

// FinishPasskeyRegistration verifies the authenticator's answer.
func (s *Service) FinishPasskeyRegistration(
	ctx context.Context, req *connect.Request[identityv1.FinishPasskeyRegistrationRequest],
) (*connect.Response[identityv1.FinishPasskeyRegistrationResponse], error) {
	if s.passkeys == nil {
		return nil, fail(unconfigured())
	}
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	got, err := s.passkeys.FinishRegistration(ctx, app.FinishRegistrationCommand{
		SubjectID:      subjectID,
		ChallengeID:    req.Msg.GetCeremonyId(),
		Response:       []byte(req.Msg.GetResponseJson()),
		Label:          req.Msg.GetLabel(),
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}
	// The recovery codes are copied straight from the result into the response
	// and touched by nothing else. They are returned by this call and by no
	// other, ever — only their digests are stored.
	return connect.NewResponse(&identityv1.FinishPasskeyRegistrationResponse{
		CredentialId:  got.CredentialID,
		RecoveryCodes: got.RecoveryCodes,
		Activated:     got.Activated,
	}), nil
}

// BeginPasskeyLogin starts a usernameless sign-in.
//
// Public, and it looks up nothing: no account is named and none is resolved, so
// the response is identical whether or not any account exists.
func (s *Service) BeginPasskeyLogin(
	ctx context.Context, _ *connect.Request[identityv1.BeginPasskeyLoginRequest],
) (*connect.Response[identityv1.BeginPasskeyLoginResponse], error) {
	if s.passkeys == nil {
		return nil, fail(unconfigured())
	}
	got, err := s.passkeys.BeginLogin(ctx, app.BeginLoginCommand{})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.BeginPasskeyLoginResponse{
		CeremonyId:  got.ChallengeID,
		OptionsJson: string(got.Options),
		ExpiresAt:   timestamppb.New(got.ExpiresAt.UTC()),
	}), nil
}

// FinishPasskeyLogin verifies an assertion and mints a session.
//
// Two calls, and the split is the same one CreateSession makes: the ceremony
// produces a Proof, and the session is minted from it. Nothing else can mint one
// — a zero Proof mints nothing — so the assurance level the ceremony reached is
// carried into the session rather than asserted alongside it.
func (s *Service) FinishPasskeyLogin(
	ctx context.Context, req *connect.Request[identityv1.FinishPasskeyLoginRequest],
) (*connect.Response[identityv1.FinishPasskeyLoginResponse], error) {
	if s.passkeys == nil {
		return nil, fail(unconfigured())
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	attempt, err := s.passkeys.FinishLogin(ctx, app.FinishLoginCommand{
		ChallengeID:    req.Msg.GetCeremonyId(),
		Response:       []byte(req.Msg.GetResponseJson()),
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}

	session, err := s.authn.CreateSession(ctx, app.CreateSessionCommand{
		Proof:          attempt.Proof,
		DeviceID:       req.Msg.GetDeviceId(),
		IdempotencyKey: key + passkeySuffix,
	})
	if err != nil {
		return nil, fail(err)
	}

	// The plaintext token is copied straight from the result and touched by
	// nothing else, exactly as CreateSession's is.
	return connect.NewResponse(&identityv1.FinishPasskeyLoginResponse{
		Token:          session.Token,
		SessionId:      session.SessionID.String(),
		AssuranceLevel: protoAAL(session.AAL),
		// Reported, not enforced. The assurance level above already carries the
		// reduction; this is what lets a client say WHY the person is being asked
		// to step up.
		CloneWarning: attempt.CloneWarned,
		ExpiresAt:    timestamppb.New(session.IdleExpiresAt.UTC()),
	}), nil
}

// ListPasskeys shows the caller their own authenticators.
func (s *Service) ListPasskeys(
	ctx context.Context, _ *connect.Request[identityv1.ListPasskeysRequest],
) (*connect.Response[identityv1.ListPasskeysResponse], error) {
	if s.passkeys == nil {
		return nil, fail(unconfigured())
	}
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	stored, err := s.passkeys.ListPasskeys(ctx, subjectID)
	if err != nil {
		return nil, fail(err)
	}

	out := make([]*identityv1.Passkey, 0, len(stored))
	for _, p := range stored {
		out = append(out, &identityv1.Passkey{
			CredentialId:   p.CredentialID,
			Label:          p.Label,
			CreatedAt:      timestamppb.New(p.RegisteredAt.UTC()),
			LastUsedAt:     optionalTime(p.LastUsedAt),
			BackupEligible: p.BackupEligible,
			BackupState:    p.BackupState,
			CloneWarnedAt:  optionalTime(p.CloneWarnedAt),
		})
	}
	return connect.NewResponse(&identityv1.ListPasskeysResponse{Passkeys: out}), nil
}

// RemovePasskey deletes one of the caller's authenticators.
func (s *Service) RemovePasskey(
	ctx context.Context, req *connect.Request[identityv1.RemovePasskeyRequest],
) (*connect.Response[identityv1.RemovePasskeyResponse], error) {
	if s.passkeys == nil {
		return nil, fail(unconfigured())
	}
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}
	if err := s.passkeys.RemovePasskey(ctx, app.RemovePasskeyCommand{
		SubjectID:      subjectID,
		CredentialID:   req.Msg.GetCredentialId(),
		IdempotencyKey: key,
	}); err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&identityv1.RemovePasskeyResponse{}), nil
}
