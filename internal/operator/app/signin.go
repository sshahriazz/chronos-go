package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/operator/contract"
	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/secret"
)

// Durations for the two stages, and why each is what it is.
const (
	// CeremonyTTL bounds a sign-in step in flight. Five minutes is a person
	// completing an IdP redirect or touching an authenticator, with margin for
	// a password manager prompt — not a window somebody parks a captured state
	// value in.
	CeremonyTTL = 5 * time.Minute

	// PendingTTL bounds the gap between the two factors. Deliberately the same
	// order as CeremonyTTL: it is the same human action, half-finished.
	PendingTTL = 5 * time.Minute

	// SessionTTL is how long a completed operator session lasts, ABSOLUTE.
	//
	// Thirty minutes, and it never moves. operator.md §3: "sessions are short
	// and non-extendable; no remember me". There is no refresh endpoint and no
	// idle deadline — an idle timeout that renews on activity IS extension, and
	// the pair of them is how a thirty-minute session becomes a working day.
	//
	// The cost is real: an operator working a long incident signs in again.
	// That is the trade operator.md makes on purpose, because the thing being
	// bounded is how long a stolen bearer reads every customer we have.
	SessionTTL = 30 * time.Minute

	// tokenBytes is the entropy in a bearer. 256 bits, machine-generated and
	// machine-checked, like the tenant plane's session token.
	tokenBytes = 32
)

// The two token purposes.
//
// `secret.Purpose` rather than a local string, because `secret.Digest` is what
// derives both — the platform already owns the construction, including the
// fixed-width length prefix that stops one purpose being made to overlap
// another by choosing a clever string.
//
// An earlier version of this file rolled its own SHA-256 with the same prefix.
// It was correct and it was a second copy of a security primitive, which is one
// more place for the prefix to be dropped in a refactor and one more place a
// reviewer has to check. There is one derivation in this codebase.
const (
	pendingTokenPurpose secret.Purpose = "chronos/operator/pending_token/v1"
	sessionTokenPurpose secret.Purpose = "chronos/operator/session_token/v1"
)

// IdentityProvider is the OIDC ceremony, as this package needs it.
//
// Narrowed to two methods from the adapter's larger surface, so the use case
// cannot reach configuration or a second provider.
type IdentityProvider interface {
	Begin() (ceremony IdPCeremony, err error)
	Finish(ctx context.Context, c IdPCeremony, cb IdPCallback) (IdPIdentity, error)
}

// IdPCeremony is one authorization request in flight — state, nonce and the
// PKCE verifier. None of it reaches the browser except the URL.
type IdPCeremony struct {
	AuthorizationURL string
	State            string
	Nonce            string
	Verifier         string
}

// IdPCallback is what the provider sent back.
type IdPCallback struct {
	Code   string
	State  string
	Issuer string
}

// IdPIdentity is what a completed ceremony proved.
type IdPIdentity struct {
	Issuer  string
	Subject string

	// Claims carries the provider-specific fields, including `hd` for a Google
	// Workspace account.
	Claims map[string]any
}

// Authenticator is the WebAuthn ceremony, as this package needs it.
type Authenticator interface {
	BeginRegistration(operatorID, label string, existing [][]byte) (WAChallenge, error)
	FinishRegistration(operatorID, label string, state []byte, credentialJSON []byte) (WARegistration, error)
	BeginLogin(operatorID string, stored []StoredCredential) (WAChallenge, error)
	FinishLogin(operatorID string, stored []StoredCredential, state []byte, credentialJSON []byte) (WAAssertion, error)
}

// WAChallenge is a WebAuthn ceremony in flight.
type WAChallenge struct {
	Options   []byte
	State     []byte
	ExpiresAt time.Time
}

// WARegistration is a completed enrolment.
type WARegistration struct {
	ID             string
	PublicKey      []byte
	SignCount      uint32
	AAGUID         []byte
	Transports     []string
	UserVerified   bool
	BackupEligible bool
	BackupState    bool
}

// WAAssertion is a completed login.
type WAAssertion struct {
	ID           string
	SignCount    uint32
	UserVerified bool
	CloneWarning bool
}

// SignIn is the two-stage sign-in operator.md §3 mandates.
type SignIn struct {
	idp     IdentityProvider
	wa      Authenticator
	accts   Accounts
	creds   Credentials
	sess    Sessions
	cers    Ceremonies
	events  EventAppender
	auditor *Auditor
	clock   Clock
	entropy io.Reader
	log     *slog.Logger
}

// SignInDeps is what the use case needs.
type SignInDeps struct {
	IdP           IdentityProvider
	Authenticator Authenticator
	Accounts      Accounts
	Credentials   Credentials
	Sessions      Sessions
	Ceremonies    Ceremonies
	Events        EventAppender
	Auditor       *Auditor
	Clock         Clock
	Entropy       io.Reader
	Log           *slog.Logger
}

// NewSignIn builds the use case.
func NewSignIn(d SignInDeps) (*SignIn, error) {
	switch {
	case d.IdP == nil:
		return nil, errors.New("operator: sign-in needs an identity provider")
	case d.Authenticator == nil:
		return nil, errors.New("operator: sign-in needs an authenticator")
	case d.Accounts == nil || d.Credentials == nil || d.Sessions == nil || d.Ceremonies == nil:
		return nil, errors.New("operator: sign-in needs its four stores")
	case d.Events == nil || d.Auditor == nil:
		return nil, errors.New("operator: sign-in needs to be able to record what happened")
	case d.Clock == nil:
		return nil, errors.New("operator: sign-in needs a clock")
	}
	entropy := d.Entropy
	if entropy == nil {
		entropy = rand.Reader
	}
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	return &SignIn{
		idp: d.IdP, wa: d.Authenticator,
		accts: d.Accounts, creds: d.Credentials, sess: d.Sessions, cers: d.Ceremonies,
		events: d.Events, auditor: d.Auditor, clock: d.Clock,
		entropy: entropy, log: log,
	}, nil
}

// BeginResult is where to send the browser.
type BeginResult struct {
	AuthorizationURL string
	CeremonyID       string
	ExpiresAt        time.Time
}

// Begin starts the OIDC ceremony.
//
// It names nobody and looks nobody up. An unauthenticated endpoint that
// resolved an operator would be an oracle for "does this person work on the
// back office", and the answer costs nothing to withhold: who is signing in is
// learned from the IdP's answer, which is the only source that can prove it.
func (s *SignIn) Begin(ctx context.Context) (BeginResult, error) {
	cer, err := s.idp.Begin()
	if err != nil {
		return BeginResult{}, fmt.Errorf("starting the operator sign-in ceremony: %w", err)
	}

	now := s.clock.Now()
	id := ids.New[ids.OperatorSession](now, s.entropy).String()
	expires := now.Add(CeremonyTTL)

	payload, err := codec.Marshal(oidcState{
		State:    cer.State,
		Nonce:    cer.Nonce,
		Verifier: cer.Verifier,
	})
	if err != nil {
		return BeginResult{}, fmt.Errorf("storing the ceremony: %w", err)
	}
	if err := s.cers.Store(ctx, id, CeremonyOIDC, "", payload, expires); err != nil {
		return BeginResult{}, fmt.Errorf("storing the ceremony: %w", err)
	}

	return BeginResult{AuthorizationURL: cer.AuthorizationURL, CeremonyID: id, ExpiresAt: expires}, nil
}

// oidcState is the ceremony's stored half. None of it reaches the browser.
type oidcState struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
}

// CompleteResult is the PENDING session — one that authorizes exactly the step
// that ends it.
type CompleteResult struct {
	PendingToken       string
	CredentialEnrolled bool
	ExpiresAt          time.Time
}

// Complete exchanges the IdP's code and issues the pending session.
//
// # The refusal is here, at the first step
//
// An operator who is unknown or disabled is refused BEFORE a pending token
// exists. The alternative — issue the token and refuse at the second step —
// would mean a valid Workspace login produces a credential on this plane, and
// every bug in the WebAuthn path would then be reachable by anybody in the
// company rather than by nobody.
//
// Both causes answer with ErrNotAnOperator, so a successful IdP login cannot be
// used to learn whether a named colleague has back-office access.
func (s *SignIn) Complete(ctx context.Context, ceremonyID string, cb IdPCallback) (CompleteResult, error) {
	now := s.clock.Now()

	_, payload, err := s.cers.Consume(ctx, ceremonyID, CeremonyOIDC, now)
	if err != nil {
		s.log.WarnContext(ctx, "an operator sign-in ceremony could not be redeemed",
			"ceremony_id", ceremonyID, "error", err)
		return CompleteResult{}, ErrCeremonyRefused
	}

	var st oidcState
	if err := codec.Into(payload, &st); err != nil {
		s.log.ErrorContext(ctx, "an operator ceremony's stored state did not decode",
			"ceremony_id", ceremonyID, "error", err)
		return CompleteResult{}, ErrCeremonyRefused
	}

	identity, err := s.idp.Finish(ctx, IdPCeremony{
		State: st.State, Nonce: st.Nonce, Verifier: st.Verifier,
	}, cb)
	if err != nil {
		s.log.WarnContext(ctx, "an operator sign-in was refused by the provider",
			"ceremony_id", ceremonyID, "error", err)
		return CompleteResult{}, ErrCeremonyRefused
	}

	rec, err := s.accts.ByBinding(ctx, identity.Issuer, identity.Subject)
	switch {
	case errors.Is(err, ErrNotAnOperator):
		// Logged at INFO with the issuer but NOT the subject. The subject
		// identifies a person, and this is the branch somebody probing would
		// hit repeatedly; a log line naming them would be a record of failed
		// sign-ins by people who are not our staff.
		s.log.InfoContext(ctx, "an authenticated identity has no operator account",
			"issuer", identity.Issuer)
		return CompleteResult{}, ErrNotAnOperator
	case err != nil:
		return CompleteResult{}, fmt.Errorf("resolving the operator: %w", err)
	case rec.Disabled():
		s.log.WarnContext(ctx, "a disabled operator attempted to sign in",
			"operator_id", rec.OperatorID)
		return CompleteResult{}, ErrNotAnOperator
	}

	count, err := s.creds.Count(ctx, rec.OperatorID)
	if err != nil {
		return CompleteResult{}, fmt.Errorf("counting authenticators: %w", err)
	}

	token, digest, err := s.mint(pendingTokenPurpose)
	if err != nil {
		return CompleteResult{}, err
	}
	expires := now.Add(PendingTTL)
	sessionID := ids.New[ids.OperatorSession](now, s.entropy).String()

	if err := s.sess.Issue(ctx, NewSession{
		Digest:     digest,
		SessionID:  sessionID,
		OperatorID: rec.OperatorID,
		Stage:      StageSSOOnly,
		ExpiresAt:  expires,
	}); err != nil {
		return CompleteResult{}, fmt.Errorf("issuing a pending session: %w", err)
	}

	return CompleteResult{
		PendingToken:       token,
		CredentialEnrolled: count > 0,
		ExpiresAt:          expires,
	}, nil
}

// ChallengeResult is what the browser needs for the second factor.
type ChallengeResult struct {
	OptionsJSON []byte
	Enrolment   bool
	CeremonyID  string
}

// BeginSecondFactor issues either an assertion challenge or, for an operator
// with no authenticator yet, a registration challenge.
//
// # The bootstrap window, and why it is one-way
//
// A freshly provisioned operator has passed SSO and holds no credential, so the
// factor they must present is one they cannot yet have. The window is the same
// deadlock `bootstrap_min_aal` resolves on the tenant plane, resolved the same
// way: the condition is read SERVER-SIDE from the credential count, never
// asserted by the caller, and enrolling the first credential closes it.
//
// It does NOT re-open when an operator's credentials are removed. If it did,
// anybody who could delete an operator's authenticators could then enrol their
// own — turning credential loss into account takeover. Recovery is an
// operator_admin re-provisioning, which is a second person's audited act.
func (s *SignIn) BeginSecondFactor(ctx context.Context, sess SessionRecord) (ChallengeResult, error) {
	if sess.Stage != StageSSOOnly {
		return ChallengeResult{}, ErrSessionRefused
	}

	stored, err := s.creds.List(ctx, sess.OperatorID)
	if err != nil {
		return ChallengeResult{}, fmt.Errorf("reading authenticators: %w", err)
	}

	now := s.clock.Now()
	id := ids.New[ids.OperatorSession](now, s.entropy).String()

	if len(stored) == 0 {
		existing := make([][]byte, 0)
		ch, err := s.wa.BeginRegistration(sess.OperatorID, "", existing)
		if err != nil {
			return ChallengeResult{}, fmt.Errorf("starting enrolment: %w", err)
		}
		if err := s.cers.Store(ctx, id, CeremonyWebAuthnEnrol, sess.OperatorID,
			ch.State, now.Add(CeremonyTTL)); err != nil {
			return ChallengeResult{}, fmt.Errorf("storing the enrolment ceremony: %w", err)
		}
		return ChallengeResult{OptionsJSON: ch.Options, Enrolment: true, CeremonyID: id}, nil
	}

	ch, err := s.wa.BeginLogin(sess.OperatorID, stored)
	if err != nil {
		return ChallengeResult{}, fmt.Errorf("starting an assertion: %w", err)
	}
	if err := s.cers.Store(ctx, id, CeremonyWebAuthnLogin, sess.OperatorID,
		ch.State, now.Add(CeremonyTTL)); err != nil {
		return ChallengeResult{}, fmt.Errorf("storing the assertion ceremony: %w", err)
	}
	return ChallengeResult{OptionsJSON: ch.Options, CeremonyID: id}, nil
}

// SessionResult is the session that actually works.
type SessionResult struct {
	Token      string
	OperatorID string
	Role       contract.Role
	ExpiresAt  time.Time
}

// FinishSecondFactor verifies the authenticator's answer and issues the live
// session.
//
// # Four properties, each one a decision
//
//  1. USER VERIFICATION IS REQUIRED. An assertion that proves only possession
//     is one factor wearing the shape of two, and operator.md §3 mandates
//     hardware-backed MFA with no fallback.
//  2. The token is a NEW secret, not a promotion of the pending one. A bearer
//     whose privileges change during its life is one a proxy log, a browser
//     extension or a client may have captured before the change.
//  3. The pending session is ENDED, whatever happens next. Leaving it live
//     would mean a failed second factor still leaves a usable ceremony token.
//  4. The sign-in is audited AFTER the session exists and BEFORE it is
//     returned, so there is no state in which an operator holds a working
//     session that the audit log does not record.
func (s *SignIn) FinishSecondFactor(
	ctx context.Context, sess SessionRecord, pendingDigest []byte,
	ceremonyID string, credentialJSON []byte, label, fromIP string,
) (SessionResult, error) {
	if sess.Stage != StageSSOOnly {
		return SessionResult{}, ErrSessionRefused
	}
	now := s.clock.Now()

	// Property 3, and it runs first so every path below leaves the pending
	// session dead — including the ones that return an error.
	defer func() {
		if _, err := s.sess.End(ctx, pendingDigest, now); err != nil {
			s.log.ErrorContext(ctx, "a pending operator session could not be ended",
				"operator_id", sess.OperatorID, "error", err)
		}
	}()

	operatorID, state, err := s.consumeCeremony(ctx, ceremonyID, sess.OperatorID, now)
	if err != nil {
		return SessionResult{}, err
	}
	_ = operatorID

	credentialID, err := s.verify(ctx, sess, ceremonyID, state, credentialJSON, label, now)
	if err != nil {
		return SessionResult{}, err
	}

	rec, err := s.accts.ByID(ctx, sess.OperatorID)
	switch {
	case errors.Is(err, ErrNotAnOperator):
		return SessionResult{}, ErrNotAnOperator
	case err != nil:
		return SessionResult{}, fmt.Errorf("resolving the operator: %w", err)
	case rec.Disabled():
		// Reachable: the operator was offboarded between the two factors.
		return SessionResult{}, ErrNotAnOperator
	}

	token, digest, err := s.mint(sessionTokenPurpose)
	if err != nil {
		return SessionResult{}, err
	}
	expires := now.Add(SessionTTL)
	sessionID := ids.New[ids.OperatorSession](now, s.entropy).String()

	if err := s.sess.Issue(ctx, NewSession{
		Digest:       digest,
		SessionID:    sessionID,
		OperatorID:   rec.OperatorID,
		Stage:        StageLive,
		ExpiresAt:    expires,
		FromIP:       fromIP,
		CredentialID: credentialID,
	}); err != nil {
		return SessionResult{}, fmt.Errorf("issuing an operator session: %w", err)
	}

	if _, err := s.auditor.RecordSignIn(ctx, Actor{
		OperatorID: rec.OperatorID,
		SubjectID:  rec.SubjectID,
		Role:       rec.Role,
		SessionID:  sessionID,
		FromIP:     fromIP,
	}, credentialID); err != nil {
		// Property 4: the session exists and the audit does not, so the session
		// is ended before this returns. An operator plane whose sign-ins can go
		// unrecorded is one whose audit log cannot be used as evidence.
		if _, endErr := s.sess.End(ctx, digest, now); endErr != nil {
			s.log.ErrorContext(ctx, "an unaudited operator session could not be ended",
				"operator_id", rec.OperatorID, "error", endErr)
		}
		return SessionResult{}, fmt.Errorf("recording the sign-in: %w", err)
	}

	return SessionResult{
		Token: token, OperatorID: rec.OperatorID, Role: rec.Role, ExpiresAt: expires,
	}, nil
}

// consumeCeremony redeems the WebAuthn ceremony, of either kind, and refuses
// one that belongs to a different operator.
func (s *SignIn) consumeCeremony(
	ctx context.Context, ceremonyID, operatorID string, now time.Time,
) (string, []byte, error) {
	for _, kind := range []CeremonyKind{CeremonyWebAuthnLogin, CeremonyWebAuthnEnrol} {
		owner, payload, err := s.cers.Consume(ctx, ceremonyID, kind, now)
		if err != nil {
			continue
		}
		if owner != operatorID {
			// A ceremony redeemed by a session it was not issued to. Logged at
			// ERROR because there is no benign cause: the ids are unguessable
			// and single-use.
			s.log.ErrorContext(ctx, "an operator ceremony was presented by a different session",
				"ceremony_id", ceremonyID, "issued_to", owner, "presented_by", operatorID)
			return "", nil, ErrCeremonyRefused
		}
		return owner, payload, nil
	}
	s.log.WarnContext(ctx, "an operator WebAuthn ceremony could not be redeemed",
		"ceremony_id", ceremonyID, "operator_id", operatorID)
	return "", nil, ErrCeremonyRefused
}

// verify runs the assertion or the enrolment and returns the credential id.
func (s *SignIn) verify(
	ctx context.Context, sess SessionRecord, ceremonyID string, state, credentialJSON []byte,
	label string, now time.Time,
) (string, error) {
	stored, err := s.creds.List(ctx, sess.OperatorID)
	if err != nil {
		return "", fmt.Errorf("reading authenticators: %w", err)
	}

	if len(stored) == 0 {
		reg, err := s.wa.FinishRegistration(sess.OperatorID, label, state, credentialJSON)
		if err != nil {
			s.log.WarnContext(ctx, "an operator enrolment did not verify",
				"operator_id", sess.OperatorID, "error", err)
			return "", ErrCeremonyRefused
		}
		if !reg.UserVerified {
			// Property 1, on the enrolment path. An authenticator registered
			// without user verification can never produce a verified assertion,
			// so accepting it here would enrol a credential that permanently
			// cannot satisfy the policy — and the operator would discover that
			// at their next sign-in, locked out, with no diagnosis.
			s.log.WarnContext(ctx, "an operator enrolment proved possession only",
				"operator_id", sess.OperatorID)
			return "", ErrCeremonyRefused
		}
		if err := s.creds.Insert(ctx, NewCredential{
			ID: reg.ID, OperatorID: sess.OperatorID, PublicKey: reg.PublicKey,
			SignCount: reg.SignCount, AAGUID: reg.AAGUID, Transports: reg.Transports,
			BackupEligible: reg.BackupEligible, BackupState: reg.BackupState,
			Label: label,
		}); err != nil {
			return "", fmt.Errorf("storing the authenticator: %w", err)
		}
		if err := s.events.AppendOperator(ctx, sess.OperatorID, &contract.OperatorCredentialEnrolled{
			OperatorID:     sess.OperatorID,
			SubjectID:      sess.SubjectID,
			CredentialID:   reg.ID,
			AAGUID:         base64.RawURLEncoding.EncodeToString(reg.AAGUID),
			BackupEligible: reg.BackupEligible,
			EnrolledAt:     now.UTC(),
		}); err != nil {
			return "", fmt.Errorf("recording the enrolment: %w", err)
		}
		return reg.ID, nil
	}

	assertion, err := s.wa.FinishLogin(sess.OperatorID, stored, state, credentialJSON)
	if err != nil {
		s.log.WarnContext(ctx, "an operator assertion did not verify",
			"operator_id", sess.OperatorID, "error", err)
		return "", ErrCeremonyRefused
	}
	if !assertion.UserVerified {
		s.log.WarnContext(ctx, "an operator assertion proved possession only",
			"operator_id", sess.OperatorID, "credential_id", assertion.ID)
		return "", ErrCeremonyRefused
	}

	if assertion.CloneWarning {
		// READ, not ignored — the failure this repository shipped three times.
		//
		// On the TENANT plane a counter regression forces step-up rather than
		// denying, because the spec lists an out-of-order race as a benign
		// cause. Here it DENIES: an operator has one authenticator per device,
		// concurrent operator sessions are not the norm, and the fallback the
		// tenant plane steps up to does not exist on a plane with no password.
		if err := s.creds.FlagClone(ctx, assertion.ID); err != nil {
			s.log.ErrorContext(ctx, "an operator clone warning could not be recorded",
				"credential_id", assertion.ID, "error", err)
		}
		s.log.ErrorContext(ctx, "an operator authenticator's signature counter went backwards",
			"operator_id", sess.OperatorID, "credential_id", assertion.ID)
		return "", ErrCeremonyRefused
	}

	moved, err := s.creds.Advance(ctx, assertion.ID, assertion.SignCount)
	if err != nil {
		return "", fmt.Errorf("advancing the signature counter: %w", err)
	}
	if !moved {
		// The counter did not advance. Normal for a synced passkey, which
		// reports 0 permanently — Apple and Google both do, because there is no
		// coherent place to keep a monotonic counter across N devices.
		if err := s.creds.Touch(ctx, assertion.ID); err != nil {
			s.log.WarnContext(ctx, "an operator credential's last use could not be recorded",
				"credential_id", assertion.ID, "error", err)
		}
	}
	return assertion.ID, nil
}

// SignOut ends the caller's own session.
func (s *SignIn) SignOut(ctx context.Context, actor Actor, digest []byte) (bool, error) {
	now := s.clock.Now()
	changed, err := s.sess.End(ctx, digest, now)
	if err != nil {
		return false, fmt.Errorf("ending the session: %w", err)
	}
	if !changed {
		// Already over. Idempotent, and the audit records nothing: no session
		// ended, so there is no action to attribute.
		return false, nil
	}
	if _, err := s.auditor.RecordSignOut(ctx, actor); err != nil {
		// The session IS ended — that succeeded and must not be undone, because
		// undoing it would resurrect a bearer the operator believes is dead.
		// The audit gap is reported rather than hidden.
		s.log.ErrorContext(ctx, "an operator sign-out could not be audited",
			"operator_id", actor.OperatorID, "error", err)
		return true, fmt.Errorf("recording the sign-out: %w", err)
	}
	return true, nil
}

// mint draws a bearer token and reduces it to what is stored.
//
// The plaintext goes to exactly one caller and the digest to the store, so
// there is no moment at which a token exists that nothing can resolve, and none
// at which a digest is stored for a token nobody was given.
func (s *SignIn) mint(purpose secret.Purpose) (string, []byte, error) {
	raw := make([]byte, tokenBytes)
	if _, err := io.ReadFull(s.entropy, raw); err != nil {
		// Refused, never degraded. A short read leaves trailing zero bytes, and
		// a token whose tail is predictable is one an attacker can search while
		// its holder believes they have 256 bits.
		return "", nil, fmt.Errorf("generating an operator token: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(raw)
	return plaintext, secret.Digest(purpose, plaintext), nil
}

// PendingDigest and SessionDigest reduce a presented bearer to what the session
// table holds, under the two purposes.
//
// Exported so the interceptor can derive one without knowing the purpose
// strings — which is what lets it choose the domain from the DECLARED ACCESS
// rather than from the token, so a pending bearer presented to an ordinary
// method hashes to something no row holds.
//
// Both go through `secret.Digest`, which is SHA-256 rather than a slow hash for
// the reason the tenant plane's session token uses the same: the token is 256
// bits from crypto/rand, so there is no candidate list to search and a
// memory-hard hash would add tens of milliseconds to every authenticated
// request while buying nothing.
func PendingDigest(plaintext string) []byte {
	return secret.Digest(pendingTokenPurpose, plaintext)
}

// SessionDigest reduces a live-session bearer.
func SessionDigest(plaintext string) []byte {
	return secret.Digest(sessionTokenPurpose, plaintext)
}
