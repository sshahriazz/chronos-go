// Package webauthn is the only place in this repository that knows the WebAuthn
// library exists.
//
// The import contract keeps `github.com/go-webauthn/webauthn` out of the kernel,
// out of every domain and out of every use case, and the reason outlives the
// lint rule: a use case that imported it could not be exercised without
// constructing browser ceremony payloads, and the decision it makes — "this
// account now has a passkey" — has nothing to do with how the signature was
// checked.
package webauthn

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	lib "github.com/go-webauthn/webauthn/webauthn"
)

// Ceremony performs WebAuthn registration and authentication.
//
// It holds no state between calls. The challenge a ceremony issues is handed
// back to the caller to store and to return, because a server that kept
// ceremonies in memory would fail every one of them the moment a second replica
// existed or a process restarted mid-login.
type Ceremony struct {
	w *lib.WebAuthn
}

// Config is what the ceremony needs to know about this deployment.
type Config struct {
	// RPID is the Relying Party ID — the registrable domain, with no scheme and
	// no port.
	//
	// It is BOUND INTO every credential at registration and cannot be changed
	// afterwards: a passkey created for `chronos.example` will not authenticate
	// against `app.chronos.example`, and every existing passkey stops working the
	// day this value moves. That is not a bug to work around, it is the anti-
	// phishing property the whole mechanism rests on.
	RPID string

	// RPDisplayName is what the authenticator shows the person while they
	// approve. It is display-only and may change freely.
	RPDisplayName string

	// Origins are the full origins a ceremony may come from, scheme and port
	// included.
	//
	// Checked against the origin the browser reports, which is what makes a
	// credential unusable from an attacker's page even if the person is fooled
	// into visiting it. An empty list is refused rather than defaulted: a
	// permissive default here would silently remove the phishing resistance that
	// is the reason to prefer passkeys at all.
	Origins []string

	// Timeout bounds a ceremony. Zero takes DefaultTimeout.
	Timeout time.Duration
}

// DefaultTimeout is how long a browser is given to complete a ceremony.
//
// Two minutes: long enough to find a security key in a bag or to be prompted for
// a fingerprint twice, short enough that an abandoned challenge is not a
// credential-shaped hole left open on a shared machine.
const DefaultTimeout = 2 * time.Minute

// New builds a ceremony.
func New(cfg Config) (*Ceremony, error) {
	switch {
	case cfg.RPID == "":
		return nil, errors.New("webauthn: a relying-party id is required; it is bound into " +
			"every credential at registration and cannot be changed afterwards")
	case len(cfg.Origins) == 0:
		return nil, errors.New("webauthn: at least one origin is required; the origin check " +
			"is what makes a passkey unusable from an attacker's page, and defaulting it " +
			"would remove the phishing resistance that is the reason to prefer passkeys")
	}
	if cfg.RPDisplayName == "" {
		cfg.RPDisplayName = cfg.RPID
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}

	w, err := lib.New(&lib.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.Origins,
		Timeouts: lib.TimeoutsConfig{
			Registration: lib.TimeoutConfig{Enforce: true, Timeout: cfg.Timeout},
			Login:        lib.TimeoutConfig{Enforce: true, Timeout: cfg.Timeout},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}
	return &Ceremony{w: w}, nil
}

// Account is what a ceremony needs to know about the person.
//
// A PSEUDONYM and a handle, never an address. The user handle travels to the
// authenticator and is stored by it permanently — synced to a cloud backup and
// shown on a lock screen — which is the same place identity.md §5 refuses to put
// an email in a TOTP label, for the same reason: it is the one store ADR-002 can
// never reach to erase.
type Account struct {
	// SubjectID is the pseudonym, used as the WebAuthn user handle.
	SubjectID string

	// Username is the public handle (ADR-051), shown by the authenticator while
	// the person chooses which credential to use. Public by design.
	Username string

	// Existing are the credential ids this account already holds, so a
	// registration can EXCLUDE them and a login can allow them.
	Existing [][]byte
}

// libUser adapts Account to the library's interface.
type libUser struct {
	account     Account
	credentials []lib.Credential
}

func (u libUser) WebAuthnID() []byte          { return []byte(u.account.SubjectID) }
func (u libUser) WebAuthnName() string        { return u.account.Username }
func (u libUser) WebAuthnDisplayName() string { return u.account.Username }
func (u libUser) WebAuthnCredentials() []lib.Credential {
	return u.credentials
}

// Challenge is a ceremony in flight.
//
// The OPTIONS go to the browser and the STATE is stored by the caller until the
// browser answers. They are separate fields because they must not travel to the
// same place: the options are public and the state carries the challenge that
// makes a replay impossible.
type Challenge struct {
	// Options is the JSON a browser passes to navigator.credentials.
	Options []byte

	// State is opaque to everyone but this package. The caller stores it and
	// hands it back; nothing else may interpret it.
	State []byte

	// ExpiresAt is when the ceremony stops being redeemable.
	ExpiresAt time.Time
}

// RegisteredCredential is what a completed registration produced.
type RegisteredCredential struct {
	// ID is the credential id, base64url — the form the database stores and the
	// form an allowCredentials list carries.
	ID string

	// PublicKey is the COSE key. Verification material: it is stored and never
	// displayed, logged or placed in an event.
	PublicKey []byte

	SignCount uint32
	AAGUID    []byte

	// Transports are hints — "usb", "internal", "hybrid" — that let a browser
	// prompt for the right thing rather than offering every option.
	Transports []string

	// UserVerified reports whether a PIN or a biometric was proven, not merely
	// that the authenticator was present. It decides AAL2 versus AAL1
	// (identity.md §2).
	UserVerified bool

	// BackupEligible and BackupState describe SYNCING. A synced passkey exists
	// on every device the person's provider account touches, which is why SP
	// 800-63B-4 Appendix B forbids one at AAL3.
	BackupEligible bool
	BackupState    bool
}

// BeginRegistration starts an enrolment.
//
// # The three options are all deliberate
//
// DISCOVERABLE (resident) credentials, so the authenticator can offer the
// account without the person typing an identifier first — identity.md §5's
// usernameless login. USER VERIFICATION preferred rather than required: required
// would refuse security keys with no PIN configured, and preferred still yields
// UV on every platform authenticator, which is where AAL2 comes from. ATTESTATION
// none, because Apple and Google return no attestation statement for synced
// passkeys, so requesting `direct` silently no-ops on the two platforms most
// people use — and storing an attestation this system cannot act on would imply
// a capability it does not have (ADR-057, IDENTITY-REVIEW C4).
//
// EXCLUSIONS are the account's existing credentials, so an authenticator that
// already holds one for this account says so instead of creating a second.
func (c *Ceremony) BeginRegistration(a Account) (Challenge, error) {
	if a.SubjectID == "" {
		return Challenge{}, errors.New("webauthn: a subject is required")
	}
	user := libUser{account: a, credentials: credentialsFor(a.Existing)}

	creation, session, err := c.w.BeginRegistration(user,
		lib.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationPreferred,
		}),
		lib.WithConveyancePreference(protocol.PreferNoAttestation),
		lib.WithExclusions(descriptorsFor(a.Existing)),
	)
	if err != nil {
		return Challenge{}, fmt.Errorf("webauthn: beginning registration: %w", err)
	}
	return marshalChallenge(creation, session)
}

// FinishRegistration verifies the authenticator's answer.
func (c *Ceremony) FinishRegistration(
	a Account, state []byte, response []byte,
) (RegisteredCredential, error) {
	session, err := unmarshalState(state)
	if err != nil {
		return RegisteredCredential{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(string(response)))
	if err != nil {
		// The browser's payload did not parse. Reported as a refusal rather than
		// an internal error: it is the caller's input.
		return RegisteredCredential{}, fmt.Errorf("%w: %w", ErrCeremonyRefused, err)
	}

	user := libUser{account: a, credentials: credentialsFor(a.Existing)}
	cred, err := c.w.CreateCredential(user, *session, parsed)
	if err != nil {
		return RegisteredCredential{}, fmt.Errorf("%w: %w", ErrCeremonyRefused, err)
	}

	return RegisteredCredential{
		ID:             base64.RawURLEncoding.EncodeToString(cred.ID),
		PublicKey:      cred.PublicKey,
		SignCount:      cred.Authenticator.SignCount,
		AAGUID:         cred.Authenticator.AAGUID,
		Transports:     transportsOf(cred),
		UserVerified:   cred.Flags.UserVerified,
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
	}, nil
}

// Assertion is what a completed login produced.
type Assertion struct {
	// ID is the credential that signed, base64url.
	ID string

	// SignCount is the counter the authenticator presented.
	SignCount uint32

	// UserVerified decides whether this login is AAL2 or AAL1.
	UserVerified bool

	// CloneWarning is the reason this struct exists rather than a bare error.
	//
	// The library sets it when the presented counter did NOT exceed the stored
	// one, and returns NO ERROR — so a caller that ignores it has clone detection
	// that does nothing while every test passes. It is surfaced here as a value
	// the caller must handle, not a flag buried in a library type it never sees.
	CloneWarning bool
}

// BeginLogin starts an authentication for a known account.
func (c *Ceremony) BeginLogin(a Account, stored []StoredCredential) (Challenge, error) {
	if len(stored) == 0 {
		return Challenge{}, ErrNoCredentials
	}
	user := libUser{account: a, credentials: toLibCredentials(stored)}
	assertion, session, err := c.w.BeginLogin(user)
	if err != nil {
		return Challenge{}, fmt.Errorf("webauthn: beginning login: %w", err)
	}
	return marshalChallenge(assertion, session)
}

// FinishLogin verifies an assertion against a stored credential.
//
// The stored SIGN COUNT goes in and the presented one comes back, because the
// monotonic comparison is the DATABASE's — an atomic `UPDATE … WHERE sign_count
// < $new`. Doing it here would be a read-modify-write that two concurrent logins
// can both win (ADR-057).
func (c *Ceremony) FinishLogin(
	a Account, stored []StoredCredential, state []byte, response []byte,
) (Assertion, error) {
	session, err := unmarshalState(state)
	if err != nil {
		return Assertion{}, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(string(response)))
	if err != nil {
		return Assertion{}, fmt.Errorf("%w: %w", ErrCeremonyRefused, err)
	}

	user := libUser{account: a, credentials: toLibCredentials(stored)}
	cred, err := c.w.ValidateLogin(user, *session, parsed)
	if err != nil {
		return Assertion{}, fmt.Errorf("%w: %w", ErrCeremonyRefused, err)
	}

	return Assertion{
		ID:           base64.RawURLEncoding.EncodeToString(cred.ID),
		SignCount:    cred.Authenticator.SignCount,
		UserVerified: cred.Flags.UserVerified,
		// READ, not ignored. See Assertion.CloneWarning.
		CloneWarning: cred.Authenticator.CloneWarning,
	}, nil
}

// StoredCredential is one credential as the database holds it.
type StoredCredential struct {
	ID             string
	PublicKey      []byte
	SignCount      uint32
	AAGUID         []byte
	Transports     []string
	UserVerified   bool
	BackupEligible bool
	BackupState    bool
}

var (
	// ErrCeremonyRefused means the browser's answer did not verify. Every cause
	// — a bad signature, a wrong origin, an expired challenge, a replayed one —
	// is deliberately one error: telling a caller which check failed tells an
	// attacker which one to work on.
	ErrCeremonyRefused = errors.New("webauthn: this ceremony could not be verified")

	// ErrNoCredentials means the account holds no passkey to authenticate with.
	ErrNoCredentials = errors.New("webauthn: this account has no passkey")
)
