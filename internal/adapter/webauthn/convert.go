package webauthn

import (
	"encoding/base64"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	lib "github.com/go-webauthn/webauthn/webauthn"

	"github.com/chronos/chronos-go/internal/platform/codec"
)

// marshalChallenge splits a ceremony into what the browser gets and what the
// caller stores.
//
// They are marshalled separately because they must not travel together: the
// options are public, and the session carries the challenge that makes a replay
// impossible. Returning one blob would invite a caller to hand the whole thing
// to the browser.
func marshalChallenge(options any, session *lib.SessionData) (Challenge, error) {
	opts, err := codec.Marshal(options)
	if err != nil {
		return Challenge{}, fmt.Errorf("webauthn: encoding the ceremony options: %w", err)
	}
	state, err := codec.Marshal(session)
	if err != nil {
		return Challenge{}, fmt.Errorf("webauthn: encoding the ceremony state: %w", err)
	}
	return Challenge{Options: opts, State: state, ExpiresAt: session.Expires}, nil
}

// unmarshalState reads back what the caller stored.
//
// A decode failure is a REFUSAL rather than an internal error: the state comes
// back from wherever the caller kept it, so a corrupt one is untrusted input.
func unmarshalState(state []byte) (*lib.SessionData, error) {
	if len(state) == 0 {
		return nil, fmt.Errorf("%w: no ceremony state", ErrCeremonyRefused)
	}
	// TOLERANT, and the choice is the point ADR-047 forces into the name. The
	// state was written by THIS package and read back by it, so a strict decode
	// looks right — but a rolling deploy has two builds alive at once, and a
	// ceremony begun by the newer one must not fail on the older simply because
	// the library added a field. A refused ceremony here is a person who cannot
	// sign in.
	session, err := codec.Tolerant[lib.SessionData](state)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCeremonyRefused, err)
	}
	return &session, nil
}

// credentialsFor builds the minimal credential set an EXCLUSION list needs.
//
// Ids only. A registration does not verify anything against an existing
// credential — it only refuses to create a second one on an authenticator that
// already holds one — so handing the library public keys here would be passing
// verification material to a call that has nothing to verify.
func credentialsFor(ids [][]byte) []lib.Credential {
	out := make([]lib.Credential, 0, len(ids))
	for _, id := range ids {
		out = append(out, lib.Credential{ID: id})
	}
	return out
}

// descriptorsFor turns credential ids into exclusion descriptors.
func descriptorsFor(ids [][]byte) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(ids))
	for _, id := range ids {
		out = append(out, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: id,
		})
	}
	return out
}

// toLibCredentials rebuilds the library's credentials from stored rows.
//
// This IS the verification path, so unlike credentialsFor it carries the public
// key and the sign count: the library checks the signature against the key and
// compares the counter to set CloneWarning.
func toLibCredentials(stored []StoredCredential) []lib.Credential {
	out := make([]lib.Credential, 0, len(stored))
	for _, s := range stored {
		id, err := base64.RawURLEncoding.DecodeString(s.ID)
		if err != nil {
			// A row whose id does not decode cannot have been written by this
			// code. Skipped rather than fatal: one corrupt row must not stop a
			// person authenticating with their other passkeys.
			continue
		}
		transports := make([]protocol.AuthenticatorTransport, 0, len(s.Transports))
		for _, t := range s.Transports {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
		out = append(out, lib.Credential{
			ID:        id,
			PublicKey: s.PublicKey,
			Transport: transports,
			Flags: lib.CredentialFlags{
				UserVerified:   s.UserVerified,
				BackupEligible: s.BackupEligible,
				BackupState:    s.BackupState,
			},
			Authenticator: lib.Authenticator{
				AAGUID:    s.AAGUID,
				SignCount: s.SignCount,
			},
		})
	}
	return out
}

// transportsOf reads the hints an authenticator reported.
func transportsOf(c *lib.Credential) []string {
	out := make([]string, 0, len(c.Transport))
	for _, t := range c.Transport {
		if t == "" {
			continue
		}
		out = append(out, string(t))
	}
	return out
}
