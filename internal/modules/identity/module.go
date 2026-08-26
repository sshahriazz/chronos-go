// Package identity is the module's composition surface: the two declarations
// every binary that touches identity events must make, in one place.
//
// They live here rather than in each cmd/ because there are three binaries —
// api, projector, worker — and a type registered in two of them is a projector
// that stops on an event the API can happily write. Drift between composition
// roots is not hypothetical in this repository; it is the failure that left
// three notification adapters wired into nothing.
package identity

import (
	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// RegisterEvents declares every identity event this build can DECODE.
//
// Registering an event the domain can no longer produce is harmless and
// necessary — the log still contains it. Failing to register one the log
// contains is a hard stop at read time, which is the correct direction for that
// mistake to fail in.
func RegisterEvents(codec *eventcodec.JSON) {
	// Email reservation — the uniqueness mechanism (ADR-044).
	eventcodec.Register[contract.EmailReserved](codec)
	eventcodec.Register[contract.EmailReservationConfirmed](codec)
	eventcodec.Register[contract.EmailReleased](codec)
	eventcodec.Register[contract.DuplicateRegistrationAttempted](codec)
	eventcodec.Register[contract.EmailReservationDemoted](codec)

	// Username reservation — the public handle's uniqueness mechanism (ADR-051).
	eventcodec.Register[contract.UsernameReserved](codec)
	eventcodec.Register[contract.UsernameTombstoned](codec)

	// Account lifecycle.
	eventcodec.Register[contract.UserRegistered](codec)
	eventcodec.Register[contract.EmailVerificationRequested](codec)
	eventcodec.Register[contract.EmailVerified](codec)
	eventcodec.Register[contract.EmailChangeRequested](codec)
	eventcodec.Register[contract.EmailChangeCancelled](codec)
	eventcodec.Register[contract.EmailChanged](codec)
	eventcodec.Register[contract.EmailChangeReverted](codec)
	eventcodec.Register[contract.UsernameAssigned](codec)
	eventcodec.Register[contract.UserActivated](codec)
	eventcodec.Register[contract.UserDeactivated](codec)
	eventcodec.Register[contract.UserReactivated](codec)
	eventcodec.Register[contract.UserSuspended](codec)
	eventcodec.Register[contract.UserDeletionRequested](codec)
	eventcodec.Register[contract.UserDeletionCancelled](codec)
	eventcodec.Register[contract.UserErased](codec)

	// Password.
	eventcodec.Register[contract.PasswordResetRequested](codec)
	eventcodec.Register[contract.PasswordSet](codec)
	eventcodec.Register[contract.PasswordChanged](codec)
	eventcodec.Register[contract.PasswordRehashed](codec)
	eventcodec.Register[contract.CredentialCompromiseDetected](codec)

	// Second factors.
	eventcodec.Register[contract.TotpEnrollmentStarted](codec)
	eventcodec.Register[contract.TotpEnabled](codec)
	eventcodec.Register[contract.TotpDisabled](codec)
	eventcodec.Register[contract.FederatedIdentityClaimed](codec)
	eventcodec.Register[contract.FederatedIdentityReleased](codec)
	eventcodec.Register[contract.FederatedIdentityLinked](codec)
	eventcodec.Register[contract.FederatedIdentityUnlinked](codec)
	eventcodec.Register[contract.PasskeyRegistered](codec)
	eventcodec.Register[contract.PasskeyRemoved](codec)
	eventcodec.Register[contract.PasskeyCloneWarning](codec)
	eventcodec.Register[contract.RecoveryCodesGenerated](codec)
	eventcodec.Register[contract.RecoveryCodeConsumed](codec)
	eventcodec.Register[contract.RecoveryCodesExhausted](codec)

	// Authentication outcomes.
	eventcodec.Register[contract.AuthenticationSucceeded](codec)
	eventcodec.Register[contract.AuthenticationFailed](codec)
	eventcodec.Register[contract.SecondFactorChallenged](codec)
	eventcodec.Register[contract.AuthenticatorDisabled](codec)

	// Sessions and devices.
	eventcodec.Register[contract.SessionCreated](codec)
	eventcodec.Register[contract.SessionElevated](codec)
	eventcodec.Register[contract.SessionRevoked](codec)
	eventcodec.Register[contract.SessionExpired](codec)
	eventcodec.Register[contract.DeviceRegistered](codec)

	// Service accounts and API keys (identity.md §10).
	eventcodec.Register[contract.ServiceAccountCreated](codec)
	eventcodec.Register[contract.ApiKeyCreated](codec)
	eventcodec.Register[contract.ApiKeyRotated](codec)
	eventcodec.Register[contract.ApiKeyRevoked](codec)
}

// RegisterSchemas declares the current schema version of every identity event
// (ADR-029).
//
// Everything is v1 and there are no upcasters, which is the correct state for a
// module whose first event has not yet been written. The function exists now,
// rather than when the first upcaster is needed, because the registry refuses to
// decode an unregistered type — so the alternative is discovering the omission
// from a projector that has already stopped.
//
// When a shape changes: bump the version here in the SAME commit as the field
// change, and add the Upcast call beside it. A version without an upcaster is a
// load failure, by design.
func RegisterSchemas(r *eventsourcing.UpcasterRegistry) {
	for _, t := range eventTypes() {
		r.Register(t, 1)
	}
}

// EventTypes is what this module declares, so a composition-root test can assert
// what a binary registers.
//
// Exported for the same reason every other module exports it, and the reason is
// a bug that already happened here once: cmd/api's registration gate compares
// what the codec REGISTERS against what the modules DECLARE, and identity was
// skipped by name prefix because it had no exported list. An identity event
// added to RegisterEvents and forgotten in eventTypes() gets no schema version,
// and `UpcasterRegistry.Apply` — which runs on EVERY read — refuses a type it
// has no version for. The write succeeds, the projector is fine, every unit test
// passes because they build repositories over a nil registry, and the first
// account to record that event becomes permanently unloadable in cmd/api.
//
// Identity is the module with the most events, so it was the largest surface the
// gate did not cover.
func EventTypes() []string { return eventTypes() }

// eventTypes lists every identity event type as a string.
//
// Derived from the same zero values the codec registers, so the two lists cannot
// disagree about a name — a typed literal here is checked by the compiler, a
// string literal would not be.
func eventTypes() []string {
	events := []eventsourcing.Event{
		&contract.EmailReserved{}, &contract.EmailReservationConfirmed{},
		&contract.EmailReleased{}, &contract.DuplicateRegistrationAttempted{},
		&contract.EmailReservationDemoted{},

		&contract.UsernameReserved{}, &contract.UsernameAssigned{},
		&contract.UsernameTombstoned{},

		&contract.UserRegistered{}, &contract.EmailVerificationRequested{},
		&contract.EmailVerified{},
		&contract.EmailChangeRequested{}, &contract.EmailChangeCancelled{},
		&contract.EmailChanged{}, &contract.EmailChangeReverted{},
		&contract.UserActivated{},
		&contract.UserDeactivated{}, &contract.UserReactivated{},
		&contract.UserSuspended{}, &contract.UserDeletionRequested{},
		&contract.UserDeletionCancelled{}, &contract.UserErased{},

		&contract.PasswordResetRequested{},
		&contract.PasswordSet{}, &contract.PasswordChanged{},
		&contract.PasswordRehashed{}, &contract.CredentialCompromiseDetected{},

		&contract.TotpEnrollmentStarted{}, &contract.TotpEnabled{},
		&contract.TotpDisabled{}, &contract.RecoveryCodesGenerated{},
		&contract.FederatedIdentityClaimed{}, &contract.FederatedIdentityReleased{},
		&contract.FederatedIdentityLinked{}, &contract.FederatedIdentityUnlinked{},
		&contract.PasskeyRegistered{}, &contract.PasskeyRemoved{},
		&contract.PasskeyCloneWarning{},
		&contract.RecoveryCodeConsumed{}, &contract.RecoveryCodesExhausted{},

		&contract.AuthenticationSucceeded{}, &contract.AuthenticationFailed{},
		&contract.SecondFactorChallenged{}, &contract.AuthenticatorDisabled{},

		&contract.SessionCreated{}, &contract.SessionElevated{},
		&contract.SessionRevoked{}, &contract.SessionExpired{},
		&contract.DeviceRegistered{},

		&contract.ServiceAccountCreated{}, &contract.ApiKeyCreated{},
		&contract.ApiKeyRotated{}, &contract.ApiKeyRevoked{},
	}
	names := make([]string, len(events))
	for i, e := range events {
		names[i] = e.EventType()
	}
	return names
}
