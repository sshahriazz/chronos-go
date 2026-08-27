//go:build integration

package main

import (
	"log/slog"
	"testing"
)

// Revoking a session must also invalidate the authorization decisions cached for
// that principal (ADR-045).
//
// Nothing at runtime can notice this wiring going missing. With no epochs the
// service logs once at construction and every revocation then succeeds locally,
// while a permit cached for that principal keeps authorizing for up to
// authz.MaxDecisionTTL — a cached decision carries no session id and no assurance
// level, so it cannot tell that the session behind it is gone. "Sign out
// everywhere" reports success and leaves access working.
//
// So this assertion is the only detector, which is exactly why it exists.
//
// # Why it is integration-tagged, having started out untagged
//
// The epochs are wired only if Valkey ANSWERS at construction, so this asserts
// live infrastructure whatever tag it carries. Untagged, it ran in the job that
// deliberately has no .env and no services, where it could only fail — and it
// passed on developer machines solely because their stack happened to be up.
// That is the shape WORKFLOW §2 calls a passing test that is not a passing
// guarantee, and it made CI red for reasons that had nothing to do with CI.
//
// Pointing VALKEY_ADDR at a closed port reproduces the CI failure exactly, which
// is what identified it.
func TestRevokingASessionInvalidatesCachedAuthorization(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.revocations == nil {
		t.Fatal("the authentication service was not constructed, so revocation cannot be asserted")
	}
	if !d.revocations.InvalidatesAuthorization() {
		t.Error("no revocation epochs are wired: revoking a session leaves every decision " +
			"cached for that principal servable until it expires on its own, and the caller " +
			"is told they were signed out everywhere")
	}
}
