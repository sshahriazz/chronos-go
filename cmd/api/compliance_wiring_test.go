package main

import (
	"log/slog"
	"net/http"
	"testing"

	"github.com/chronos/chronos-go/gen/proto/chronos/compliance/v1/compliancev1connect"
)

// COMPLIANCESERVICE MUST BE REGISTERED.
//
// Its absence is the shape this repository keeps producing: the aggregate, the
// projection and the dispatcher check all exist and pass their own tests, and
// nothing can place a restriction — so Article 18 is reachable only by an
// operator editing a table by hand.
//
// That is exactly what the erasure path looked like before its cancel endpoint
// landed, one slice earlier, which is why this test exists at the same time as
// the endpoint rather than after somebody notices.
func TestComplianceServiceIsRegistered(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.compliance == nil {
		t.Fatal("no compliance service was constructed; a person cannot halt processing of " +
			"their own data and Article 18 needs an operator with database access")
	}

	served := registerServices(http.NewServeMux(), d, testConfig(t),
		testSystemService(t), slog.New(slog.DiscardHandler))
	var found bool
	for _, name := range served {
		if name == compliancev1connect.ComplianceServiceName {
			found = true
		}
	}
	if !found {
		t.Fatalf("the service exists but %s is not routed; every call answers 404 while "+
			"every unit test below it passes", compliancev1connect.ComplianceServiceName)
	}
}

// RECTIFICATION CORRECTS THROUGH PROFILE, NOT BESIDE IT.
//
// # The failure this guards is a SECOND writer to the vault
//
// Article 16 corrects the display name, the locale and the timezone — fields
// `profile` owns. The obvious implementation calls `vault.PutAll` from inside
// compliance, and it would work: the value changes, the endpoint returns, every
// unit test passes.
//
// What it would leave behind is a vault write that no `profile.ProfileUpdated.v1`
// accounts for. profile's own history would then disagree with the vault about
// when somebody's name changed — and that history is what a support conversation
// about an impersonation report is settled from. profile's own use case
// documents the identical hazard from the other side, which is why its write
// puts the vault first.
//
// So compliance declares a port and this composition root satisfies it with
// profile's use case. The assertion is that the root actually HAS one to satisfy
// it with: the field is set by buildProfile, and buildProfile runs first — an
// ordering nothing else enforces, so reversing the two calls would leave
// rectification unbuilt with the rest of compliance still working.
func TestRectificationIsWiredToProfilesOwnWriteUseCase(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.profileUpdates == nil {
		t.Fatal("profile's update use case was not held on the composition root, so " +
			"compliance's Article 16 port has nothing to satisfy it. Either buildProfile " +
			"failed — in which case the whole compliance service is unbuilt — or the two " +
			"build calls have been reordered")
	}
	if d.compliance == nil {
		t.Fatal("the compliance service is unbuilt, so RectifyMyData answers " +
			"'unimplemented' and the only record of a correction is a profile save — " +
			"which cannot be told apart from somebody editing a preference")
	}
}

// AND THE COMPLIANCE SERVICE REFUSES TO BUILD WITHOUT IT.
//
// Not a duplicate of the assertion above: that one says the root holds the use
// case, this one says the root would NOTICE if it did not. A buildCompliance
// that quietly skipped rectification when profile was unavailable would produce
// a working service missing one right, which is precisely the outcome the
// per-right refusal in complianceapi.New exists to prevent.
func TestComplianceRefusesToBuildWithoutProfilesWriteUseCase(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	d.profileUpdates = nil
	if _, err := d.buildCompliance(slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("compliance was built with no way to apply a correction. RectifyMyData " +
			"would then record that a statutory right was exercised and change nothing, " +
			"which makes the log evidence for a request we did not act on")
	}
}
