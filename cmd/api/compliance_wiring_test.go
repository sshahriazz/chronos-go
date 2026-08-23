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
