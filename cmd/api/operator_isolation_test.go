package main

import (
	"os"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// This file is operator.md §11's "Isolation" test:
//
//	"The tenant binary exposes ZERO operator routes; a conformance test asserts
//	 the operator packages are not linked into cmd/api."
//
// depguard already refuses the import at lint time, and that is the primary
// control. This is the second one, and it exists because the two fail
// differently: a linter rule can be disabled with a `//nolint`, a file can be
// added to an exclusion list, and a config edit that widens the rule is a small
// diff that reads as tidying. This test cannot be satisfied by anything except
// the packages actually being absent from the binary.

// TestTheOperatorPlaneIsNotLinkedIntoTheTenantAPI asserts on the protobuf
// registry, which is the cheapest observable proof of what is in this binary.
//
// # Why the registry, rather than the import graph
//
// Every generated protobuf package registers its file descriptors in
// `protoregistry.GlobalFiles` from an `init()`. That registration happens
// because the package was LINKED, not because anything called it — so a
// `chronos.operator.v1` descriptor present here means the operator schema is
// compiled into the tenant API, whether or not a single line of code uses it.
//
// It is a proxy for the real property rather than the property itself: an
// operator package with no generated protobuf in it could slip past. That is
// acceptable, because the packages that matter — the service, the options, and
// everything that transitively imports them — all pull the generated code in.
func TestTheOperatorPlaneIsNotLinkedIntoTheTenantAPI(t *testing.T) {
	var found []string

	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if strings.HasPrefix(string(fd.Package()), "chronos.operator.") {
			found = append(found, fd.Path())
		}
		return true
	})

	if len(found) > 0 {
		t.Fatalf("the operator schema is linked into cmd/api:\n  %s\n\n"+
			"ADR-024: a cross-tenant capability living in the same process as the tenant "+
			"API is one routing mistake away from total data disclosure. The separation is "+
			"what makes that class of bug impossible rather than unlikely, and it only "+
			"holds while these packages are absent from this binary.",
			strings.Join(found, "\n  "))
	}
}

// TestTheOperatorPlaneIsNotInThePublishedSpec is the same argument for the
// documentation.
//
// The operator protos live in their own buf module (proto-operator/), and
// `make api-docs` generates the OpenAPI document from `proto` alone. If that
// input is ever widened to the whole workspace, the published REST reference
// starts advertising the existence and the exact shape of the cross-tenant
// surface to every reader of our public API docs.
//
// It reads the generated artefact rather than the Makefile, because what
// matters is what SHIPPED — a correct Makefile and a stale committed spec would
// still publish it.
func TestTheOperatorPlaneIsNotInThePublishedSpec(t *testing.T) {
	spec, err := os.ReadFile("../../docs/api/chronos-openapi.yaml")
	if err != nil {
		t.Skipf("the generated spec is not present: %v", err)
	}

	// The PACKAGE PATH, not the word "operator". The prose in that document
	// uses "operator" in its ordinary English sense in several places, and
	// matching on the word would fail on a sentence about who reads a trace id.
	for _, marker := range []string{
		"chronos.operator.v1",
		"/chronos.operator.v1.OperatorService/",
		"OperatorService",
	} {
		if strings.Contains(string(spec), marker) {
			t.Errorf("the published OpenAPI document contains %q.\n\n"+
				"The operator plane is not a public surface (operator.md §1). Check that "+
				"`make api-docs` still passes `proto` as its input rather than generating "+
				"from the whole buf workspace.", marker)
		}
	}
}
