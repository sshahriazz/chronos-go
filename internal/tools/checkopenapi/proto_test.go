package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRoutesReadsTheDeclaredOption pins the two fixtures the security cases in
// spec_test.go depend on.
//
// If ResendEmailVerification ever stops being public, or ListSessions starts
// being public, those cases would still pass while testing the opposite of what
// they claim. This is the assertion that stops that.
func TestRoutesReadsTheDeclaredOption(t *testing.T) {
	t.Parallel()

	got := routes()
	if len(got) == 0 {
		t.Fatal("routes() found no RPCs at all; the generated packages are not imported")
	}

	public, ok := got[publicRoute]
	if !ok {
		t.Fatalf("%s is not in the registry", publicRoute)
	}
	if !public {
		t.Errorf("%s is not public; the security fixtures in spec_test.go are testing nothing", publicRoute)
	}

	protectedPublic, ok := got[protectedRoute]
	if !ok {
		t.Fatalf("%s is not in the registry", protectedRoute)
	}
	if protectedPublic {
		t.Errorf("%s is public; the security fixtures in spec_test.go are testing nothing", protectedRoute)
	}
}

// TestCrossCheckAgainstSourcesCoversTheRepo asserts the registry is not missing
// anything the .proto sources declare.
//
// This is the guard on routes()'s one weakness: it sees only packages some
// import reached. A new proto package nobody blank-imported would be skipped in
// silence, and every rule would pass over the smaller set.
func TestCrossCheckAgainstSourcesCoversTheRepo(t *testing.T) {
	t.Parallel()

	found, problems := crossCheckAgainstSources(protoDir, routes())
	if found == 0 {
		t.Fatalf("no RPCs found under %s; the source scan is broken or the path is wrong", protoDir)
	}
	if len(problems) != 0 {
		t.Errorf("the descriptor registry does not cover the sources:\n  %s",
			strings.Join(problems, "\n  "))
	}
}

// TestCrossCheckAgainstSourcesReportsAnUnregisteredRPC is the negative half: an
// RPC on disk that no imported package registered must be named, not ignored.
func TestCrossCheckAgainstSourcesReportsAnUnregisteredRPC(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	proto := `syntax = "proto3";

package chronos.ghost.v1;

service GhostService {
  rpc Vanish(VanishRequest) returns (VanishResponse) {}
}
`
	if err := os.WriteFile(filepath.Join(dir, "ghost.proto"), []byte(proto), 0o600); err != nil {
		t.Fatal(err)
	}

	found, problems := crossCheckAgainstSources(dir, routes())
	if found != 1 {
		t.Errorf("found %d RPCs, want 1", found)
	}
	if !containsSubstring(problems, "/chronos.ghost.v1.GhostService/Vanish") {
		t.Errorf("an unregistered RPC was not reported; got %v", problems)
	}
}

// TestCrossCheckAgainstSourcesFailsOnAMissingDirectory keeps the tool from
// reporting a clean scan of nothing.
func TestCrossCheckAgainstSourcesFailsOnAMissingDirectory(t *testing.T) {
	t.Parallel()

	found, problems := crossCheckAgainstSources(filepath.Join(t.TempDir(), "absent"), routes())
	if found != 0 {
		t.Errorf("found %d RPCs in a directory that does not exist", found)
	}
	if len(problems) == 0 {
		t.Error("a missing .proto directory was reported as clean; an unrun scan proves nothing")
	}
}
