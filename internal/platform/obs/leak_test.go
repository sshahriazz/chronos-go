package obs_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/obs"
)

// leakOnAnUnreachableChannel blocks forever on a channel only it can see.
//
// The channel is created INSIDE the function on purpose. A channel the caller
// still holds is reachable, and a reachable channel is not a leak by the
// runtime's definition however stuck the goroutine on it is — so a test that
// let the channel escape would be asserting on the detector's blind spot rather
// than on its detector.
//
//go:noinline
func leakOnAnUnreachableChannel() {
	<-make(chan struct{})
	panic("unreachable: the whole point of this goroutine is that nothing sends")
}

// blockedOnAGloballyReachableChannel is the documented BLIND SPOT, kept as a
// test so the limitation is a measured fact rather than a sentence in a doc
// comment that nobody re-checks after a toolchain upgrade.
//
//go:noinline
func blockedOnAGloballyReachableChannel() { <-globallyReachable }

var globallyReachable = make(chan struct{})

// leaked records that this process has already started the unkillable
// goroutine, so a repeated run can tell its own leak from a broken detector.
var leaked bool

// The detector must report a real leak.
//
// This is the assertion the old `make leaks` target could never have made. It
// ran `-gcflags=all=-d=checkptr`, which is unsafe.Pointer arithmetic checking:
// it would have passed with this goroutine leaking, with a hundred of them
// leaking, and with the entire concept of a goroutine removed from the language.
// A leak target that cannot fail on a leak is the same defect as a test that
// passes unconditionally, and it is worse than having no target at all, because
// its name is a claim somebody relies on.
//
// The test therefore starts by proving the profile is CLEAN, so a report that
// always says "leak" cannot pass either.
func TestTheGoroutineLeakProfileReportsALeakedGoroutine(t *testing.T) {
	before, err := obs.GoroutineLeaks()
	if err != nil {
		t.Fatalf("collecting the baseline profile: %v", err)
	}
	if strings.Contains(before.Profile, "leakOnAnUnreachableChannel") {
		// SKIPPED on a repeat run, FAILED on the first — and the difference is
		// the whole value of the guard.
		//
		// The goroutine this test starts is unkillable by construction; that is
		// what makes it a leak. So a second run of the test in the same process,
		// which is what `go test -count=2` does, finds the FIRST run's leak in
		// its baseline. That is the test working, not the detector lying.
		//
		// It matters because `-count=N` is how this repository hunts flakes, and
		// a package that cannot be re-run makes every such hunt report a failure
		// that has nothing to do with what was being hunted.
		if leaked {
			t.Skip("the leak from an earlier run of this test in this process is still " +
				"leaked, which is what makes it a leak; the assertion below can only " +
				"run once per process")
		}
		t.Fatalf("the baseline profile already names the leak this test has not started "+
			"yet; the detector reports leaks unconditionally and proves nothing:\n%s",
			before.Profile)
	}

	go leakOnAnUnreachableChannel()
	leaked = true

	// Poll rather than sleep-then-assert. Detection needs the goroutine to be
	// parked and needs one leak-detecting GC, and both happen on the runtime's
	// schedule, not the test's.
	deadline := time.Now().Add(30 * time.Second)
	for {
		got, err := obs.GoroutineLeaks()
		if err != nil {
			t.Fatalf("collecting the profile: %v", err)
		}
		if strings.Contains(got.Profile, "leakOnAnUnreachableChannel") {
			if got.Count <= before.Count {
				t.Fatalf("the profile names the leaked goroutine but reports a total of %d, "+
					"which is not above the baseline %d: the header and the stacks disagree, "+
					"so one of them is not being parsed",
					got.Count, before.Count)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("a goroutine blocked on an unreachable channel was NOT reported as "+
				"leaked within 30s. Count=%d. Profile:\n%s", got.Count, got.Profile)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// The blind spot must be real, and must be the one the doc comment claims.
//
// If a future toolchain starts catching this case, this test fails — which is
// the correct outcome, because obs.GoroutineLeaks then documents a limitation it
// no longer has, and `make leaks` is more useful than its help text says.
func TestAGoroutineBlockedOnAGlobalIsNotReportedAsLeaked(t *testing.T) {
	go blockedOnAGloballyReachableChannel()

	// Give it at least as long as the positive case needed, so "not detected"
	// cannot merely mean "not detected yet".
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, err := obs.GoroutineLeaks()
		if err != nil {
			t.Fatalf("collecting the profile: %v", err)
		}
		if strings.Contains(got.Profile, "blockedOnAGloballyReachableChannel") {
			t.Fatalf("the goroutineleak profile now DETECTS a goroutine parked on a "+
				"package-level channel. That is better than documented — update the "+
				"limitation in obs.GoroutineLeaks and in `make leaks`:\n%s", got.Profile)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// The reported count must be parsed from the profile, not invented.
func TestTheLeakCountMatchesTheProfileHeader(t *testing.T) {
	got, err := obs.GoroutineLeaks()
	if err != nil {
		t.Fatalf("collecting the profile: %v", err)
	}
	header := got.Profile
	if i := strings.IndexByte(header, '\n'); i >= 0 {
		header = header[:i]
	}
	if !strings.HasPrefix(header, "goroutineleak profile: total ") {
		t.Fatalf("profile header is %q; the count cannot be trusted", header)
	}
	field, _, _ := strings.Cut(strings.TrimPrefix(header, "goroutineleak profile: total "), " ")
	if field != strconv.Itoa(got.Count) {
		t.Fatalf("LeakReport.Count is %d but the header says %q", got.Count, header)
	}
}
