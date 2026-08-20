package obs

import (
	"bytes"
	"fmt"
	"io"
	"runtime/pprof"
	"strconv"
	"strings"
)

// leakProfileName is the runtime profile Go 1.27 promoted to general
// availability. In Go 1.26 it lived behind GOEXPERIMENT=goroutineleakprofile;
// that experiment no longer exists, and `go env GOEXPERIMENT=goroutineleakprofile`
// now fails with "unknown GOEXPERIMENT", which is how you tell the two apart.
const leakProfileName = "goroutineleak"

// leakProfileHeader is the first line of the debug=1 text form:
//
//	goroutineleak profile: total 3
//
// The count is parsed from here rather than from Profile.Count(), which reports
// what the LAST detection found and is therefore zero until something has run
// one.
const leakProfileHeader = leakProfileName + " profile: total "

// LeakReport is what the goroutineleak profile found.
type LeakReport struct {
	// Count is the number of leaked goroutines.
	Count int

	// Profile is the debug=1 text form: the header line, then one stack per
	// distinct leak site. Empty stacks are not possible — a report with Count > 0
	// always names where the goroutine was parked.
	Profile string
}

// GoroutineLeaks collects the goroutine-leak profile.
//
// A goroutine is LEAKED when it is blocked on a concurrency primitive — a
// channel send or receive, a select, a mutex, a WaitGroup — that no live
// goroutine can ever reach again. The runtime establishes that by running a
// garbage collection with leak detection, so this call is not free: it is a GC
// cycle plus a reachability pass, which is why it belongs in a test, in a
// deliberate `make leaks` run, or behind an authenticated debug endpoint, and
// not on a timer.
//
// # What it does NOT find, and why that must be said out loud
//
// Reachability is the whole mechanism, so anything still reachable is not a
// leak by this definition even when it is one by yours:
//
//   - A goroutine blocked on a channel held by a PACKAGE-LEVEL VARIABLE is
//     reported as healthy forever. The global keeps the channel alive, so the
//     runtime cannot prove nothing will ever send.
//   - A goroutine blocked on a primitive that lives in a RUNNABLE goroutine's
//     locals is likewise invisible: that stack is a root.
//
// Both were confirmed against this toolchain rather than read off a release
// note. So a clean report means "no goroutine is provably stranded", never "no
// goroutine is stuck" — and a leak parked on a global still needs the goroutine
// count in Prometheus to find it.
//
// What it does find is the common case: a worker whose owner returned without
// closing its channel, a subscription loop whose consumer went away, a
// select on a context nobody holds any more.
func GoroutineLeaks() (LeakReport, error) {
	p := pprof.Lookup(leakProfileName)
	if p == nil {
		// Reachable only on a toolchain without the profile. Named explicitly
		// because the alternative — an empty report — reads exactly like "no
		// leaks", which is the failure this whole package exists to stop.
		return LeakReport{}, fmt.Errorf(
			"obs: this toolchain has no %q profile; goroutine-leak detection is NOT running",
			leakProfileName)
	}

	// debug=1 for the text form. debug=2 is the panic-style dump of EVERY
	// goroutine, leaked or not, which is the opposite of what a leak check wants.
	var buf bytes.Buffer
	if err := p.WriteTo(&buf, 1); err != nil {
		return LeakReport{}, fmt.Errorf("obs: writing the %s profile: %w", leakProfileName, err)
	}

	text := buf.String()
	count, err := parseLeakCount(text)
	if err != nil {
		return LeakReport{}, err
	}
	return LeakReport{Count: count, Profile: text}, nil
}

// parseLeakCount reads the total off the profile header.
//
// A parse failure is an ERROR rather than a zero, for the same reason as the
// missing-profile branch above: a leak checker that silently reports "none"
// when it could not read its own input is worse than no leak checker.
func parseLeakCount(text string) (int, error) {
	_, rest, found := strings.Cut(text, leakProfileHeader)
	if !found {
		return 0, fmt.Errorf("obs: the %s profile has no %q header: %q",
			leakProfileName, leakProfileHeader, firstLine(text))
	}
	field, _, _ := strings.Cut(strings.TrimSpace(rest), " ")
	field, _, _ = strings.Cut(field, "\n")
	n, err := strconv.Atoi(field)
	if err != nil {
		return 0, fmt.Errorf("obs: the %s profile total %q is not a number: %w",
			leakProfileName, field, err)
	}
	return n, nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// ReportLeaks writes the goroutine-leak profile to w and returns a process exit
// code: 0 when nothing is stranded, non-zero otherwise.
//
// It exists so a package's TestMain is three lines rather than thirty, and so
// the failure message — the part that decides whether anyone acts on it — is
// written once. A test binary is the caller; the signature avoids importing
// `testing` into a package that is linked into every server.
//
// A collection FAILURE is also a non-zero exit. A leak checker that cannot read
// its own profile has not found zero leaks, and reporting success there would
// reproduce the defect this whole facility replaced: a target whose name claims
// a check it does not perform.
func ReportLeaks(w io.Writer) int {
	report, err := GoroutineLeaks()
	if err != nil {
		_, _ = fmt.Fprintf(w, "\nGOROUTINE LEAK CHECK DID NOT RUN: %v\n", err)
		return 1
	}
	if report.Count == 0 {
		return 0
	}
	_, _ = fmt.Fprintf(w, "\nGOROUTINE LEAK CHECK FAILED: %d goroutine(s) are blocked on a "+
		"concurrency primitive nothing can reach again. Each one holds its stack, its "+
		"captured variables and whatever they reference, for the life of the process.\n\n%s\n",
		report.Count, report.Profile)
	return 1
}
