package connect_test

import (
	"os"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/obs"
)

// TestMain fails the package when the suite leaves a goroutine stranded.
//
// This package starts one goroutine per Server.Run and hands its lifetime to a
// context, which is exactly the shape that leaks when a shutdown path is
// reordered — and exactly the shape no other test in the repository can catch,
// because a leaked goroutine changes no result, returns no error and logs
// nothing.
//
// It is OPT-IN by environment variable rather than always on. Go 1.27's
// goroutineleak profile is not a bookkeeping read: collecting it runs a garbage
// collection with a reachability pass over every parked goroutine, which is a
// real cost to pay on every `make check` for a signal that is almost always
// negative. `make leaks` sets the variable; `make check` does not, and the whole
// check then compiles to one os.Getenv.
//
// A package NOT carrying this TestMain is NOT leak-checked. There is no `go
// test` flag for the profile and it is process-global while `go test ./...`
// gives every package its own process, so per-package opt-in is the only
// mechanism available. `make leaks` lists the packages that have opted in.
func TestMain(m *testing.M) {
	code := m.Run()
	if code == 0 && os.Getenv("CHRONOS_LEAKCHECK") != "" {
		code = obs.ReportLeaks(os.Stderr)
	}
	os.Exit(code)
}
