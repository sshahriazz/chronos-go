package main

import (
	"os"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/obs"
)

// TestMain fails the package when the suite leaves a goroutine stranded.
//
// The composition root is where this matters most. newDependencies starts
// supervision goroutines, backgroundTasks starts a sweep loop, and every one of
// them takes a context whose cancellation is the ONLY thing that stops it — so
// a task that stops selecting on ctx.Done() keeps running with nothing to
// report it. TestEveryBackgroundTaskStopsWithTheContext asserts the tasks
// return; this asserts that nothing they spawned stayed behind.
//
// See internal/server/connect/leakcheck_test.go for why this is opt-in, and for
// what a package without it is NOT getting.
func TestMain(m *testing.M) {
	code := m.Run()
	if code == 0 && os.Getenv("CHRONOS_LEAKCHECK") != "" {
		code = obs.ReportLeaks(os.Stderr)
	}
	os.Exit(code)
}
