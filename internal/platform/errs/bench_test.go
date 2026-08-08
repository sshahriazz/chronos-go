package errs_test

import (
	"testing"

	"github.com/chronos/chronos-go/internal/platform/errs"
)

// Sinks defeat escape analysis. Without them `_ = f()` lets the compiler prove
// the result never escapes and stack-allocate it, so the benchmark measures a
// program nobody runs: in production the error is returned up the stack.
var (
	errSink    *errs.Error
	reasonSink errs.Reason
)

// The error path is hot precisely when the system is under probing or attack.
func BenchmarkAccessDenied_NoArgs(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		errSink = errs.AccessDeniedf("permission denied")
	}
}

func BenchmarkAccessDenied_WithArgs(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		errSink = errs.AccessDeniedf("no %s on %s", "admin", "workspace")
	}
}

func BenchmarkDisclose(b *testing.B) {
	e := errs.AccessDeniedf("denied")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		errSink = errs.Disclose(e, false)
	}
}

func BenchmarkReasonOf(b *testing.B) {
	e := errs.QuotaExceededf("no seats")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		reasonSink = errs.ReasonOf(e)
	}
}
