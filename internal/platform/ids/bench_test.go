package ids_test

import (
	"testing"

	"github.com/chronos/chronos-go/internal/platform/ids"
)

// Sinks defeat escape analysis — see the note in the errs benchmarks.
var (
	strSink string
	idSink  ids.OrgID
	bufSink []byte
)

// Hot path: every response that carries an id renders it.
func BenchmarkString(b *testing.B) {
	id := ids.New[ids.Org](at, ent)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		strSink = id.String()
	}
}

// Hot path: every request that names a resource parses one.
func BenchmarkParse(b *testing.B) {
	s := ids.New[ids.Org](at, ent).String()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		idSink, _ = ids.Parse[ids.Org](s)
	}
}

func BenchmarkNew(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		idSink = ids.New[ids.Org](at, ent)
	}
}

// The zero-allocation path: render into a caller-owned buffer.
func BenchmarkAppendTo(b *testing.B) {
	id := ids.New[ids.Org](at, ent)
	buf := make([]byte, 0, 64)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		bufSink = id.AppendTo(buf[:0])
	}
}
