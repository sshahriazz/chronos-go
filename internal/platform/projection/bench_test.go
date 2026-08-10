package projection_test

import (
	"context"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// Package-level sinks. Without them, escape analysis stack-allocates results
// the real caller would heap-allocate, and the benchmark reports numbers that
// are simply wrong — measured at ~40% off on this codebase before.
var (
	sinkErr    error
	sinkTenant db.Tenant
	sinkBool   bool
	sinkString string
	sinkStart  eventsourcing.StartFrom
)

func benchDispatch(b *testing.B) (*projection.Dispatch, db.Writer) {
	b.Helper()
	d := projection.NewDispatch(fakeCodec{})
	projection.On[thingHappened](d, func(context.Context, db.Writer, projection.Envelope, *thingHappened) error {
		return nil
	})
	return d, &fakeBatch{}
}

// The hit path: one map lookup, one JSON decode, one typed call. The decode
// dominates and is unavoidable — what matters is that routing adds nothing on
// top of it.
func BenchmarkDispatchApplyHit(b *testing.B) {
	d, w := benchDispatch(b)
	env := projection.Envelope{
		Type:    "test.ThingHappened.v1",
		Payload: []byte(`{"name":"kettle"}`),
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkErr = d.Apply(ctx, w, env)
	}
}

// The miss path is the common one: $all is filtered by stream prefix, so a
// projection is offered every event its own module writes and handles a few of
// them. This must cost a map lookup and nothing else — in particular it must
// not decode.
func BenchmarkDispatchApplyMiss(b *testing.B) {
	d, w := benchDispatch(b)
	env := projection.Envelope{
		Type:    "test.OtherHappened.v1",
		Payload: []byte(`{"name":"kettle"}`),
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkErr = d.Apply(ctx, w, env)
	}
}

// Runs once per event, inside the batch. Must not allocate.
func BenchmarkScopeOf(b *testing.B) {
	m := eventsourcing.Metadata{OrgID: "org_01J8Z9", WorkspaceID: "ws_01J8Z9", Residency: "eu"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkTenant = projection.ScopeOf(m)
	}
}

// StartFrom is a value type precisely so the resume point costs nothing to pass.
func BenchmarkStartFrom(b *testing.B) {
	p := eventsourcing.Position{Commit: 918273645, Prepare: 918273645}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkStart = eventsourcing.After(p)
		sinkBool = sinkStart.IsBeginning()
	}
}

// Registration-time only, but it is the mechanism the whole typed-dispatch
// design rests on, so it is worth knowing what it costs.
func BenchmarkTypeOf(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkString = eventsourcing.TypeOf[thingHappened]()
	}
}
