package eventsourcing

// Root is an aggregate: the consistency boundary of exactly one stream.
//
// The unexported method makes the interface sealed — the only way to satisfy it
// is to embed Base. That is deliberate: version tracking and the uncommitted
// buffer are easy to reimplement subtly wrong, and a half-correct aggregate
// corrupts the log rather than failing loudly.
type Root interface {
	// Apply mutates state from an event. It must be PURE: no I/O, no clock, no
	// validation. It runs during rebuild for events that are already facts, and
	// rejecting one there would make the stream unloadable.
	Apply(Event)

	Version() Revision
	Uncommitted() []Event
	ClearUncommitted()

	base() *Base
}

// Base provides the mechanics every aggregate needs. Embed it by value.
type Base struct {
	version     Revision
	uncommitted []Event
}

// base is the sealing method: it is what makes Root unimplementable without
// embedding Base.
//
//nolint:unused // used through the Root interface, which the linter cannot see
func (b *Base) base() *Base { return b }

// Version is the revision of the last event applied from the store. It is -1
// for an aggregate that does not exist yet, which is exactly what NoStream
// expresses on append.
func (b *Base) Version() Revision {
	if b.version == 0 && len(b.uncommitted) == 0 {
		return b.version
	}
	return b.version
}

func (b *Base) Uncommitted() []Event { return b.uncommitted }

func (b *Base) ClearUncommitted() { b.uncommitted = nil }

// Record stages an event: applies it to state and queues it for append.
//
// Aggregates call this from a decide method, never from Apply — Apply runs
// during rebuild, and recording there would duplicate history on every load.
func Record(r Root, e Event) {
	r.Apply(e)
	b := r.base()
	b.uncommitted = append(b.uncommitted, e)
}

// NewAggregate returns a zero-valued root positioned before the first event.
func NewAggregate[T Root](make func() T) T {
	agg := make()
	agg.base().version = noStreamRevision
	return agg
}

// noStreamRevision marks "this aggregate has no events yet".
const noStreamRevision Revision = -1

// IsNew reports whether the aggregate has never been persisted.
func IsNew(r Root) bool { return r.base().version == noStreamRevision }

// rebuild applies recorded events in order, advancing the version. Used by the
// repository; aggregates never call it.
func rebuild(r Root, events []Event, lastRevision Revision) {
	for _, e := range events {
		r.Apply(e)
	}
	b := r.base()
	b.version = lastRevision
	b.uncommitted = nil
}

// ExpectedFor returns the concurrency precondition for saving r: NoStream for a
// new aggregate, otherwise the exact revision it was loaded at.
//
// This is what turns a concurrent modification into ErrWrongExpectedRevision
// instead of a lost update.
func ExpectedFor(r Root) ExpectedRevision {
	if IsNew(r) {
		return NoStream()
	}
	return AtRevision(r.base().version)
}
