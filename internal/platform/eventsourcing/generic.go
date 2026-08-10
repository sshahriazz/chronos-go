package eventsourcing

// EventPtr constrains a pointer-to-event, so generic code can construct an
// event without reflection and without a hand-written factory.
//
// The two-parameter form — EventPtr[T] with the caller writing On[T] — is what
// lets `new(T)` typecheck as an Event: T itself is a plain struct, and only
// *T carries the method set. Deserialization needs a pointer anyway, so this
// costs nothing and removes an entire class of registration typos.
//
// Usage:
//
//	func Register[T any, PT EventPtr[T]](c *Codec) {
//	    var e PT = new(T)
//	    c.bind(e.EventType(), func() Event { return PT(new(T)) })
//	}
//
//	Register[UserRegistered](codec)   // PT inferred as *UserRegistered
type EventPtr[T any] interface {
	*T
	Event
}

// TypeOf reports the persisted discriminator for an event type without an
// instance in hand. The single allocation happens at registration time, never
// on the hot path.
func TypeOf[T any, PT EventPtr[T]]() string {
	var e PT = new(T)
	return e.EventType()
}
