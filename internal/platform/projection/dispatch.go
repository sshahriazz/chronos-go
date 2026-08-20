package projection

import (
	"context"
	"fmt"

	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// Dispatch routes events to statically typed handlers.
//
// Without it, every projection ends up with the same hand-written
// `switch e.Type { case "identity.UserRegistered.v1": ... }` followed by an
// unchecked type assertion — a string literal and a cast that the compiler
// cannot connect to each other. Dispatch derives both from the type parameter,
// so a renamed field or a mismatched handler is a build failure.
//
// Zero registrations happen at run time: On is called once during wiring, and
// the hot path is a single map lookup on a string that is already in hand.
type Dispatch struct {
	codec    eventsourcing.Codec
	handlers map[string]handler
}

type handler func(context.Context, db.Writer, Envelope, eventsourcing.Event) error

func NewDispatch(codec eventsourcing.Codec) *Dispatch {
	return &Dispatch{codec: codec, handlers: make(map[string]handler)}
}

// On registers a handler for one event type.
//
// T is the event struct; PT — inferred — is the pointer type that carries the
// method set and that deserialization needs:
//
//	d.On[identity.UserRegistered](func(
//	    ctx context.Context, w db.Writer, env projection.Envelope, e *identity.UserRegistered,
//	) error { ... })
//
// It panics on a duplicate registration. That is a wiring bug, it is
// deterministic, and it happens at startup — the alternative is a projection
// that silently drops half its events.
func (d *Dispatch) On[T any, PT eventsourcing.EventPtr[T]](
	fn func(context.Context, db.Writer, Envelope, PT) error,
) {
	eventType := eventsourcing.TypeOf[T, PT]()
	if _, dup := d.handlers[eventType]; dup {
		panic(fmt.Sprintf("projection: duplicate handler for %q", eventType))
	}
	d.handlers[eventType] = func(ctx context.Context, w db.Writer, env Envelope, e eventsourcing.Event) error {
		typed, ok := e.(PT)
		if !ok {
			// The codec returned a different Go type than the one registered
			// under this event type name — a registry mismatch, not bad data.
			return fmt.Errorf("projection: %q decoded as %T, want %T", env.Type, e, PT(nil))
		}
		return fn(ctx, w, env, typed)
	}
}

// Decode decodes an envelope's payload using the registered codec.
//
// Exposed for Emitter implementations, which need the typed event to build a
// realtime message but must not re-implement type lookup — a second decoding
// path is a second place for the codec and the projection to disagree.
func (d *Dispatch) Decode(env Envelope) (eventsourcing.Event, error) {
	return d.codec.Unmarshal(env.Type, env.Payload)
}

// Handles reports whether any handler is registered for an event type.
func (d *Dispatch) Handles(eventType string) bool {
	_, ok := d.handlers[eventType]
	return ok
}

// Apply decodes and routes one event.
//
// An event with no registered handler is SKIPPED, not an error: $all is filtered
// by stream prefix, so a projection is routinely offered events from its own
// module that it has no interest in. Decoding happens only after a handler is
// found, which keeps an unregistered-but-irrelevant type from costing anything.
func (d *Dispatch) Apply(ctx context.Context, w db.Writer, env Envelope) error {
	h, ok := d.handlers[env.Type]
	if !ok {
		return nil
	}
	e, err := d.codec.Unmarshal(env.Type, env.Payload)
	if err != nil {
		return fmt.Errorf("projection: decoding %s from %s: %w", env.Type, env.Stream, err)
	}
	return h(ctx, w, env, e)
}
