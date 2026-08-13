package identity

import (
	"slices"
	"testing"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// The codec registry and the schema registry must describe the SAME set of
// events.
//
// Two lists exist because they are consumed by different machinery — one decodes
// payloads, one drives the upcaster chain — and nothing but this test connects
// them. Drift is silent in the worst direction: an event registered with the
// codec but not the schema registry decodes fine in a unit test and fails at
// read time with "event type is not registered", from inside a projector, in
// production.
func TestTheCodecAndSchemaRegistriesAgree(t *testing.T) {
	upcasters := eventsourcing.NewUpcasterRegistry()
	RegisterSchemas(upcasters)

	codec := eventcodec.NewJSON(upcasters)
	RegisterEvents(codec)

	registered := codec.Types()
	declared := eventTypes()

	slices.Sort(registered)
	slices.Sort(declared)

	if !slices.Equal(registered, declared) {
		missing := difference(registered, declared)
		extra := difference(declared, registered)
		t.Fatalf("the two registries disagree.\n"+
			"registered with the codec but not declared as a schema: %v\n"+
			"declared as a schema but never registered with the codec: %v",
			missing, extra)
	}
}

// Every declared type gets a version, and it is a version the chain can reach.
//
// Version zero is the trap this guards: eventsourcing.Metadata.SchemaVersion is
// an int, so an unregistered type reads as v0, and Apply's `storedVersion >
// current` check would then pass silently for a stored v0 event. Registering at
// v1 makes "never registered" and "version one" different states.
func TestEveryEventTypeHasASchemaVersion(t *testing.T) {
	r := eventsourcing.NewUpcasterRegistry()
	RegisterSchemas(r)

	for _, name := range eventTypes() {
		v, ok := r.CurrentVersion(name)
		if !ok {
			t.Errorf("%s has no registered schema version: reading one back fails with "+
				"\"event type is not registered\"", name)
			continue
		}
		if v < 1 {
			t.Errorf("%s is registered at v%d; versions start at 1 so that "+
				"\"unregistered\" and \"version one\" are distinguishable", name, v)
		}
	}
}

// Every event type is named "identity.<Name>.v<N>" (CONVENTIONS §3).
//
// The discriminator is permanent — it is in every stored event forever — so a
// typo is not a rename away from being fixed. It is a second event type that
// nothing decodes.
func TestEveryEventTypeIsCorrectlyNamed(t *testing.T) {
	for _, name := range eventTypes() {
		if len(name) < len("identity.X.v1") || name[:len("identity.")] != "identity." {
			t.Errorf("%q does not start with the module prefix %q", name, "identity.")
			continue
		}
		if i := slices.Index([]byte(name), '.'); i < 0 {
			t.Errorf("%q has no separator", name)
		}
		tail := name[len(name)-3:]
		if tail[0] != '.' || tail[1] != 'v' || tail[2] < '1' || tail[2] > '9' {
			t.Errorf("%q does not end in a version suffix like \".v1\"", name)
		}
	}
}

// No two events share a type string.
//
// eventcodec.Register panics on a duplicate, so the codec side is covered — but
// only for the exact duplicate. Two DIFFERENT Go types that return the same
// string is the case that gets through: the second registration panics at
// wiring, which is a crash on startup rather than a named failure here.
func TestNoTwoEventsShareATypeString(t *testing.T) {
	seen := make(map[string]bool)
	for _, name := range eventTypes() {
		if seen[name] {
			t.Errorf("%q is claimed by more than one event type: one would shadow the other, "+
				"and stored events of the shadowed type would decode into the wrong struct", name)
		}
		seen[name] = true
	}
}

func difference(a, b []string) []string {
	var out []string
	for _, s := range a {
		if !slices.Contains(b, s) {
			out = append(out, s)
		}
	}
	return out
}
