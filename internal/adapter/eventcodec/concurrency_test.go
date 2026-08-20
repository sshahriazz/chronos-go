package eventcodec_test

import (
	"strconv"
	"sync"
	"testing"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

type concEvent struct {
	Name string `json:"name"`
}

func (*concEvent) EventType() string { return "conc.event" }

// Decoding from many goroutines is race-free.
//
// A rebuild decodes on N shard workers at once (ADR-044), so this is the normal
// operating mode, not an edge case. Run under -race in `make check`.
func TestConcurrentDecodeIsRaceFree(t *testing.T) {
	c := eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())
	eventcodec.Register[concEvent](c)
	c.Freeze()

	payload, err := c.Marshal(&concEvent{Name: "alice"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			for range 100 {
				e, err := c.Unmarshal("conc.event", payload)
				if err != nil {
					t.Errorf("Unmarshal: %v", err)
					return
				}
				if e.(*concEvent).Name != "alice" {
					t.Errorf("decoded %+v", e)
					return
				}
			}
		})
	}
	wg.Wait()
}

// Registration concurrent with decoding does not race and never loses a type.
//
// Copy-on-write is what makes this safe: the map a decoder is reading is never
// written to. Mutating it in place would be a data race the detector only finds
// if a test happens to do both at once — which is precisely what this does.
func TestConcurrentRegistrationAndDecodeIsRaceFree(t *testing.T) {
	c := eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())
	eventcodec.Register[concEvent](c)

	payload, err := c.Marshal(&concEvent{Name: "alice"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	const registrations = 50
	var wg sync.WaitGroup

	wg.Go(func() {
		for i := range registrations {
			c.Register("late.type."+strconv.Itoa(i),
				func() eventsourcing.Event { return &concEvent{} })
		}
	})

	for range 16 {
		wg.Go(func() {
			for range 200 {
				if _, err := c.Unmarshal("conc.event", payload); err != nil {
					t.Errorf("a decode failed while registration was in progress: %v", err)
					return
				}
			}
		})
	}
	wg.Wait()

	// Every registration survived: a copy-on-write that read a stale snapshot
	// would silently drop one.
	if got := len(c.Types()); got != registrations+1 {
		t.Fatalf("%d types registered, want %d: a concurrent registration was lost, so those "+
			"events decode as unknown forever", got, registrations+1)
	}
}

// Freezing closes the registry, so a late registration is a stack trace rather
// than a projector that already treated those events as unknown and stopped.
func TestRegisteringAfterFreezePanics(t *testing.T) {
	c := eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())
	eventcodec.Register[concEvent](c)
	c.Freeze()

	if !c.Frozen() {
		t.Fatal("Freeze did not take effect")
	}

	defer func() {
		if recover() == nil {
			t.Fatal("registering after Freeze was allowed: anything already consuming the log " +
				"treated that type as unknown and stopped, and nothing connects the two")
		}
	}()
	c.Register("too.late", func() eventsourcing.Event { return &concEvent{} })
}

// A duplicate registration panics at wiring time.
//
// The alternative is one event type silently shadowing another, which is a read
// model built from the wrong Go struct.
func TestDuplicateRegistrationPanics(t *testing.T) {
	c := eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())
	eventcodec.Register[concEvent](c)

	defer func() {
		if recover() == nil {
			t.Fatal("a duplicate registration was accepted")
		}
	}()
	eventcodec.Register[concEvent](c)
}

// A nil constructor and an empty type name are refused, because both produce a
// codec that looks registered and decodes nothing.
func TestMalformedRegistrationsPanic(t *testing.T) {
	for name, register := range map[string]func(*eventcodec.JSON){
		"empty type name": func(c *eventcodec.JSON) {
			c.Register("", func() eventsourcing.Event { return &concEvent{} })
		},
		"nil constructor": func(c *eventcodec.JSON) { c.Register("x.y", nil) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s was accepted", name)
				}
			}()
			register(eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry()))
		}()
	}
}

// Types() returns a COPY: a caller that sorts or truncates it must not corrupt
// the registry for everybody else.
func TestTypesReturnsACopy(t *testing.T) {
	c := eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())
	eventcodec.Register[concEvent](c)

	got := c.Types()
	if len(got) != 1 {
		t.Fatalf("got %v", got)
	}
	got[0] = "clobbered"

	if again := c.Types(); again[0] != "conc.event" {
		t.Fatalf("the registry was mutated through the slice Types returned: %v", again)
	}
}
