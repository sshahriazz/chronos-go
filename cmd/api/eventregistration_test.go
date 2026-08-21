package main

import (
	"log/slog"
	"slices"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/notification"
	"github.com/chronos/chronos-go/internal/modules/organization"
	"github.com/chronos/chronos-go/internal/modules/profile"
)

// Every module this binary WRITES has its events registered in the codec.
//
// # The defect this exists to prevent, which shipped once
//
// newDependencies registered identity's events and nothing else, while cmd/api
// served notification and profile as well. The consequence was invisible in
// exactly the way that matters: an aggregate could be written ONCE and was then
// permanently broken.
//
// The first append succeeds because an empty stream decodes zero events, so
// nothing needs to be registered to write it. Every later command for that
// subject loads the stream, meets a type the codec has never heard of, and fails
// with `event type "profile.ProfileUpdated.v1" is not registered` — forever.
// Meanwhile cmd/projector has its OWN codec and registers all six modules, so
// the projections keep filling, every read keeps answering, and every dashboard
// stays green. A second UpdateProfile returns `internal`; a GetProfile returns
// 200. Nothing in the read path can see it.
//
// It was found by driving the API twice from outside
// (internal/adapter/protocolit, TestASecondWriteToAnAggregateIsRefused), not by
// any unit test — because every unit test builds its own codec and registers
// what it needs.
//
// # Why this test is shaped this way
//
// Both modules already export EventTypes() with the comment "so a
// composition-root test can assert what a binary registers". No such test
// existed. This is it: it compares what the modules DECLARE against what the
// composition root actually built, so adding an event to a module without
// registering it here fails, and so does adding a module.
func TestTheCodecRegistersEveryModuleThisBinaryWrites(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.codec == nil {
		t.Fatal("the composition root built no codec; nothing can be written or read back")
	}
	registered := d.codec.Types()

	// Identity keeps its list unexported, so it is represented by the type every
	// registration path must produce. The other two are checked in full.
	for _, want := range []string{"identity.UserRegistered.v1"} {
		if !slices.Contains(registered, want) {
			t.Errorf("the codec cannot decode %q; identity's events are not registered", want)
		}
	}

	for _, module := range []struct {
		name  string
		types []string
	}{
		{"notification", notification.EventTypes()},
		{"profile", profile.EventTypes()},
		{"organization", organization.EventTypes()},
	} {
		if len(module.types) == 0 {
			t.Fatalf("%s declares no event types; this test would assert nothing", module.name)
		}
		for _, want := range module.types {
			if !slices.Contains(registered, want) {
				t.Errorf("the codec cannot decode %q, which %s declares. cmd/api SERVES "+
					"this module, so an aggregate of its can be appended to once — an "+
					"empty stream decodes zero events — and is then unloadable forever. "+
					"The projector registers it and keeps answering reads, so nothing in "+
					"the read path shows the failure.", want, module.name)
			}
		}
	}
}
