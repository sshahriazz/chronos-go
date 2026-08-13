package eventsourcing_test

import (
	"bytes"
	"errors"
	"testing"

	es "github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// A KurrentDB filter matches streams OR event types, never both. A filter that
// names two dimensions therefore has to lose one — silently, because the
// subscription still runs and the checkpoint still advances over the events it
// never received. It is refused instead.
func TestSubscriptionFilterRejectsMixedSelectors(t *testing.T) {
	mixed := []es.SubscriptionFilter{
		{StreamPrefixes: []string{"a-"}, EventTypes: []string{"a.v1"}},
		{StreamPrefixes: []string{"a-"}, EventTypePrefixes: []string{"a."}},
		{EventTypes: []string{"a.v1"}, EventTypePrefixes: []string{"a."}},
	}
	for i, f := range mixed {
		if err := f.Validate(); !errors.Is(err, es.ErrAmbiguousFilter) {
			t.Errorf("filter %d: got %v, want ErrAmbiguousFilter", i, err)
		}
	}
}

func TestSubscriptionFilterAccepts(t *testing.T) {
	ok := []es.SubscriptionFilter{
		{}, // every domain event: the subscriber renders this as exclude-system
		{StreamPrefixes: []string{"organization-", "workspace-"}},
		{EventTypes: []string{"notification.Created.v1"}},
		{EventTypePrefixes: []string{"notification."}},
	}
	for i, f := range ok {
		if err := f.Validate(); err != nil {
			t.Errorf("filter %d: %v", i, err)
		}
	}
}

// An empty selector matches everything, which makes the filter a lie rather
// than a narrowing; a '$' selector asks for system streams no consumer may
// decode.
func TestSubscriptionFilterRejectsUnusableSelectors(t *testing.T) {
	bad := []es.SubscriptionFilter{
		{StreamPrefixes: []string{""}},
		{EventTypes: []string{""}},
		{StreamPrefixes: []string{"$et-"}},
		{EventTypePrefixes: []string{"$"}},
	}
	for i, f := range bad {
		if err := f.Validate(); !errors.Is(err, es.ErrAmbiguousFilter) {
			t.Errorf("filter %d: got %v, want a refusal", i, err)
		}
	}
}

// ---- event size ----------------------------------------------------------

// An append past the server's limit fails mid-command, after uniqueness has
// been reserved, and reports a generic write error. Refusing our own oversized
// event names the event and the fix.
func TestCheckEventSizeRefusesAnOversizedPayload(t *testing.T) {
	_, err := es.CheckEventSize("test.Big.v1", bytes.Repeat([]byte("x"), es.MaxEventBytes+1))
	if !errors.Is(err, es.ErrEventTooLarge) {
		t.Fatalf("got %v, want ErrEventTooLarge", err)
	}
}

func TestCheckEventSizeReportsLargeButPermitsIt(t *testing.T) {
	large, err := es.CheckEventSize("test.Big.v1", bytes.Repeat([]byte("x"), es.LargeEventBytes+1))
	if err != nil {
		t.Fatalf("an event over the soft threshold must still be written: %v", err)
	}
	if !large {
		t.Error("an event over the soft threshold must be reported as large")
	}
}

func TestCheckEventSizePassesOrdinaryEvents(t *testing.T) {
	large, err := es.CheckEventSize("test.Small.v1", bytes.Repeat([]byte("x"), 1024))
	if err != nil || large {
		t.Fatalf("large=%v err=%v, want a quiet pass", large, err)
	}
}

// The soft threshold has to sit below the hard one, or nothing is ever reported
// before it is refused.
func TestSizeThresholdsAreOrdered(t *testing.T) {
	if es.LargeEventBytes >= es.MaxEventBytes {
		t.Fatalf("LargeEventBytes (%d) must be below MaxEventBytes (%d)",
			es.LargeEventBytes, es.MaxEventBytes)
	}
}
