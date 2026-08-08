package clock_test

import (
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/clock"
)

func TestSystem_IsAlwaysUTC(t *testing.T) {
	if loc := (clock.System{}).Now().Location(); loc != time.UTC {
		t.Fatalf("ADR-008: got %v want UTC", loc)
	}
}

func TestFixed_NormalisesToUTC(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	c := clock.NewFixed(time.Date(2026, 8, 8, 12, 0, 0, 0, ny))
	if c.Now().Location() != time.UTC {
		t.Fatalf("a local time passed in must be observed as UTC, got %v", c.Now().Location())
	}
	if h := c.Now().Hour(); h != 16 {
		t.Fatalf("12:00 New York is 16:00 UTC, got %d", h)
	}
}

func TestFixed_DoesNotAdvanceOnItsOwn(t *testing.T) {
	c := clock.NewFixed(time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC))
	first := c.Now()
	time.Sleep(2 * time.Millisecond)
	if !c.Now().Equal(first) {
		t.Fatal("a fixed clock must not move by itself")
	}
	c.Advance(90 * time.Minute)
	if got := c.Now().Sub(first); got != 90*time.Minute {
		t.Fatalf("advance: got %v want 90m", got)
	}
}
