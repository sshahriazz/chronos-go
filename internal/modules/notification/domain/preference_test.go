package domain_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/notification/contract"
	"github.com/chronos/chronos-go/internal/modules/notification/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

var at = time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)

// ---------------------------------------------------------------------------
// The rule this whole module exists to keep: a preference cannot silence a
// security alert.
// ---------------------------------------------------------------------------

// A channel toggle governs Activity and Product and NOTHING ELSE.
//
// This is the assertion a mutation has to get past. Making Security
// preference-respecting — in notify.Class.IgnoresPreferences, or by
// hand-writing these lists — fails here, and it fails at the API too, because
// GetNotificationPreferences reports exactly these two functions.
func TestSecurityAndTransactionalAreNeverGovernedByAToggle(t *testing.T) {
	t.Parallel()

	governed := domain.GovernedClasses()
	always := domain.AlwaysDeliveredClasses()

	for _, c := range []notify.Class{notify.Security, notify.Transactional} {
		if slices.Contains(governed, c) {
			t.Errorf("%s is reported as governed by a channel toggle; "+
				"NOTIFICATIONS §3 makes it unsuppressible, and a toggle that reached it "+
				"would let an account takeover switch off the alert that reveals it", c)
		}
		if !slices.Contains(always, c) {
			t.Errorf("%s is not reported as always delivered", c)
		}
	}

	for _, c := range []notify.Class{notify.Activity, notify.Product} {
		if !slices.Contains(governed, c) {
			t.Errorf("%s must be governed by a channel toggle, or there is nothing "+
				"a person can actually turn off", c)
		}
	}
}

// The two lists must PARTITION every tenant-facing class, with no class in both
// and none in neither.
//
// A class in neither is the dangerous one: it would be absent from the settings
// screen's explanation while still being delivered, so a person reading that
// screen would be told something false by omission.
func TestEveryTenantClassIsInExactlyOneList(t *testing.T) {
	t.Parallel()

	governed := domain.GovernedClasses()
	always := domain.AlwaysDeliveredClasses()

	for _, c := range domain.Classes() {
		if c == notify.Operator {
			if slices.Contains(governed, c) || slices.Contains(always, c) {
				t.Errorf("the operator class is published to tenants; it has no tenant " +
					"recipient and must appear in neither list")
			}
			continue
		}
		in := 0
		if slices.Contains(governed, c) {
			in++
		}
		if slices.Contains(always, c) {
			in++
		}
		if in != 1 {
			t.Errorf("%s appears in %d of the two lists, want exactly 1", c, in)
		}
	}
}

// domain.Classes() is hand-enumerated because Go cannot range over a constant
// block. This derives the real set by PROBING notify.Class.String(), so a class
// added to the kernel and forgotten here fails rather than silently falling into
// neither list above.
//
// It is the same shape of guard as cmd/worker's catalogue completeness test, and
// for the same reason: a hand-maintained list only ever covers what was on it the
// day it was written.
func TestClassesCoversEveryClassTheKernelDefines(t *testing.T) {
	t.Parallel()

	var probed []notify.Class
	for i := 1; i < 256; i++ {
		c := notify.Class(i) //nolint:gosec // bounded by the loop
		if c.String() != "unknown" {
			probed = append(probed, c)
		}
	}
	if len(probed) == 0 {
		t.Fatal("the probe found no classes at all; it cannot be proving anything")
	}

	declared := domain.Classes()
	for _, c := range probed {
		if !slices.Contains(declared, c) {
			t.Errorf("notify defines class %s and domain.Classes() omits it, so it is in "+
				"neither the governed nor the always-delivered list and the settings "+
				"screen describes it to nobody", c)
		}
	}
	for _, c := range declared {
		if !slices.Contains(probed, c) {
			t.Errorf("domain.Classes() names %v, which notify does not define", c)
		}
	}
}

// ---------------------------------------------------------------------------
// Governable channels
// ---------------------------------------------------------------------------

func TestOnlyTheThreeUserChannelsAreGovernable(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		channel notify.Channel
		want    bool
	}{
		"email":    {notify.ChannelEmail, true},
		"in-app":   {notify.ChannelInApp, true},
		"web push": {notify.ChannelWebPush, true},
		// Transient signals, not notifications. A person who subscribed to the
		// realtime stream has already said they want it.
		"realtime": {notify.ChannelRealtime, false},
		"empty":    {notify.Channel(""), false},
		"invented": {notify.Channel("carrier_pigeon"), false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := domain.IsGovernable(tc.channel); got != tc.want {
				t.Errorf("IsGovernable(%q) = %v, want %v", string(tc.channel), got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The aggregate
// ---------------------------------------------------------------------------

func TestAnUntouchedAggregateReportsEveryChannelEnabled(t *testing.T) {
	t.Parallel()

	p := domain.NewPreferences()
	current := p.Current()
	if len(current) != len(domain.Governable()) {
		t.Fatalf("Current() returned %d channels, want %d — a settings screen would "+
			"render a switch short", len(current), len(domain.Governable()))
	}
	for _, s := range current {
		if !s.Enabled {
			t.Errorf("%q reads as disabled on an account that never touched it; "+
				"absence must mean enabled, or a failure to write a default silences "+
				"somebody", string(s.Channel))
		}
	}
}

func TestSetRecordsOneEventPerChangedChannel(t *testing.T) {
	t.Parallel()

	p := domain.NewPreferences()
	err := p.Set("subj_a", "org_a", []domain.Setting{
		{Channel: notify.ChannelEmail, Enabled: false},
		{Channel: notify.ChannelWebPush, Enabled: false},
	}, at)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	events := p.Uncommitted()
	if len(events) != 2 {
		t.Fatalf("recorded %d events, want 2", len(events))
	}
	for _, e := range events {
		set, ok := e.(*contract.ChannelPreferenceSet)
		if !ok {
			t.Fatalf("recorded %T, want *contract.ChannelPreferenceSet", e)
		}
		if set.SubjectID != "subj_a" || set.OrgID != "org_a" {
			t.Errorf("event scoped to (%q, %q), want (subj_a, org_a)", set.SubjectID, set.OrgID)
		}
		if set.Enabled {
			t.Errorf("%s recorded as enabled, want disabled", set.Channel)
		}
	}
}

// Turning something off that is already off records NOTHING.
//
// The log is a history of CHANGES. Recording a save that changed nothing would
// make "when did they turn this off" unanswerable, which is the question a
// support conversation about missing mail actually asks.
func TestSetRecordsNothingForANoOp(t *testing.T) {
	t.Parallel()

	p := replay(t,
		&contract.ChannelPreferenceSet{
			SubjectID: "subj_a", OrgID: "org_a",
			Channel: string(notify.ChannelEmail), Enabled: false, ChangedAt: at,
		})

	if err := p.Set("subj_a", "org_a", []domain.Setting{
		{Channel: notify.ChannelEmail, Enabled: false},
	}, at); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if n := len(p.Uncommitted()); n != 0 {
		t.Errorf("recorded %d events for a change that changed nothing", n)
	}
}

// Enabling a channel nobody ever switched off records nothing either: the row
// does not exist, absence already means enabled, and writing one would record a
// decision the person did not make.
func TestEnablingAnUntouchedChannelRecordsNothing(t *testing.T) {
	t.Parallel()

	p := domain.NewPreferences()
	if err := p.Set("subj_a", "org_a", []domain.Setting{
		{Channel: notify.ChannelEmail, Enabled: true},
	}, at); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if n := len(p.Uncommitted()); n != 0 {
		t.Errorf("recorded %d events for enabling a channel that was never off", n)
	}
}

// Turning one back ON after it was off DOES record — that is a real change.
func TestReEnablingADisabledChannelRecords(t *testing.T) {
	t.Parallel()

	p := replay(t, &contract.ChannelPreferenceSet{
		SubjectID: "subj_a", OrgID: "org_a",
		Channel: string(notify.ChannelEmail), Enabled: false, ChangedAt: at,
	})
	if err := p.Set("subj_a", "org_a", []domain.Setting{
		{Channel: notify.ChannelEmail, Enabled: true},
	}, at); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if n := len(p.Uncommitted()); n != 1 {
		t.Fatalf("recorded %d events for a real change, want 1", n)
	}
	if !p.Enabled(notify.ChannelEmail) {
		t.Error("email still reads as disabled after being switched back on")
	}
}

func TestSetRefusesAnUngovernableChannelAndRecordsNothing(t *testing.T) {
	t.Parallel()

	p := domain.NewPreferences()
	err := p.Set("subj_a", "org_a", []domain.Setting{
		{Channel: notify.ChannelEmail, Enabled: false},
		{Channel: notify.ChannelRealtime, Enabled: false},
	}, at)
	if !errors.Is(err, domain.ErrNotGovernable) {
		t.Fatalf("Set returned %v, want ErrNotGovernable", err)
	}
	// All-or-nothing at validation: a save must not half-apply because one
	// switch in it was nonsense.
	if n := len(p.Uncommitted()); n != 0 {
		t.Errorf("recorded %d events for a batch that was refused", n)
	}
}

func TestSetRefusesTheSameChannelTwiceInOneBatch(t *testing.T) {
	t.Parallel()

	p := domain.NewPreferences()
	err := p.Set("subj_a", "org_a", []domain.Setting{
		{Channel: notify.ChannelEmail, Enabled: false},
		{Channel: notify.ChannelEmail, Enabled: true},
	}, at)
	if err == nil {
		t.Fatal("a batch that contradicts itself was accepted; whichever entry came " +
			"last would silently win")
	}
	if n := len(p.Uncommitted()); n != 0 {
		t.Errorf("recorded %d events for a refused batch", n)
	}
}

// The stream key is derived from (org, subject), so a mismatch means the
// derivation and the caller disagree. Overwriting would write one person's
// preference into another person's stream.
func TestSetRefusesAStreamBelongingToAnotherSubject(t *testing.T) {
	t.Parallel()

	p := replay(t, &contract.ChannelPreferenceSet{
		SubjectID: "subj_a", OrgID: "org_a",
		Channel: string(notify.ChannelEmail), Enabled: false, ChangedAt: at,
	})
	if err := p.Set("subj_intruder", "org_a", []domain.Setting{
		{Channel: notify.ChannelInApp, Enabled: false},
	}, at); err == nil {
		t.Fatal("one subject was allowed to write into another subject's preference stream")
	}
}

func TestSetRefusesAStreamBelongingToAnotherOrganization(t *testing.T) {
	t.Parallel()

	p := replay(t, &contract.ChannelPreferenceSet{
		SubjectID: "subj_a", OrgID: "org_a",
		Channel: string(notify.ChannelEmail), Enabled: false, ChangedAt: at,
	})
	if err := p.Set("subj_a", "org_b", []domain.Setting{
		{Channel: notify.ChannelInApp, Enabled: false},
	}, at); err == nil {
		t.Fatal("one organization's preferences were allowed to be written from another")
	}
}

func TestSetRefusesAnEmptyScope(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct{ subject, org string }{
		"no subject":      {"", "org_a"},
		"no organization": {"subj_a", ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := domain.NewPreferences()
			if err := p.Set(tc.subject, tc.org, []domain.Setting{
				{Channel: notify.ChannelEmail, Enabled: false},
			}, at); err == nil {
				t.Fatalf("Set accepted subject=%q org=%q", tc.subject, tc.org)
			}
		})
	}
}

// replay builds an aggregate in the state those events leave it in, without
// going near a store.
func replay(t *testing.T, events ...eventsourcing.Event) *domain.Preferences {
	t.Helper()
	p := domain.NewPreferences()
	for _, e := range events {
		p.Apply(e)
	}
	return p
}
