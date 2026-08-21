package app_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sync"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/notification/app"
	"github.com/chronos/chronos-go/internal/modules/notification/contract"
	"github.com/chronos/chronos-go/internal/modules/notification/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

func newPreferences(t *testing.T, store *memStore, prefs *fakePrefs) *app.Preferences {
	t.Helper()
	p, err := app.NewPreferences(app.PreferencesDeps{
		Repo: store.preferenceRepo(), Reader: prefs, Clock: testClock,
	})
	if err != nil {
		t.Fatalf("NewPreferences: %v", err)
	}
	return p
}

func offAll() []app.ChannelPreference {
	out := make([]app.ChannelPreference, 0, len(domain.Governable()))
	for _, ch := range domain.Governable() {
		out = append(out, app.ChannelPreference{Channel: ch, Enabled: false})
	}
	return out
}

// ---------------------------------------------------------------------------
// Writes go through the log, never to the table
// ---------------------------------------------------------------------------

// The command APPENDS. The projection is not touched by this path at all — the
// reader port has no write method, so there is nothing here that could write a
// row, and the events below are the only record the save leaves.
func TestSetAppendsOneEventPerChannelAndWritesNoRow(t *testing.T) {
	t.Parallel()

	store := newMemStore(t)
	prefs := newFakePrefs()

	if _, err := newPreferences(t, store, prefs).Set(context.Background(), app.SetPreferencesCommand{
		OrgID: testOrg, SubjectID: testSubject,
		Settings:       offAll(),
		IdempotencyKey: "cmd-1",
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	events := store.events(t, preferenceStream(testOrg, testSubject))
	if len(events) != len(domain.Governable()) {
		t.Fatalf("appended %d events, want %d — one per channel switched",
			len(events), len(domain.Governable()))
	}
	seen := map[string]bool{}
	for _, e := range events {
		set, ok := e.(*contract.ChannelPreferenceSet)
		if !ok {
			t.Fatalf("appended %T, want *contract.ChannelPreferenceSet", e)
		}
		if set.OrgID != testOrg || set.SubjectID != testSubject {
			t.Errorf("event scoped to (%q, %q), want (%q, %q)",
				set.OrgID, set.SubjectID, testOrg, testSubject)
		}
		if set.Enabled {
			t.Errorf("%s recorded as enabled", set.Channel)
		}
		seen[set.Channel] = true
	}
	for _, ch := range domain.Governable() {
		if !seen[string(ch)] {
			t.Errorf("no event for %s", string(ch))
		}
	}

	// Nothing reached the projection from here. The row appears only once the
	// projector applies the events above.
	stored, err := prefs.ChannelPreferences(context.Background(), testOrg, testSubject)
	if err != nil {
		t.Fatalf("ChannelPreferences: %v", err)
	}
	if len(stored) != 0 {
		t.Errorf("the use case wrote %d preference rows directly; that table is a "+
			"projection and a row written here is one no replay reproduces", len(stored))
	}
}

// Each person's preferences live on a stream derived from (organization,
// subject), so two people never share a consistency boundary.
func TestSetWritesToAStreamScopedToTheCallerAndOrganization(t *testing.T) {
	t.Parallel()

	store := newMemStore(t)
	pref := newPreferences(t, store, newFakePrefs())

	for _, scope := range []struct{ org, subject string }{
		{testOrg, testSubject},
		{testOrg, testOther},
		{testOtherOrg, testSubject},
	} {
		if _, err := pref.Set(context.Background(), app.SetPreferencesCommand{
			OrgID: scope.org, SubjectID: scope.subject,
			Settings:       []app.ChannelPreference{{Channel: notify.ChannelEmail, Enabled: false}},
			IdempotencyKey: "cmd-" + scope.org + scope.subject,
		}); err != nil {
			t.Fatalf("Set(%s,%s): %v", scope.org, scope.subject, err)
		}
	}

	if got := store.streamCount(); got != 3 {
		t.Fatalf("three different (organization, subject) pairs produced %d streams, want 3",
			got)
	}
}

// ---------------------------------------------------------------------------
// Concurrency: a save must not tear
// ---------------------------------------------------------------------------

// Two settings screens saving at once collide on the stream's revision, and the
// loser is told CONFLICT rather than silently overwriting.
//
// The interleave is forced rather than raced: an unrelated event is appended to
// the same stream in the instant between this command's load and its save, which
// is exactly the window a second screen occupies.
func TestConcurrentSetsCollideRatherThanOverwriting(t *testing.T) {
	t.Parallel()

	store := newMemStore(t)
	stream := preferenceStream(testOrg, testSubject)

	var once sync.Once
	store.beforeAppend = func(s eventsourcing.StreamID) {
		if s != stream {
			return
		}
		once.Do(func() {
			store.beforeAppend = nil
			// The other screen's save, landing first.
			if _, err := store.Append(context.Background(), stream, eventsourcing.NoStream(),
				[]eventsourcing.PendingEvent{{
					ID: eventsourcing.DeriveEventID("other-screen", 0),
					Event: &contract.ChannelPreferenceSet{
						SubjectID: testSubject, OrgID: testOrg,
						Channel: string(notify.ChannelInApp), Enabled: false,
						ChangedAt: testClock.t,
					},
					Meta: eventsourcing.Metadata{SchemaVersion: 1, OrgID: testOrg},
				}}); err != nil {
				t.Errorf("staging the competing save: %v", err)
			}
		})
	}

	_, err := newPreferences(t, store, newFakePrefs()).Set(context.Background(),
		app.SetPreferencesCommand{
			OrgID: testOrg, SubjectID: testSubject,
			Settings:       []app.ChannelPreference{{Channel: notify.ChannelEmail, Enabled: false}},
			IdempotencyKey: "cmd-1",
		})
	if errs.ReasonOf(err) != errs.Conflict {
		t.Fatalf("got %v (reason %s), want CONFLICT — without the revision precondition "+
			"both saves land and the result is half of each", err, errs.ReasonOf(err))
	}

	// The loser wrote NOTHING. A partial write is exactly the tearing this
	// precondition exists to prevent.
	events := store.events(t, stream)
	if len(events) != 1 {
		t.Fatalf("the stream carries %d events after one winner and one loser, want 1",
			len(events))
	}
}

// Many screens saving the same target state at once produce a result that is all
// of it or none of it, never a mixture.
//
// Run under -race. Tearing here would look like two of the three channels
// disabled — a person who switched three things off, saw one come back, and
// never trusted the screen again.
func TestConcurrentSetsNeverLeaveAPartialState(t *testing.T) {
	t.Parallel()

	const writers = 6
	store := newMemStore(t)
	prefs := newFakePrefs()
	pref := newPreferences(t, store, prefs)

	var (
		mu        sync.Mutex
		succeeded int
		conflicts int
		other     []error
		wg        sync.WaitGroup
	)
	for i := range writers {
		wg.Go(func() {
			_ = i
			_, err := pref.Set(context.Background(), app.SetPreferencesCommand{
				OrgID: testOrg, SubjectID: testSubject,
				Settings:       offAll(),
				IdempotencyKey: "cmd-" + string(rune('a'+i)),
			})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				succeeded++
			case errs.ReasonOf(err) == errs.Conflict:
				conflicts++
			default:
				other = append(other, err)
			}
		})
	}
	wg.Wait()

	if len(other) > 0 {
		t.Fatalf("a concurrent save failed for a reason other than contention: %v", other)
	}
	if succeeded == 0 {
		t.Fatal("no concurrent save succeeded at all")
	}
	if succeeded+conflicts != writers {
		t.Fatalf("%d succeeded and %d conflicted, want %d in total",
			succeeded, conflicts, writers)
	}

	// Every event on the stream must be a complete save's worth. The failure
	// this guards is a stream holding, say, four events — one full save plus
	// half of another that should have been refused whole.
	events := store.events(t, preferenceStream(testOrg, testSubject))
	if len(events)%len(domain.Governable()) != 0 {
		t.Fatalf("the stream carries %d events, which is not a whole number of "+
			"three-channel saves — a save landed partially", len(events))
	}

	prefs.applyEvents(events)
	view, err := newQueries(t, newFakeFeed(), prefs).GetPreferences(
		context.Background(), testOrg, testSubject)
	if err != nil {
		t.Fatalf("GetPreferences: %v", err)
	}
	for _, c := range view.Channels {
		if c.Enabled {
			t.Errorf("%s is still enabled after every writer asked for it off; "+
				"the result is a mixture of saves rather than one of them",
				string(c.Channel))
		}
	}
}

// ---------------------------------------------------------------------------
// The rule: no preference can silence a security alert
// ---------------------------------------------------------------------------

// Every channel switched OFF through the real use case, then a SECURITY
// notification pushed through the REAL notify.Dispatcher — and it is delivered
// on every channel anyway.
//
// This is the enforcement, exercised rather than described. The dispatcher
// checks class before it consults any preference (notify.Dispatcher.allowed), so
// the preference this test just wrote is never even read for a security alert.
// Making Security preference-respecting fails here; so does letting the
// preference surface name a class, because the delivered set would then depend
// on a row this test wrote.
func TestNoPreferenceCanSilenceASecurityAlert(t *testing.T) {
	t.Parallel()

	store := newMemStore(t)
	prefs := newFakePrefs()

	if _, err := newPreferences(t, store, prefs).Set(context.Background(), app.SetPreferencesCommand{
		OrgID: testOrg, SubjectID: testSubject,
		Settings:       offAll(),
		IdempotencyKey: "cmd-1",
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	// The projector's effect, applied so the dispatcher reads what a real
	// deployment would read.
	prefs.applyEvents(store.events(t, preferenceStream(testOrg, testSubject)))

	email := &spyTransport{ch: notify.ChannelEmail}
	inApp := &spyTransport{ch: notify.ChannelInApp}
	push := &spyTransport{ch: notify.ChannelWebPush}

	dispatcher := notify.NewDispatcher(notify.Deps{
		Vault:      stubVault{},
		Prefs:      preferencePort{prefs: prefs},
		Transports: []notify.Transport{email, inApp, push},
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	security := notify.Notification{
		Template: "identity.totp_disabled",
		Class:    notify.Security,
		OrgID:    testOrg,
		Recipient: notify.Recipient{
			SubjectID: testSubject, OrgID: testOrg,
		},
	}
	if err := dispatcher.Dispatch(context.Background(), security); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	for _, tr := range []*spyTransport{email, inApp, push} {
		if tr.calls == 0 {
			t.Errorf("a SECURITY notification was suppressed on %s by a channel toggle; "+
				"NOTIFICATIONS §3 makes it unsuppressible, and an attacker who reached "+
				"the account could switch off the alert that reveals them",
				string(tr.ch))
		}
	}

	// And the control: the same toggles DO suppress an Activity notification, so
	// the test above is not passing because preferences are simply ignored.
	email.calls, inApp.calls, push.calls = 0, 0, 0
	activity := security
	activity.Class = notify.Activity
	activity.Template = "access.shared_with_you"
	if err := dispatcher.Dispatch(context.Background(), activity); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	for _, tr := range []*spyTransport{email, inApp, push} {
		if tr.calls != 0 {
			t.Errorf("%s delivered an ACTIVITY notification the caller switched off; "+
				"the toggle does nothing at all, which would make the assertion above "+
				"vacuous", string(tr.ch))
		}
	}
}

// The reported class lists come from the dispatcher's own predicate, so the API
// cannot describe a rule the server does not enforce.
func TestSetReportsSecurityAsAlwaysDelivered(t *testing.T) {
	t.Parallel()

	store := newMemStore(t)
	prefs := newFakePrefs()
	view, err := newPreferences(t, store, prefs).Set(context.Background(),
		app.SetPreferencesCommand{
			OrgID: testOrg, SubjectID: testSubject,
			Settings:       offAll(),
			IdempotencyKey: "cmd-1",
		})
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if !slices.Contains(view.AlwaysDelivered, notify.Security) {
		t.Error("the settings screen does not report Security as always delivered")
	}
	if slices.Contains(view.Governed, notify.Security) {
		t.Error("the settings screen reports Security as governed by a channel toggle")
	}
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

func TestSetRefusals(t *testing.T) {
	t.Parallel()

	for name, cmd := range map[string]app.SetPreferencesCommand{
		"no organization": {
			SubjectID: testSubject, IdempotencyKey: "cmd-1",
			Settings: []app.ChannelPreference{{Channel: notify.ChannelEmail, Enabled: false}},
		},
		"no subject": {
			OrgID: testOrg, IdempotencyKey: "cmd-1",
			Settings: []app.ChannelPreference{{Channel: notify.ChannelEmail, Enabled: false}},
		},
		"no channels": {
			OrgID: testOrg, SubjectID: testSubject, IdempotencyKey: "cmd-1",
		},
		"no idempotency key": {
			OrgID: testOrg, SubjectID: testSubject,
			Settings: []app.ChannelPreference{{Channel: notify.ChannelEmail, Enabled: false}},
		},
		"an ungovernable channel": {
			OrgID: testOrg, SubjectID: testSubject, IdempotencyKey: "cmd-1",
			Settings: []app.ChannelPreference{{Channel: notify.ChannelRealtime, Enabled: false}},
		},
		"an unnamed channel": {
			OrgID: testOrg, SubjectID: testSubject, IdempotencyKey: "cmd-1",
			Settings: []app.ChannelPreference{{Channel: "", Enabled: false}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := newMemStore(t)
			_, err := newPreferences(t, store, newFakePrefs()).Set(context.Background(), cmd)
			if errs.ReasonOf(err) != errs.ValidationFailed {
				t.Fatalf("got %v (reason %s), want VALIDATION_FAILED", err, errs.ReasonOf(err))
			}
			if store.streamCount() != 0 {
				t.Error("a refused command still appended")
			}
		})
	}
}

func TestNewPreferencesRefusesAPartialWiring(t *testing.T) {
	t.Parallel()

	store := newMemStore(t)
	if _, err := app.NewPreferences(app.PreferencesDeps{Reader: newFakePrefs()}); err == nil {
		t.Error("built with no repository")
	}
	if _, err := app.NewPreferences(app.PreferencesDeps{Repo: store.preferenceRepo()}); err == nil {
		t.Error("built with no preference reader")
	}
}

// A read failure after a successful append is reported, not papered over. See
// app.Preferences.view for why that is safe: the idempotency gate releases its
// claim on an error, and the retry records nothing new.
func TestSetReportsAReadBackFailure(t *testing.T) {
	t.Parallel()

	store := newMemStore(t)
	prefs := newFakePrefs()
	prefs.err = errors.New("the read model is unreachable")

	_, err := newPreferences(t, store, prefs).Set(context.Background(), app.SetPreferencesCommand{
		OrgID: testOrg, SubjectID: testSubject,
		Settings:       offAll(),
		IdempotencyKey: "cmd-1",
	})
	if errs.ReasonOf(err) != errs.Internal {
		t.Fatalf("got %v (reason %s), want INTERNAL", err, errs.ReasonOf(err))
	}
	// The append still happened; the retry will find the aggregate already in
	// the requested state and record nothing.
	if n := len(store.events(t, preferenceStream(testOrg, testSubject))); n == 0 {
		t.Error("the append was rolled back by a read failure that came after it")
	}
}

// ---------------------------------------------------------------------------
// notify ports, for the dispatcher test
// ---------------------------------------------------------------------------

// preferencePort is notify.Preferences over the projection, with the SAME
// absence-means-enabled rule the real adapter implements. A different rule here
// would make the dispatcher test assert against a system this repository does
// not have.
type preferencePort struct{ prefs *fakePrefs }

func (p preferencePort) Enabled(
	ctx context.Context, orgID, subjectID, _ string, ch notify.Channel,
) (bool, error) {
	stored, err := p.prefs.ChannelPreferences(ctx, orgID, subjectID)
	if err != nil {
		return false, err
	}
	for _, s := range stored {
		if s.Channel == ch {
			return s.Enabled, nil
		}
	}
	return true, nil
}

type stubVault struct{}

func (stubVault) Resolve(_ context.Context, subjectID string) (notify.Recipient, error) {
	return notify.Recipient{SubjectID: subjectID, Address: "someone@example.test"}, nil
}

type spyTransport struct {
	ch    notify.Channel
	calls int
}

func (s *spyTransport) Channel() notify.Channel { return s.ch }

func (s *spyTransport) Deliver(context.Context, notify.Notification) error {
	s.calls++
	return nil
}
