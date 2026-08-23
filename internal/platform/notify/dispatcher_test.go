package notify_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/notify"
)

// ---------------------------------------------------------------------------
// the rule that must never bend
// ---------------------------------------------------------------------------

// A security alert is the tripwire for account takeover. Nothing may suppress
// it: not a switched-off preference, not a fast in-app read, not a channel the
// user muted (notification.md §6).
func TestSecurityIsNeverSuppressed(t *testing.T) {
	email := &spyTransport{ch: notify.ChannelEmail}
	d := notify.NewDispatcher(notify.Deps{
		Vault:      vault{},
		Prefs:      prefs{enabled: false}, // everything switched off
		ReadState:  readState{read: true}, // and already read in-app
		Transports: []notify.Transport{email},
		Log:        quiet(),
	})

	err := d.Dispatch(context.Background(), notification(notify.Security))
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if email.calls != 1 {
		t.Fatal("a security alert was suppressed by preferences or by an in-app read — " +
			"this is the account-takeover tripwire and it must always be delivered")
	}
}

func TestTransactionalIgnoresPreferences(t *testing.T) {
	email := &spyTransport{ch: notify.ChannelEmail}
	d := notify.NewDispatcher(notify.Deps{
		Vault: vault{}, Prefs: prefs{enabled: false},
		Transports: []notify.Transport{email}, Log: quiet(),
	})
	if err := d.Dispatch(context.Background(), notification(notify.Transactional)); err != nil {
		t.Fatal(err)
	}
	if email.calls != 1 {
		t.Fatal("a transactional message the user asked for was suppressed by a preference")
	}
}

// Activity is the ONLY class an in-app read may suppress (ADR-026).
func TestActivityIsSuppressedByAnInAppRead(t *testing.T) {
	email := &spyTransport{ch: notify.ChannelEmail}
	inApp := &spyTransport{ch: notify.ChannelInApp}
	d := notify.NewDispatcher(notify.Deps{
		Vault: vault{}, Prefs: prefs{enabled: true}, ReadState: readState{read: true},
		Transports: []notify.Transport{email, inApp}, Log: quiet(),
	})

	if err := d.Dispatch(context.Background(), notification(notify.Activity)); err != nil {
		t.Fatal(err)
	}
	if email.calls != 0 {
		t.Error("an activity email was sent although it had already been read in-app")
	}
	// The in-app entry IS the thing that was read; suppressing it would make
	// the read impossible.
	if inApp.calls != 1 {
		t.Error("the in-app notification was suppressed by its own read state")
	}
}

func TestActivityIsSentWhenNotYetRead(t *testing.T) {
	email := &spyTransport{ch: notify.ChannelEmail}
	d := notify.NewDispatcher(notify.Deps{
		Vault: vault{}, Prefs: prefs{enabled: true}, ReadState: readState{read: false},
		Transports: []notify.Transport{email}, Log: quiet(),
	})
	if err := d.Dispatch(context.Background(), notification(notify.Activity)); err != nil {
		t.Fatal(err)
	}
	if email.calls != 1 {
		t.Fatal("an unread activity notification was not emailed")
	}
}

func TestPreferencesSuppressActivity(t *testing.T) {
	email := &spyTransport{ch: notify.ChannelEmail}
	d := notify.NewDispatcher(notify.Deps{
		Vault: vault{}, Prefs: prefs{enabled: false},
		Transports: []notify.Transport{email}, Log: quiet(),
	})
	if err := d.Dispatch(context.Background(), notification(notify.Activity)); err != nil {
		t.Fatal(err)
	}
	if email.calls != 0 {
		t.Fatal("a switched-off preference did not suppress an activity notification")
	}
}

// ---------------------------------------------------------------------------
// erasure
// ---------------------------------------------------------------------------

// Someone who exercised erasure has no address. That is a correct outcome, not
// a failure: it must not retry, and it must not report an error (NOTIFICATIONS §4).
func TestErasedSubjectIsSkippedNotFailed(t *testing.T) {
	email := &spyTransport{ch: notify.ChannelEmail}
	obs := &spyObserver{}
	d := notify.NewDispatcher(notify.Deps{
		Vault:      vault{err: notify.ErrSubjectErased},
		Transports: []notify.Transport{email}, Log: quiet(), Observer: obs,
	})

	err := d.Dispatch(context.Background(), notification(notify.Security))
	if err != nil {
		t.Fatalf("an erased subject must not produce an error — it would be retried forever: %v", err)
	}
	if email.calls != 0 {
		t.Fatal("attempted to deliver to an erased subject")
	}
	if obs.suppressed["subject_erased"] != 1 {
		t.Errorf("the skip was not recorded: %v", obs.suppressed)
	}
}

// A vault that is merely unreachable is a different matter: we do not know
// whether there is an address, so it must be retried.
func TestVaultFailureIsRetried(t *testing.T) {
	email := &spyTransport{ch: notify.ChannelEmail}
	d := notify.NewDispatcher(notify.Deps{
		Vault:      vault{err: errors.New("vault: connection refused")},
		Transports: []notify.Transport{email}, Log: quiet(),
	})
	if err := d.Dispatch(context.Background(), notification(notify.Security)); err == nil {
		t.Fatal("an unreachable vault must be retried, not treated as 'no address'")
	}
}

// Contact details come from the vault, never from the caller: an event payload
// must not be able to redirect mail.
func TestVaultDataOverridesCallerSuppliedAddress(t *testing.T) {
	email := &spyTransport{ch: notify.ChannelEmail}
	d := notify.NewDispatcher(notify.Deps{
		Vault:      vault{addr: "real@example.test", name: "Real"},
		Transports: []notify.Transport{email}, Log: quiet(),
	})

	n := notification(notify.Security)
	n.Recipient.Address = "attacker@evil.test"
	n.Recipient.Name = "Attacker"
	if err := d.Dispatch(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	if email.last.Recipient.Address != "real@example.test" {
		t.Fatalf("mail was addressed to %q, which came from the caller rather than the vault",
			email.last.Recipient.Address)
	}
}

// ---------------------------------------------------------------------------
// operator mail
// ---------------------------------------------------------------------------

func TestOperatorMailSkipsTheVault(t *testing.T) {
	email := &spyTransport{ch: notify.ChannelEmail}
	d := notify.NewDispatcher(notify.Deps{
		Vault:      vault{err: errors.New("vault must not be consulted for operator mail")},
		Transports: []notify.Transport{email}, Log: quiet(),
	})

	n := notify.Notification{
		Template:  "operator.alert",
		Class:     notify.Operator,
		Recipient: notify.Recipient{Address: "ops@chronos.test"},
	}
	if err := d.Dispatch(context.Background(), n); err != nil {
		t.Fatalf("operator mail must not depend on the tenant vault: %v", err)
	}
	if email.calls != 1 {
		t.Fatal("operator alert was not delivered")
	}
}

// Operator mail addressed to a tenant subject would leak operational detail to
// a customer.
func TestOperatorMailCannotTargetATenantSubject(t *testing.T) {
	d := notify.NewDispatcher(notify.Deps{Vault: vault{}, Log: quiet()})
	n := notify.Notification{
		Template:  "operator.alert",
		Class:     notify.Operator,
		Recipient: notify.Recipient{SubjectID: "sub_customer", Address: "ops@chronos.test"},
	}
	err := d.Dispatch(context.Background(), n)
	if !errors.Is(err, notify.ErrInvalid) {
		t.Fatalf("expected rejection, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// delivery outcomes
// ---------------------------------------------------------------------------

// One failing channel must not stop the others: a broken mail server should not
// also suppress the in-app copy of a security alert.
func TestOneChannelFailingDoesNotStopTheRest(t *testing.T) {
	email := &spyTransport{ch: notify.ChannelEmail, err: errors.New("smtp: refused")}
	inApp := &spyTransport{ch: notify.ChannelInApp}
	d := notify.NewDispatcher(notify.Deps{
		Vault: vault{}, Transports: []notify.Transport{email, inApp}, Log: quiet(),
	})

	err := d.Dispatch(context.Background(), notification(notify.Security))
	if err == nil {
		t.Fatal("a failed channel must be reported so the event is retried")
	}
	if inApp.calls != 1 {
		t.Fatal("a failure on the email channel suppressed the in-app notification")
	}
}

func TestChannelsCanBeRestricted(t *testing.T) {
	email := &spyTransport{ch: notify.ChannelEmail}
	inApp := &spyTransport{ch: notify.ChannelInApp}
	d := notify.NewDispatcher(notify.Deps{
		Vault: vault{}, Transports: []notify.Transport{email, inApp}, Log: quiet(),
	})

	n := notification(notify.Security)
	n.Channels = []notify.Channel{notify.ChannelInApp}
	if err := d.Dispatch(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	if email.calls != 0 {
		t.Error("email was delivered although the notification named only in-app")
	}
	if inApp.calls != 1 {
		t.Error("in-app was not delivered")
	}
}

func TestClassIsRequired(t *testing.T) {
	d := notify.NewDispatcher(notify.Deps{Vault: vault{}, Log: quiet()})
	err := d.Dispatch(context.Background(), notify.Notification{
		Template:  "x",
		Recipient: notify.Recipient{SubjectID: "s"},
	})
	if !errors.Is(err, notify.ErrInvalid) {
		t.Fatalf("a notification with no class must be rejected: %v", err)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func notification(c notify.Class) notify.Notification {
	return notify.Notification{
		Template:       "identity.password_changed",
		Class:          c,
		Recipient:      notify.Recipient{SubjectID: "sub_1"},
		OccurredAt:     time.Date(2026, 3, 14, 9, 26, 0, 0, time.UTC),
		IdempotencyKey: "evt_1",
	}
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type spyTransport struct {
	ch    notify.Channel
	err   error
	calls int
	last  notify.Notification
}

func (s *spyTransport) Channel() notify.Channel { return s.ch }

func (s *spyTransport) Deliver(_ context.Context, n notify.Notification) error {
	if s.err != nil {
		return s.err
	}
	s.calls++
	s.last = n
	return nil
}

type vault struct {
	addr string
	name string
	err  error
}

func (v vault) Resolve(context.Context, string) (notify.Recipient, error) {
	if v.err != nil {
		return notify.Recipient{}, v.err
	}
	addr := v.addr
	if addr == "" {
		addr = "user@example.test"
	}
	return notify.Recipient{Address: addr, Name: v.name, Locale: "en", Timezone: "UTC"}, nil
}

type prefs struct{ enabled bool }

func (p prefs) Enabled(context.Context, string, string, string, notify.Channel) (bool, error) {
	return p.enabled, nil
}

type readState struct{ read bool }

func (r readState) ReadWithin(context.Context, string, string, string, time.Duration) (bool, error) {
	return r.read, nil
}

type spyObserver struct {
	suppressed map[string]int
}

func (s *spyObserver) Delivered(string, string, string) {}

func (s *spyObserver) Suppressed(_ string, _ string, _ string, reason string) {
	if s.suppressed == nil {
		s.suppressed = map[string]int{}
	}
	s.suppressed[reason]++
}

func (s *spyObserver) Failed(string, string, string) {}

// ---------------------------------------------------------------------------
// per-user channel toggles
// ---------------------------------------------------------------------------

// Every user owns their three channels. Switching one off must actually stop
// the optional traffic on it.
func TestUserCanSwitchOffEachChannelIndependently(t *testing.T) {
	for _, off := range []notify.Channel{notify.ChannelEmail, notify.ChannelInApp, notify.ChannelWebPush} {
		t.Run(string(off), func(t *testing.T) {
			email := &spyTransport{ch: notify.ChannelEmail}
			inApp := &spyTransport{ch: notify.ChannelInApp}
			push := &spyTransport{ch: notify.ChannelWebPush}

			d := notify.NewDispatcher(notify.Deps{
				Vault:      vault{},
				Prefs:      perChannelPrefs{off: off},
				Transports: []notify.Transport{email, inApp, push},
				Log:        quiet(),
			})
			if err := d.Dispatch(context.Background(), notification(notify.Activity)); err != nil {
				t.Fatal(err)
			}

			byChannel := map[notify.Channel]*spyTransport{
				notify.ChannelEmail: email, notify.ChannelInApp: inApp, notify.ChannelWebPush: push,
			}
			for ch, spy := range byChannel {
				want := 1
				if ch == off {
					want = 0
				}
				if spy.calls != want {
					t.Errorf("channel %s delivered %d times, want %d (user switched off %s)",
						ch, spy.calls, want, off)
				}
			}
		})
	}
}

// THE limit on that control. Someone who has gained access to an account must
// not be able to switch off the alert that reveals them — so the toggles reach
// Activity and Product only, never Security or Transactional.
func TestUserCannotSilenceSecurityOnAnyChannel(t *testing.T) {
	for _, class := range []notify.Class{notify.Security, notify.Transactional} {
		t.Run(class.String(), func(t *testing.T) {
			email := &spyTransport{ch: notify.ChannelEmail}
			inApp := &spyTransport{ch: notify.ChannelInApp}
			push := &spyTransport{ch: notify.ChannelWebPush}

			d := notify.NewDispatcher(notify.Deps{
				Vault: vault{},
				// Every channel switched off, and already read in-app.
				Prefs:      prefs{enabled: false},
				ReadState:  readState{read: true},
				Transports: []notify.Transport{email, inApp, push},
				Log:        quiet(),
			})
			if err := d.Dispatch(context.Background(), notification(class)); err != nil {
				t.Fatal(err)
			}

			for _, spy := range []*spyTransport{email, inApp, push} {
				if spy.calls != 1 {
					t.Fatalf("a %s notification was suppressed on %s by a user preference. "+
						"Someone who takes over an account could switch off the alert that "+
						"reveals the takeover", class, spy.ch)
				}
			}
		})
	}
}

// perChannelPrefs switches off exactly one channel, as a settings screen would.
type perChannelPrefs struct{ off notify.Channel }

func (p perChannelPrefs) Enabled(_ context.Context, _, _, _ string, ch notify.Channel) (bool, error) {
	return ch != p.off, nil
}

// A nil vault used to panic on the first tenant-facing notification — which,
// with an all-silent catalogue, is not the first event but the first one
// somebody declares months later.
func TestMissingVaultFailsRatherThanPanics(t *testing.T) {
	email := &spyTransport{ch: notify.ChannelEmail}
	d := notify.NewDispatcher(notify.Deps{
		Transports: []notify.Transport{email}, Log: quiet(), // no Vault
	})

	err := d.Dispatch(context.Background(), notification(notify.Security))
	if err == nil {
		t.Fatal("a tenant notification with no vault wired must fail, not succeed silently")
	}
	if !errors.Is(err, notify.ErrNotConfigured) {
		t.Errorf("the failure should name the missing wiring, got: %v", err)
	}
	if email.calls != 0 {
		t.Error("delivered without resolving contact details")
	}
}

// Operator alerts never consult the vault, so an operator-only deployment must
// keep working with none wired.
func TestOperatorAlertsWorkWithoutAVault(t *testing.T) {
	email := &spyTransport{ch: notify.ChannelEmail}
	d := notify.NewDispatcher(notify.Deps{
		Transports: []notify.Transport{email}, Log: quiet(),
	})

	err := d.Dispatch(context.Background(), notify.Notification{
		Template:  "operator.alert",
		Class:     notify.Operator,
		Recipient: notify.Recipient{Address: "ops@chronos.test"},
	})
	if err != nil {
		t.Fatalf("operator alerts must not depend on a tenant vault: %v", err)
	}
	if email.calls != 1 {
		t.Fatal("the operator alert was not delivered")
	}
}

// ---------------------------------------------------------------------------
// Article 18 — processing restriction
// ---------------------------------------------------------------------------

type fakeRestrictions struct {
	restricted bool
	err        error
	asked      []string
}

func (f *fakeRestrictions) Restricted(_ context.Context, subjectID string) (bool, error) {
	f.asked = append(f.asked, subjectID)
	return f.restricted, f.err
}

// A RESTRICTED SUBJECT IS NOT CONTACTED, WHATEVER THE CLASS.
//
// Restriction is a legal obligation, not a preference — and Security and
// Transactional bypass preferences deliberately, so a check that lived with the
// preference logic would be bypassed by exactly the classes that send most.
//
// Suppressing Security is the specified behaviour (compliance.md §6: "no email,
// no push") and it is a real trade: somebody under restriction is not told when
// their password changes. It is recorded as a decision to revisit rather than
// silently narrowed here.
func TestARestrictedSubjectIsNotContacted(t *testing.T) {
	for _, class := range []notify.Class{
		notify.Security, notify.Transactional, notify.Activity, notify.Product,
	} {
		t.Run(class.String(), func(t *testing.T) {
			transport := &spyTransport{ch: notify.ChannelEmail}
			restrictions := &fakeRestrictions{restricted: true}
			d := notify.NewDispatcher(notify.Deps{
				Vault:        vault{addr: "user@example.test"},
				Transports:   []notify.Transport{transport},
				Restrictions: restrictions,
				Log:          quiet(),
			})

			if err := d.Dispatch(context.Background(), notify.Notification{
				Template:  "identity.password_changed",
				Class:     class,
				Recipient: notify.Recipient{SubjectID: "subj_1"},
			}); err != nil {
				t.Fatalf("a restricted subject produced an error: %v; suppression is a "+
					"correct outcome, not a failure to retry", err)
			}
			if transport.calls != 0 {
				t.Errorf("a %s notification reached a subject under Article 18 restriction",
					class)
			}
		})
	}
}

// AN UNRESTRICTED SUBJECT IS CONTACTED.
//
// The other half. Without it "suppress everything" passes the test above and
// nobody receives anything.
func TestAnUnrestrictedSubjectIsContacted(t *testing.T) {
	transport := &spyTransport{ch: notify.ChannelEmail}
	d := notify.NewDispatcher(notify.Deps{
		Vault:        vault{addr: "user@example.test"},
		Transports:   []notify.Transport{transport},
		Restrictions: &fakeRestrictions{restricted: false},
		Log:          quiet(),
	})

	if err := d.Dispatch(context.Background(), notify.Notification{
		Template:  "identity.password_changed",
		Class:     notify.Security,
		Recipient: notify.Recipient{SubjectID: "subj_1"},
	}); err != nil {
		t.Fatal(err)
	}
	if transport.calls != 1 {
		t.Fatalf("an unrestricted subject received %d notifications, want 1", transport.calls)
	}
}

// AN UNREADABLE RESTRICTION REFUSES TO SEND.
//
// The failure direction is the whole point. A rebuild that has not yet replayed
// a restriction leaves the table EMPTY, so treating an unreadable lookup as
// permission would resume processing for exactly the people who asked it to
// stop — and nobody would notice, because a sent notification looks like
// success.
//
// It returns an ERROR rather than suppressing, so the notification is retried
// once the lookup works rather than silently dropped.
func TestAnUnreadableRestrictionRefusesToSend(t *testing.T) {
	transport := &spyTransport{ch: notify.ChannelEmail}
	d := notify.NewDispatcher(notify.Deps{
		Vault:        vault{addr: "user@example.test"},
		Transports:   []notify.Transport{transport},
		Restrictions: &fakeRestrictions{err: errors.New("postgres: down")},
		Log:          quiet(),
	})

	err := d.Dispatch(context.Background(), notify.Notification{
		Template:  "identity.password_changed",
		Class:     notify.Security,
		Recipient: notify.Recipient{SubjectID: "subj_1"},
	})
	if err == nil {
		t.Fatal("an unreadable restriction sent the notification; a rebuild in progress " +
			"reads as 'nobody is restricted' and every restricted person is contacted")
	}
	if transport.calls != 0 {
		t.Error("the notification was sent despite the failed lookup")
	}
}

// OPERATOR NOTIFICATIONS ARE NOT SUBJECT TO IT.
//
// They carry no tenant subject at all — an operator alert is about the system,
// not about a person — so consulting a restriction for one would look up the
// empty string.
func TestAnOperatorNotificationIgnoresRestrictions(t *testing.T) {
	transport := &spyTransport{ch: notify.ChannelEmail}
	restrictions := &fakeRestrictions{restricted: true}
	d := notify.NewDispatcher(notify.Deps{
		Transports:   []notify.Transport{transport},
		Restrictions: restrictions,
		Log:          quiet(),
	})

	if err := d.Dispatch(context.Background(), notify.Notification{
		Template:  "operator.projection_stopped",
		Class:     notify.Operator,
		Recipient: notify.Recipient{Address: "ops@chronos.test"},
	}); err != nil {
		t.Fatal(err)
	}
	if len(restrictions.asked) != 0 {
		t.Error("an operator notification consulted the restriction table")
	}
	if transport.calls != 1 {
		t.Errorf("an operator alert was suppressed by a tenant's restriction")
	}
}

// NO RESTRICTION PORT MEANS NO RESTRICTIONS.
//
// A deployment without compliance wired sends normally, which is correct: there
// is nothing that can record a restriction, so there is none to honour.
func TestWithoutARestrictionPortNotificationsSend(t *testing.T) {
	transport := &spyTransport{ch: notify.ChannelEmail}
	d := notify.NewDispatcher(notify.Deps{
		Vault:      vault{addr: "user@example.test"},
		Transports: []notify.Transport{transport},
		Log:        quiet(),
	})

	if err := d.Dispatch(context.Background(), notify.Notification{
		Template:  "identity.password_changed",
		Class:     notify.Security,
		Recipient: notify.Recipient{SubjectID: "subj_1"},
	}); err != nil {
		t.Fatal(err)
	}
	if transport.calls != 1 {
		t.Error("a deployment with no compliance module suppressed a notification")
	}
}
