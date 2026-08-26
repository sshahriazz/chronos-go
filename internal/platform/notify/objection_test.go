package notify_test

import (
	"context"
	"errors"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/notify"
)

// ---------------------------------------------------------------------------
// Article 21 — objection to processing
// ---------------------------------------------------------------------------

type fakeObjections struct {
	objected bool
	err      error
	asked    []string
}

func (f *fakeObjections) Objected(
	_ context.Context, subjectID, purpose string,
) (bool, error) {
	f.asked = append(f.asked, subjectID+"|"+purpose)
	return f.objected, f.err
}

// AN OBJECTING SUBJECT STOPS RECEIVING THE PURPOSE THEY OBJECTED TO.
func TestAnObjectingSubjectIsNotProcessedForThatPurpose(t *testing.T) {
	for _, class := range []notify.Class{notify.Activity, notify.Product} {
		t.Run(class.String(), func(t *testing.T) {
			email := &spyTransport{ch: notify.ChannelEmail}
			d := notify.NewDispatcher(notify.Deps{
				Vault: vault{}, Prefs: prefs{enabled: true},
				Objections: &fakeObjections{objected: true},
				Transports: []notify.Transport{email}, Log: quiet(),
			})

			if err := d.Dispatch(context.Background(), notification(class)); err != nil {
				t.Fatalf("dispatch: %v", err)
			}
			if email.calls != 0 {
				t.Fatalf("a %v message was sent to somebody who objected to that "+
					"processing", class)
			}
		})
	}
}

// AN OBJECTION IS NOT A RESTRICTION, AND THIS IS WHERE THE DIFFERENCE IS
// OBSERVABLE.
//
// Article 18 restriction halts everything except storage — transactional
// receipts included — while a dispute about the data runs. Article 21 objection
// stops one purpose that rests on legitimate interests and leaves the rest
// alone: the account keeps working, and the person keeps getting the receipts
// and verification links they need to use it.
//
// If this test ever fails, objection has absorbed restriction (or the reverse)
// and one of the two should be deleted rather than kept as a synonym for the
// other. It is the concrete form of the argument in domain.Objection's own doc.
func TestAnObjectionDoesNotStopTransactionalMail(t *testing.T) {
	email := &spyTransport{ch: notify.ChannelEmail}
	objections := &fakeObjections{objected: true}
	d := notify.NewDispatcher(notify.Deps{
		Vault: vault{}, Prefs: prefs{enabled: true},
		Objections: objections,
		Transports: []notify.Transport{email}, Log: quiet(),
	})

	if err := d.Dispatch(context.Background(), notification(notify.Transactional)); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if email.calls != 1 {
		t.Fatal("a transactional message was withheld from somebody who objected under " +
			"Article 21. That right does not reach processing grounded in contract, and " +
			"an implementation that stops receipts has become a restriction with a " +
			"different name")
	}
	if len(objections.asked) != 0 {
		t.Errorf("the objection store was consulted for a transactional message (%v). "+
			"Article 21 cannot reach it, so the lookup buys nothing and costs a round "+
			"trip on the majority of what this system sends", objections.asked)
	}
}

// AN OBJECTION CAN NEVER SILENCE A SECURITY ALERT.
//
// The same reasoning the preference gate and the restriction gate both carry: a
// control a session holder can set, which stops a security alert, is a control
// an attacker sets to silence the message that would reveal them.
//
// Here it holds for a legal reason as well as a practical one. Security alerts
// rest on contract and on protecting the rights of a natural person, not on
// legitimate interests, so Article 21 does not reach them at all.
func TestAnObjectionCannotSilenceASecurityAlert(t *testing.T) {
	email := &spyTransport{ch: notify.ChannelEmail}
	objections := &fakeObjections{objected: true}
	d := notify.NewDispatcher(notify.Deps{
		Vault: vault{}, Prefs: prefs{enabled: false},
		Objections: objections,
		Transports: []notify.Transport{email}, Log: quiet(),
	})

	if err := d.Dispatch(context.Background(), notification(notify.Security)); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if email.calls != 1 {
		t.Fatal("a security alert was suppressed by an objection — the account-takeover " +
			"tripwire, disabled by a control the attacker can set")
	}
}

// AN UNREADABLE OBJECTION LOOKUP REFUSES TO SEND.
//
// A rebuild that has not yet replayed an objection leaves the table empty, so
// treating an unreadable lookup as permission would resume processing for
// precisely the people who stopped it. The failure would be silent: no error, no
// metric, and mail arriving for a reason the recipient believes was ruled out.
//
// An error is returned rather than swallowed so the reactor RETRIES, which is
// what makes the refusal a delay rather than a lost message.
func TestAnUnreadableObjectionRefusesToSend(t *testing.T) {
	email := &spyTransport{ch: notify.ChannelEmail}
	d := notify.NewDispatcher(notify.Deps{
		Vault: vault{}, Prefs: prefs{enabled: true},
		Objections: &fakeObjections{err: errors.New("postgres is unreachable")},
		Transports: []notify.Transport{email}, Log: quiet(),
	})

	err := d.Dispatch(context.Background(), notification(notify.Activity))
	if err == nil {
		t.Fatal("an activity message was sent while the objection lookup could not " +
			"answer; an unreadable objection is not an absent one")
	}
	if email.calls != 0 {
		t.Error("it was delivered anyway")
	}
}

// THE PURPOSE ASKED ABOUT IS THE ONE THE CLASS RESTS ON.
//
// The lookup is a composite key. If the dispatcher asked about the wrong
// purpose, every objection would record correctly, project correctly, and match
// nothing — the person is told the processing stopped and the mail keeps
// arriving.
func TestTheDispatcherAsksAboutTheClassesOwnPurpose(t *testing.T) {
	for class, want := range map[notify.Class]string{
		notify.Activity: notify.PurposeActivityNotifications,
		notify.Product:  notify.PurposeProductUpdates,
	} {
		t.Run(class.String(), func(t *testing.T) {
			objections := &fakeObjections{}
			d := notify.NewDispatcher(notify.Deps{
				Vault: vault{}, Prefs: prefs{enabled: true},
				Objections: objections,
				Transports: []notify.Transport{&spyTransport{ch: notify.ChannelEmail}},
				Log:        quiet(),
			})
			if err := d.Dispatch(context.Background(), notification(class)); err != nil {
				t.Fatal(err)
			}
			if len(objections.asked) != 1 {
				t.Fatalf("the objection store was asked %d times", len(objections.asked))
			}
			if got := objections.asked[0]; got != "sub_1|"+want {
				t.Errorf("asked %q, want %q — a mismatched purpose makes every objection "+
					"to it match nothing at send time", got, "sub_1|"+want)
			}
		})
	}
}

// A DISPATCHER WITH NO OBJECTION PORT SAYS SO.
//
// A nil port is permissive and therefore invisible at runtime: every unit test
// below it passes while a legal obligation is enforced by no binary. This is the
// seam a composition-root test asserts on, and it exists for the reason
// `Channels()` does — three adapters in this repository were fully built, fully
// tested and constructed by nothing.
func TestADispatcherReportsWhetherTheRightsArePluggedIn(t *testing.T) {
	bare := notify.NewDispatcher(notify.Deps{Vault: vault{}, Log: quiet()})
	if bare.HasObjections() {
		t.Error("a dispatcher with no objection port reports that it has one")
	}
	if bare.HasRestrictions() {
		t.Error("a dispatcher with no restriction port reports that it has one")
	}

	wired := notify.NewDispatcher(notify.Deps{
		Vault: vault{}, Log: quiet(),
		Objections:   &fakeObjections{},
		Restrictions: &fakeRestrictions{},
	})
	if !wired.HasObjections() || !wired.HasRestrictions() {
		t.Error("a wired dispatcher reports the rights as unplugged, so the " +
			"composition-root assertion can never fail and proves nothing")
	}
}
