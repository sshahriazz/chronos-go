package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"
)

// ArbitrationWindow is how long an in-app read suppresses the email for an
// Activity notification (ADR-026, notification.md §6).
//
// Fifteen minutes: long enough that someone reading in the app does not also get
// mail, short enough that someone who steps away still receives it.
const ArbitrationWindow = 15 * time.Minute

// Dispatcher applies notification policy and fans out to channels.
//
// This is where the rules live, once, rather than in each transport: a channel
// that decided for itself whether a class ignores preferences would eventually
// disagree with the others, and the disagreement would be a security alert
// nobody received.
type Dispatcher struct {
	vault       Vault
	prefs       Preferences
	readState   ReadState
	transports  map[Channel]Transport
	log         *slog.Logger
	window      time.Duration
	obs         Observer
	defaultChan []Channel

	// restrictions answers Article 18. Optional: a deployment without compliance
	// wired sends normally, which is correct — there is nothing to restrict when
	// nothing can record a restriction.
	restrictions Restrictions

	// objections answers Article 21, per purpose. Optional for restrictions'
	// reason.
	objections Objections
}

// Restrictions answers "has this subject halted processing" (Article 18).
//
// A port rather than a table handle, so this package never learns which store
// holds it. compliance owns the events and the projection; the dispatcher only
// needs the answer.
//
// It is consulted for every TENANT-FACING notification, including Security and
// Transactional, and that is deliberate: a restriction is a legal obligation
// rather than a preference, and a class that could bypass it would make it not
// an obligation. See Dispatch for the tension that creates and where it is
// recorded.
type Restrictions interface {
	Restricted(ctx context.Context, subjectID string) (bool, error)
}

// Objections answers "has this subject objected to this purpose" (Article 21).
//
// # A separate port from Restrictions, and a separate lookup
//
// The two rights are not the same shape and merging them would lose the
// difference. A restriction halts everything but storage while a dispute runs;
// an objection stops ONE purpose that rests on legitimate interests, until its
// author withdraws it. A restricted subject receives no transactional receipt;
// an objecting subject does.
//
// So this is consulted only for the classes Article 21 can reach — see
// Class.ObjectionablePurpose — and Restrictions is consulted for everything. The
// difference in scope IS the difference in the rights.
//
// # Why it is a purpose STRING and not a typed value
//
// The kernel may not import a module (depguard: platform-is-pure), and the
// purpose vocabulary belongs to compliance's domain. A string keeps the
// dependency pointing the right way, and the pairing is held by
// TestEveryObjectionablePurposeIsADomainPurpose rather than by the type system.
type Objections interface {
	Objected(ctx context.Context, subjectID, purpose string) (bool, error)
}

// Observer records what was delivered, suppressed and skipped. Optional.
//
// Plain strings rather than this package's own types, so a metrics
// implementation satisfies it structurally without importing the kernel — the
// same arrangement projection.Metrics and reactor.Metrics use.
type Observer interface {
	Delivered(template, class, channel string)
	Suppressed(template, class, channel, reason string)
	Failed(template, class, channel string)
}

type noObserver struct{}

func (noObserver) Delivered(string, string, string)          {}
func (noObserver) Suppressed(string, string, string, string) {}
func (noObserver) Failed(string, string, string)             {}

// Deps is what a Dispatcher needs.
type Deps struct {
	Vault      Vault
	Prefs      Preferences
	ReadState  ReadState
	Transports []Transport
	Log        *slog.Logger
	Observer   Observer

	// Restrictions answers Article 18. Optional — a deployment with no
	// compliance module wired sends normally, which is correct: nothing can
	// record a restriction, so there is none to honour.
	Restrictions Restrictions

	// Objections answers Article 21. Optional, for Restrictions' reason.
	Objections Objections

	// Window overrides the arbitration window. Zero takes the default.
	Window time.Duration
}

func NewDispatcher(d Deps) *Dispatcher {
	transports := make(map[Channel]Transport, len(d.Transports))
	var order []Channel
	for _, t := range d.Transports {
		transports[t.Channel()] = t
		order = append(order, t.Channel())
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Observer == nil {
		d.Observer = noObserver{}
	}
	if d.Window <= 0 {
		d.Window = ArbitrationWindow
	}
	if d.Vault == nil {
		// A nil vault would panic on the first tenant-facing notification —
		// which, with an all-silent catalogue, is not the first event but the
		// first one somebody adds months later. A stand-in turns that into a
		// visible, parked failure naming the missing wiring.
		d.Vault = unconfiguredVault{}
	}
	return &Dispatcher{
		vault: d.Vault, prefs: d.Prefs, readState: d.ReadState,
		transports: transports, log: d.Log, window: d.Window,
		obs: d.Observer, defaultChan: order, restrictions: d.Restrictions,
		objections: d.Objections,
	}
}

// Channels reports which transports are wired.
//
// Exposed so a test can assert the COMPOSITION ROOT, not just the parts. Every
// component test can pass while a channel is never constructed by any binary —
// and a channel that is never constructed delivers nothing, silently.
func (d *Dispatcher) Channels() []Channel {
	out := make([]Channel, 0, len(d.transports))
	for ch := range d.transports {
		out = append(out, ch)
	}
	slices.Sort(out)
	return out
}

// HasPreferences reports whether user channel toggles are consulted. A nil port
// is permissive, so its absence is invisible at runtime.
func (d *Dispatcher) HasPreferences() bool { return d.prefs != nil }

// HasReadState reports whether alert arbitration can happen (ADR-026).
func (d *Dispatcher) HasReadState() bool { return d.readState != nil }

// HasRestrictions reports whether Article 18 is honoured on this path.
//
// Exposed so a composition-root test can assert it, for the reason Channels is:
// a nil port is permissive and therefore invisible at runtime — every unit test
// below it passes while a legal obligation is not enforced by any binary.
func (d *Dispatcher) HasRestrictions() bool { return d.restrictions != nil }

// HasObjections reports whether Article 21 is honoured on this path.
func (d *Dispatcher) HasObjections() bool { return d.objections != nil }

// Dispatch resolves the recipient, applies policy, and delivers.
//
// It returns an error only when something should be RETRIED. A suppressed
// notification and an erased subject both return nil: neither is a failure, and
// retrying either would be pointless — or, for an erased subject, an attempt to
// reach someone who asked to be forgotten.
func (d *Dispatcher) Dispatch(ctx context.Context, n Notification) error {
	if err := n.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	if n.Class != Operator {
		// ARTICLE 18, checked before the address is even resolved.
		//
		// Restriction is not a preference, so it is here rather than in
		// allowed(): Transactional, Activity and Product all reach delivery, and
		// a legal obligation that a class could bypass is not an obligation.
		//
		// # SECURITY IS EXEMPT, and this is the account-takeover tripwire
		//
		// compliance.md §6 says "no email, no push" without qualification, and
		// this narrows it. The reason is the one the Preferences port already
		// documents for the identical attack: if a control a session holder can
		// set could stop a security alert, an attacker who gains access simply
		// sets it and silences the message that would reveal them — the tripwire
		// disabled by the takeover itself.
		//
		// Restriction is exactly such a control. It reintroduces that hole
		// through a different door: restrict the victim, then operate on their
		// account with no password-changed, no new-device and no
		// credential-compromised mail reaching them. Requiring AAL2 to invoke it
		// raises the bar and does not remove the hole.
		//
		// Article 18(2) is what makes the exemption lawful rather than
		// convenient: restriction does not bar processing necessary for the
		// establishment, exercise or defence of legal claims, nor for protecting
		// the rights of a natural person — and a warning to the data subject
		// about their own account is squarely the second.
		//
		// It is deliberately narrow. Only Security is exempt; a restriction still
		// stops every Transactional receipt, every Activity nudge and everything
		// Product.
		if d.restrictions != nil && n.Class != Security {
			restricted, err := d.restrictions.Restricted(ctx, n.Recipient.SubjectID)
			if err != nil {
				// REFUSES rather than sends. A rebuild that has not yet replayed a
				// restriction leaves the table empty, so an unreadable lookup
				// treated as permission would resume processing for exactly the
				// people who asked it to stop — the wrong direction to fail in.
				return fmt.Errorf("notify: reading processing restrictions: %w", err)
			}
			if restricted {
				d.obs.Suppressed(n.Template, n.Class.String(), "", "processing_restricted")
				d.log.Info("notification skipped: processing restricted (Article 18)",
					"template", n.Template, "class", n.Class.String())
				return nil
			}
		}

		// ARTICLE 21, and it is a NARROWER gate than Article 18 above rather
		// than a second copy of it.
		//
		// # Only the classes the article reaches are asked about
		//
		// Objection applies to processing grounded in legitimate interests.
		// Security and transactional mail rest on contract and on our own legal
		// obligations, so `ObjectionablePurpose` reports nothing for them and
		// this whole block is skipped — which is also why the extra lookup costs
		// nothing on the common path: most of what this system sends is one of
		// those two.
		//
		// # The difference from a restriction, stated where it is enforced
		//
		// A restricted subject loses their receipts. An objecting subject keeps
		// them and loses one purpose. If those two ever suppress the same set,
		// one of the rights has absorbed the other and the narrower one should be
		// deleted rather than kept as a synonym.
		//
		// # It is NOT a preference, even though it lands in the same decision
		//
		// A preference is checked in allowed(), per channel, and a person may set
		// one and unset it as a product control. An objection is a legal
		// instruction about a PURPOSE, so it stops that processing on every
		// channel at once and no product control may clear it. Putting it here,
		// beside the restriction and above the channel loop, is what makes the
		// second property true by construction.
		if purpose, objectionable := n.Class.ObjectionablePurpose(); objectionable &&
			d.objections != nil {
			objected, err := d.objections.Objected(ctx, n.Recipient.SubjectID, purpose)
			if err != nil {
				// REFUSES rather than sends, exactly as the restriction lookup
				// does. A rebuild that has not yet replayed an objection leaves
				// the table empty, so an unreadable lookup treated as permission
				// would resume processing for precisely the people who stopped
				// it — the wrong direction to fail in.
				return fmt.Errorf("notify: reading processing objections: %w", err)
			}
			if objected {
				d.obs.Suppressed(n.Template, n.Class.String(), "", "processing_objected")
				d.log.Info("notification skipped: processing objected to (Article 21)",
					"template", n.Template, "class", n.Class.String(), "purpose", purpose)
				return nil
			}
		}

		resolved, err := d.vault.Resolve(ctx, n.Recipient.SubjectID, n.Address)
		switch {
		case errors.Is(err, ErrSubjectErased):
			// Correct outcome, not an error. Someone who exercised erasure has
			// no address; there is nothing to deliver and nothing to retry.
			d.obs.Suppressed(n.Template, n.Class.String(), "", "subject_erased")
			d.log.Info("notification skipped: subject erased",
				"template", n.Template, "class", n.Class.String())
			return nil
		case err != nil:
			// Unknown: the vault may be down. Retry.
			return fmt.Errorf("notify: resolving subject: %w", err)
		}
		// Vault data wins over anything the caller supplied: contact details
		// must never come from an event payload.
		n.Recipient.Address = resolved.Address
		n.Recipient.Name = resolved.Name
		if resolved.Locale != "" {
			n.Recipient.Locale = resolved.Locale
		}
		if resolved.Timezone != "" {
			n.Recipient.Timezone = resolved.Timezone
		}
	}

	channels := n.Channels
	if len(channels) == 0 {
		channels = d.defaultChan
	}

	var firstErr error
	for _, ch := range channels {
		transport, ok := d.transports[ch]
		if !ok {
			continue
		}
		send, reason, err := d.allowed(ctx, n, ch)
		if err != nil {
			// Policy could not be evaluated. Better to retry than to guess:
			// guessing "yes" spams and guessing "no" loses a security alert.
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if !send {
			d.obs.Suppressed(n.Template, n.Class.String(), string(ch), reason)
			continue
		}

		if err := transport.Deliver(ctx, n); err != nil {
			if errors.Is(err, ErrSubjectErased) || errors.Is(err, ErrNoAddress) {
				d.obs.Suppressed(n.Template, n.Class.String(), string(ch), "no_address")
				continue
			}
			d.obs.Failed(n.Template, n.Class.String(), string(ch))
			d.log.Error("notification delivery failed",
				"template", n.Template, "channel", string(ch), "error", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("notify: %s: %w", ch, err)
			}
			continue
		}
		d.obs.Delivered(n.Template, n.Class.String(), string(ch))
	}
	return firstErr
}

// allowed applies class policy, then the recipient's own channel toggles, then
// read arbitration — in that order.
//
// The order is the design. Class is checked FIRST, so a Security notification
// never reaches the preference lookup at all. That is what stops someone who
// has gained access to an account from switching off email and silencing the
// alert that would reveal them.
func (d *Dispatcher) allowed(ctx context.Context, n Notification, ch Channel) (bool, string, error) {
	if n.Class.IgnoresPreferences() {
		return true, "", nil
	}

	if d.prefs != nil {
		enabled, err := d.prefs.Enabled(ctx, n.OrgID, n.Recipient.SubjectID, n.Template, ch)
		if err != nil {
			return false, "", fmt.Errorf("notify: reading preferences: %w", err)
		}
		if !enabled {
			return false, "preference_off", nil
		}
	}

	// Arbitration: an Activity email is pointless if it was already read in the
	// app. Only email is suppressed — the in-app entry IS the thing that was
	// read, and suppressing it would make the read impossible.
	if ch == ChannelEmail && n.Class.SuppressibleByRead() && d.readState != nil {
		key := n.IdempotencyKey
		if key == "" {
			key = n.Template
		}
		read, err := d.readState.ReadWithin(ctx, n.OrgID, n.Recipient.SubjectID, key, d.window)
		if err != nil {
			return false, "", fmt.Errorf("notify: reading read-state: %w", err)
		}
		if read {
			return false, "read_in_app", nil
		}
	}
	return true, "", nil
}

// unconfiguredVault stands in when no vault is wired. Operator notifications
// never consult it, so an operator-only deployment runs unaffected; anything
// tenant-facing fails loudly instead of panicking.
type unconfiguredVault struct{}

func (unconfiguredVault) Resolve(context.Context, string, AddressChoice) (Recipient, error) {
	return Recipient{}, fmt.Errorf("%w: no PII vault is wired, so contact details "+
		"for a tenant subject cannot be resolved", ErrNotConfigured)
}

// ErrNotConfigured means a dependency needed for this notification is absent.
// It is a deployment fault, not a transient one: retrying cannot wire a vault.
var ErrNotConfigured = errors.New("notify: not configured")

// ErrInvalid marks a notification that can never be delivered as constructed.
// It must not be retried.
var ErrInvalid = errors.New("notify: invalid notification")
