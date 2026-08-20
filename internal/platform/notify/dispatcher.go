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
		obs: d.Observer, defaultChan: order,
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
		resolved, err := d.vault.Resolve(ctx, n.Recipient.SubjectID)
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

func (unconfiguredVault) Resolve(context.Context, string) (Recipient, error) {
	return Recipient{}, fmt.Errorf("%w: no PII vault is wired, so contact details "+
		"for a tenant subject cannot be resolved", ErrNotConfigured)
}

// ErrNotConfigured means a dependency needed for this notification is absent.
// It is a deployment fault, not a transient one: retrying cannot wire a vault.
var ErrNotConfigured = errors.New("notify: not configured")

// ErrInvalid marks a notification that can never be delivered as constructed.
// It must not be retried.
var ErrInvalid = errors.New("notify: invalid notification")
