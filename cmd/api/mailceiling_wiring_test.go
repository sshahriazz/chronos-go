package main

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/ratelimit"
)

// The verification-mail ceiling is asserted at the COMPOSITION ROOT, because
// that is the only place its absence is visible.
//
// A resend with no ceiling behind it works perfectly. It appends the event, the
// reactor mints a token, the mail goes out, every test in identity/app and
// identity/api passes, and the endpoint is an unauthenticated mail bomb aimed at
// any address a caller can type. Nothing at runtime distinguishes "the ceiling is
// configured" from "the ceiling was never wired" until somebody's mailbox is
// full — so it is asserted here, against the two limiters the root actually
// built and handed to app.NewResendVerification.

func TestTheVerificationMailCeilingIsWired(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.mailAddressLimiter == nil {
		t.Fatal("no per-address mail ceiling was built: an unauthenticated caller can " +
			"have unlimited verification mail sent to any address they can type")
	}
	if d.mailCallerLimiter == nil {
		t.Fatal("no per-caller mail ceiling was built: an unauthenticated enumeration " +
			"sweep across every address an attacker holds is unbounded")
	}

	// Two windows on each axis. NOTIFICATIONS.md §4 asks for an HOURLY ceiling per
	// address, and one window cannot express both shapes of abuse — three an hour
	// with no daily rule is 72 messages a day, which is the flood the rule exists
	// to prevent.
	for _, axis := range []struct {
		name  string
		rules []ratelimit.Rule
	}{
		{"address", d.mailAddressLimiter.Rules()},
		{"caller", d.mailCallerLimiter.Rules()},
	} {
		if len(axis.rules) < 2 {
			t.Errorf("the %s ceiling carries %d rule(s): %v. A single window bounds one "+
				"shape of abuse and leaves the other unbounded",
				axis.name, len(axis.rules), axis.rules)
			continue
		}
		// Rules() reports shortest window first.
		shortest, longest := axis.rules[0], axis.rules[len(axis.rules)-1]
		if shortest.Window > time.Hour {
			t.Errorf("the %s ceiling's narrowest window is %s; NOTIFICATIONS.md §4 asks "+
				"for an hourly ceiling", axis.name, shortest.Window)
		}
		if longest.Window <= shortest.Window {
			t.Errorf("the %s ceiling's two windows are %s and %s: the second is not a "+
				"wider bound, so it is decoration",
				axis.name, shortest.Window, longest.Window)
		}
		if longest.Limit <= shortest.Limit {
			t.Errorf("the %s ceiling permits %d per %s and %d per %s: the wider window is "+
				"never the rule that trips, so it counts nothing",
				axis.name, shortest.Limit, shortest.Window, longest.Limit, longest.Window)
		}
	}

	// One address may not be permitted more mail than one caller can send. The
	// reverse ordering makes the caller axis unreachable — it would never be the
	// rule that trips — and the enumeration control would be dead code.
	addr, caller := d.mailAddressLimiter.Rules(), d.mailCallerLimiter.Rules()
	if addr[0].Limit > caller[0].Limit {
		t.Errorf("the per-address hourly limit (%d) exceeds the per-caller one (%d): the "+
			"caller ceiling can never be the rule that trips first, and the enumeration "+
			"control does nothing", addr[0].Limit, caller[0].Limit)
	}
}

// The two axes must count under DIFFERENT key prefixes.
//
// Sharing one prefix would let one axis consume the other's budget wherever the
// two scopes collide. The prefixes are constants in identity.go, so this asserts
// on the values the limiters were actually built with.
func TestTheTwoMailCeilingsDoNotShareACounter(t *testing.T) {
	t.Parallel()
	if mailAddressLimitPrefix == mailCallerLimitPrefix {
		t.Fatalf("both mail ceilings use the prefix %q, so one axis consumes the other's "+
			"budget", mailAddressLimitPrefix)
	}
	if mailAddressLimitPrefix == authnLimitPrefix || mailCallerLimitPrefix == authnLimitPrefix {
		t.Fatal("a mail ceiling shares the authentication ceiling's prefix: a failed login " +
			"would spend somebody's verification-mail budget and vice versa")
	}
	// The per-address prefix must NOT be verification-specific. "An hourly ceiling
	// per address across ALL classes" (NOTIFICATIONS.md §4) is only true if the
	// password-reset mail that lands next increments the SAME key — otherwise an
	// attacker alternates between two endpoints and doubles the mail one victim
	// receives.
	for _, forbidden := range []string{"verif", "resend"} {
		if strings.Contains(mailAddressLimitPrefix, forbidden) {
			t.Errorf("the per-address prefix %q contains %q, so it is specific to one class "+
				"of mail; the next class gets a fresh budget and the cross-class ceiling "+
				"is fiction", mailAddressLimitPrefix, forbidden)
		}
	}
}
