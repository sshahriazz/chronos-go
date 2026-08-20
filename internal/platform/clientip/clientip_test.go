package clientip_test

import (
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/clientip"
)

// TestResolverScope is the whole security argument of this package, expressed as
// a table.
//
// Every case is written as "what does an ATTACKER get out of this", because the
// only interesting failures here are the ones where a caller improves their own
// outcome by writing a header. The peer address is unforgeable; anything else in
// this table is not.
func TestResolverScope(t *testing.T) {
	t.Parallel()

	const peer = "203.0.113.9:44321"
	const peerScope = "203.0.113.9"

	tests := []struct {
		name      string
		hops      int
		peer      string
		forwarded []string
		want      string
	}{
		// ---- zero hops: the header does not exist ------------------------
		{
			name:      "zero hops ignores the header entirely",
			hops:      0,
			peer:      peer,
			forwarded: []string{"198.51.100.1, 198.51.100.2"},
			want:      peerScope,
		},
		{
			name: "zero hops with no header is the peer address",
			hops: 0,
			peer: peer,
			want: peerScope,
		},
		{
			name:      "zero hops ignores a header naming a single plausible client",
			hops:      0,
			peer:      peer,
			forwarded: []string{"198.51.100.1"},
			want:      peerScope,
		},

		// ---- counting from the right --------------------------------------
		{
			name:      "one hop takes the last entry",
			hops:      1,
			peer:      peer,
			forwarded: []string{"198.51.100.7, 192.0.2.44"},
			want:      "192.0.2.44",
		},
		{
			name:      "two hops take the second-from-last entry",
			hops:      2,
			peer:      peer,
			forwarded: []string{"198.51.100.7, 192.0.2.44, 192.0.2.90"},
			want:      "192.0.2.44",
		},
		{
			name:      "three hops with exactly three entries take the leftmost",
			hops:      3,
			peer:      peer,
			forwarded: []string{"192.0.2.44, 198.51.100.7, 198.51.100.8"},
			want:      "192.0.2.44",
		},
		{
			name:      "exactly as many entries as hops is enough",
			hops:      1,
			peer:      peer,
			forwarded: []string{"192.0.2.44"},
			want:      "192.0.2.44",
		},

		// ---- the spoof --------------------------------------------------
		//
		// The caller writes as many entries as they like; the proxy appends the
		// address it actually saw. Whatever the caller writes stays to the LEFT
		// and can never be selected, however long the list.
		{
			name:      "a spoofed leftmost entry is never selected",
			hops:      1,
			peer:      peer,
			forwarded: []string{"1.1.1.1, 2.2.2.2, 3.3.3.3, 192.0.2.44"},
			want:      "192.0.2.44",
		},
		{
			name:      "a spoofed list cannot reach past two trusted hops either",
			hops:      2,
			peer:      peer,
			forwarded: []string{"1.1.1.1, 2.2.2.2, 192.0.2.44, 198.51.100.7"},
			want:      "192.0.2.44",
		},
		{
			name:      "padding the list with empties does not shift the selection",
			hops:      1,
			peer:      peer,
			forwarded: []string{"1.1.1.1,,,, 192.0.2.44"},
			want:      "192.0.2.44",
		},

		// ---- too few entries: fall back, never leftward -------------------
		{
			name:      "a header shorter than the hop count falls back to the peer",
			hops:      2,
			peer:      peer,
			forwarded: []string{"192.0.2.44"},
			want:      peerScope,
		},
		{
			name: "an absent header falls back to the peer",
			hops: 1,
			peer: peer,
			want: peerScope,
		},
		{
			name:      "an empty header line falls back to the peer",
			hops:      1,
			peer:      peer,
			forwarded: []string{""},
			want:      peerScope,
		},

		// ---- malformed entries fail closed --------------------------------
		{
			name:      "a garbage entry falls back to the peer",
			hops:      1,
			peer:      peer,
			forwarded: []string{"192.0.2.44, not-an-ip"},
			want:      peerScope,
		},
		{
			name:      "a hostname is not an address and falls back to the peer",
			hops:      1,
			peer:      peer,
			forwarded: []string{"client.example.com"},
			want:      peerScope,
		},
		{
			name:      "an RFC 7239 for= fragment is not an address",
			hops:      1,
			peer:      peer,
			forwarded: []string{"for=192.0.2.44"},
			want:      peerScope,
		},
		{
			name:      "a whitespace-only entry falls back to the peer",
			hops:      1,
			peer:      peer,
			forwarded: []string{"192.0.2.44,    "},
			want:      peerScope,
		},
		{
			name:      "an empty entry in the selected position falls back to the peer",
			hops:      2,
			peer:      peer,
			forwarded: []string{"1.1.1.1,,192.0.2.44"},
			want:      peerScope,
		},
		{
			name:      "a CIDR block is not an address",
			hops:      1,
			peer:      peer,
			forwarded: []string{"192.0.2.0/24"},
			want:      peerScope,
		},

		// ---- shapes real infrastructure emits ------------------------------
		{
			name:      "an entry carrying a port keeps only the address",
			hops:      1,
			peer:      peer,
			forwarded: []string{"192.0.2.44:51000"},
			want:      "192.0.2.44",
		},
		{
			name:      "surrounding whitespace is trimmed",
			hops:      1,
			peer:      peer,
			forwarded: []string{"   192.0.2.44   "},
			want:      "192.0.2.44",
		},
		{
			name:      "several header lines are one list, in arrival order",
			hops:      1,
			peer:      peer,
			forwarded: []string{"1.1.1.1", "192.0.2.44"},
			want:      "192.0.2.44",
		},
		{
			name:      "several header lines are counted as one list from the right",
			hops:      2,
			peer:      peer,
			forwarded: []string{"1.1.1.1, 192.0.2.44", "198.51.100.7"},
			want:      "192.0.2.44",
		},

		// ---- IPv6 ---------------------------------------------------------
		{
			name:      "a bare IPv6 entry is reduced to its /64",
			hops:      1,
			peer:      peer,
			forwarded: []string{"2001:db8:1:2:3:4:5:6"},
			want:      "2001:db8:1:2::/64",
		},
		{
			name:      "a bracketed IPv6 entry with a port is reduced to its /64",
			hops:      1,
			peer:      peer,
			forwarded: []string{"[2001:db8:1:2:3:4:5:6]:51000"},
			want:      "2001:db8:1:2::/64",
		},
		{
			name:      "a bracketed IPv6 entry without a port is reduced to its /64",
			hops:      1,
			peer:      peer,
			forwarded: []string{"[2001:db8:1:2:3:4:5:6]"},
			want:      "2001:db8:1:2::/64",
		},
		{
			name:      "two addresses in one /64 are one bucket",
			hops:      1,
			peer:      peer,
			forwarded: []string{"2001:db8:1:2:ffff:ffff:ffff:ffff"},
			want:      "2001:db8:1:2::/64",
		},
		{
			name:      "a different /64 is a different bucket",
			hops:      1,
			peer:      peer,
			forwarded: []string{"2001:db8:1:3::1"},
			want:      "2001:db8:1:3::/64",
		},
		{
			name:      "an IPv4-mapped IPv6 entry folds onto the IPv4 address",
			hops:      1,
			peer:      peer,
			forwarded: []string{"::ffff:192.0.2.44"},
			want:      "192.0.2.44",
		},
		{
			name:      "a zone identifier is stripped rather than becoming its own bucket",
			hops:      1,
			peer:      peer,
			forwarded: []string{"fe80::1%eth0"},
			want:      "fe80::/64",
		},

		// ---- the peer address itself ---------------------------------------
		{
			name: "an empty peer with no header is unattributed",
			hops: 0,
			peer: "",
			want: clientip.Unattributed,
		},
		{
			name:      "an empty peer does not become an excuse to trust the header",
			hops:      0,
			peer:      "",
			forwarded: []string{"192.0.2.44"},
			want:      clientip.Unattributed,
		},
		{
			name: "a peer with no port is used as-is",
			hops: 0,
			peer: "203.0.113.9",
			want: peerScope,
		},
		{
			name: "an IPv6 peer is reduced to its /64",
			hops: 0,
			peer: "[2001:db8:1:2::5]:44321",
			want: "2001:db8:1:2::/64",
		},
		{
			name: "a non-address peer is passed through rather than discarded",
			hops: 0,
			peer: "/tmp/chronos.sock",
			want: "/tmp/chronos.sock",
		},
		{
			name:      "a malformed header falls back to a normalised IPv6 peer",
			hops:      1,
			peer:      "[2001:db8:1:2::5]:44321",
			forwarded: []string{"nonsense"},
			want:      "2001:db8:1:2::/64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r, err := clientip.NewResolver(tt.hops)
			if err != nil {
				t.Fatalf("NewResolver(%d): %v", tt.hops, err)
			}
			got := r.Scope(tt.peer, tt.forwarded)
			if got != tt.want {
				t.Errorf("Scope(%q, %q) with %d trusted hop(s) = %q, want %q",
					tt.peer, tt.forwarded, tt.hops, got, tt.want)
			}
			// ratelimit.Limiter refuses an empty scope, which would turn any hole in
			// the fallback chain into a 500 on the endpoint rather than a weakened
			// ceiling. Asserted for every row rather than in one case of its own.
			if strings.TrimSpace(got) == "" {
				t.Error("Scope returned an empty scope; the limiter refuses one outright")
			}
		})
	}
}

// TestTheZeroResolverTrustsNothing is the property that makes the field safe to
// carry as a value in a struct literal.
//
// If this ever fails, a Deps literal that forgot the field would start trusting
// a header — the failure mode that has no symptom, no log line and no metric.
func TestTheZeroResolverTrustsNothing(t *testing.T) {
	t.Parallel()

	var zero clientip.Resolver
	if hops := zero.TrustedHops(); hops != 0 {
		t.Errorf("the zero Resolver trusts %d hops, want 0", hops)
	}

	const peer = "203.0.113.9:44321"
	spoofed := []string{"1.1.1.1, 2.2.2.2, 3.3.3.3"}

	got := zero.Scope(peer, spoofed)
	if got != "203.0.113.9" {
		t.Errorf("the zero Resolver returned %q for a spoofed header; want the peer "+
			"address %q", got, "203.0.113.9")
	}

	// And it is the SAME answer an explicitly-zero resolver gives, which is what
	// "an unconfigured deployment behaves exactly as it did" means in practice.
	configured, err := clientip.NewResolver(0)
	if err != nil {
		t.Fatalf("NewResolver(0): %v", err)
	}
	if want := configured.Scope(peer, spoofed); got != want {
		t.Errorf("the zero Resolver answered %q where NewResolver(0) answered %q", got, want)
	}
}

// TestNewResolverBounds. Both ends are refused rather than clamped: a clamp
// would let a deployment run with a trust boundary nobody chose, which is the
// same failure as a silent default.
func TestNewResolverBounds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		hops    int
		wantErr bool
	}{
		{name: "zero is the default and is valid", hops: 0},
		{name: "one proxy", hops: 1},
		{name: "the cap itself is permitted", hops: clientip.MaxTrustedHops},
		{name: "negative is refused", hops: -1, wantErr: true},
		{name: "one above the cap is refused", hops: clientip.MaxTrustedHops + 1, wantErr: true},
		{name: "a fat-fingered hop count is refused", hops: 100, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r, err := clientip.NewResolver(tt.hops)
			switch {
			case tt.wantErr && err == nil:
				t.Fatalf("NewResolver(%d) was accepted; it must be refused", tt.hops)
			case !tt.wantErr && err != nil:
				t.Fatalf("NewResolver(%d): %v", tt.hops, err)
			}
			if err != nil {
				// A refused resolver must still be the safe one, because a caller that
				// ignores the error gets this value.
				if r.TrustedHops() != 0 {
					t.Errorf("a refused NewResolver returned a resolver trusting %d hops",
						r.TrustedHops())
				}
				return
			}
			if r.TrustedHops() != tt.hops {
				t.Errorf("TrustedHops() = %d, want %d", r.TrustedHops(), tt.hops)
			}
		})
	}
}

// TestNoHeaderBeatsAShortOne is the property stated as a comparison rather than
// as two independent rows, because it is the one an attacker probes for: sending
// a truncated header must never produce a different — let alone a
// caller-chosen — bucket than sending none.
func TestNoHeaderBeatsAShortOne(t *testing.T) {
	t.Parallel()

	r, err := clientip.NewResolver(2)
	if err != nil {
		t.Fatalf("NewResolver(2): %v", err)
	}
	const peer = "203.0.113.9:44321"

	none := r.Scope(peer, nil)
	for _, short := range [][]string{
		{"1.1.1.1"},
		{""},
		{"   "},
		{","},
		{"garbage"},
		{"1.1.1.1", ""},
	} {
		if got := r.Scope(peer, short); got != none {
			t.Errorf("Scope with the header %q = %q, but with no header = %q; a caller "+
				"who sends a short header must not land in a different bucket",
				short, got, none)
		}
	}
}

// FuzzScopeNeverTrustsTooFar is the generalisation of the table, stated as the
// one invariant that is worth the whole package:
//
//	NOTHING TO THE LEFT OF THE TRUSTED HOPS CAN CHANGE THE ANSWER.
//
// Expressed by truncating the header to its rightmost trustedHops entries and
// demanding the same result. Everything an attacker can write lives in the part
// that was truncated away, so any influence it had shows up as a disagreement —
// without this test having to reimplement the parser and agree with it by
// construction.
func FuzzScopeNeverTrustsTooFar(f *testing.F) {
	f.Add(1, "203.0.113.9:44321", "1.1.1.1, 192.0.2.44")
	f.Add(2, "203.0.113.9:44321", "1.1.1.1, 192.0.2.44, 198.51.100.7")
	f.Add(0, "203.0.113.9:44321", "192.0.2.44")
	f.Add(1, "", "")
	f.Add(3, "[2001:db8::1]:443", "[::1]:80,,fe80::1%eth0")
	// A left entry that is a SUBSTRING of the selected one. Found by the fuzzer
	// against an earlier, weaker statement of this property, and kept because it is
	// exactly the shape a containment check gets wrong.
	f.Add(1, "0.0:00000000", "0,0.0.0.0")

	f.Fuzz(func(t *testing.T, hops int, peer, header string) {
		if hops < 0 || hops > clientip.MaxTrustedHops {
			t.Skip()
		}
		r, err := clientip.NewResolver(hops)
		if err != nil {
			t.Fatalf("NewResolver(%d): %v", hops, err)
		}
		got := r.Scope(peer, []string{header})
		if got == "" {
			t.Fatalf("Scope(%q, %q) with %d hops returned an empty scope", peer, header, hops)
		}

		fallback := r.Scope(peer, nil)
		entries := strings.Split(header, ",")

		// With no trusted hops, or fewer entries than hops, the header cannot
		// contribute at all and the peer address is the only permitted answer.
		if hops == 0 || len(entries) < hops {
			if got != fallback {
				t.Fatalf("Scope(%q, %q) = %q with %d trusted hop(s) over %d entries; "+
					"the header must not have been read at all, want %q",
					peer, header, got, hops, len(entries), fallback)
			}
			return
		}

		truncated := strings.Join(entries[len(entries)-hops:], ",")
		if want := r.Scope(peer, []string{truncated}); got != want {
			t.Fatalf("Scope(%q, %q) = %q but Scope(%q, %q) = %q; the part of the header "+
				"left of the %d trusted hop(s) — which is the part the CALLER writes — "+
				"changed the answer",
				peer, header, got, peer, truncated, want, hops)
		}
	})
}
