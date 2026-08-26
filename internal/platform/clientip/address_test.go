package clientip_test

import (
	"net/netip"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/clientip"
)

// TestAddressReturnsAnAddressWhereScopeReturnsABucket is the regression test
// for a shipped bug.
//
// Scope returns a rate-limit BUCKET KEY, and for IPv6 that key is a /64 PREFIX
// — two addresses on one link deliberately share a budget. The operator plane's
// network restriction was written against Scope and parsed its answer as an
// address, which worked over IPv4 and failed over IPv6: every loopback request
// was refused with "this request's origin could not be established" while the
// configuration was correct.
//
// The assertion that matters is that Address's answer PARSES and that Scope's
// does not have to.
func TestAddressReturnsAnAddressWhereScopeReturnsABucket(t *testing.T) {
	r, err := clientip.NewResolver(0)
	if err != nil {
		t.Fatalf("building the resolver: %v", err)
	}

	cases := []struct {
		name string
		peer string
		want netip.Addr
	}{
		{"ipv4 with a port", "127.0.0.1:54321", netip.MustParseAddr("127.0.0.1")},
		{"ipv4 bare", "10.1.2.3", netip.MustParseAddr("10.1.2.3")},
		{"ipv6 loopback with a port", "[::1]:54321", netip.MustParseAddr("::1")},
		{"ipv6 bare", "2001:db8::1", netip.MustParseAddr("2001:db8::1")},
		// An IPv4-mapped IPv6 address must come back as the IPv4 it is, or a
		// permitted set written as 127.0.0.0/8 would not contain it.
		{"ipv4-mapped", "[::ffff:127.0.0.1]:80", netip.MustParseAddr("127.0.0.1")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := r.Address(tc.peer, nil)
			if !ok {
				t.Fatalf("Address(%q) could not resolve an origin", tc.peer)
			}
			if got != tc.want {
				t.Errorf("Address(%q) = %v, want %v", tc.peer, got, tc.want)
			}
		})
	}
}

// TestLoopbackIsContainedByTheObviousPrefixes is the property the operator
// plane's restriction actually depends on.
//
// A test that only checked the returned address would pass on a value that
// `Prefix.Contains` then rejects — which is one Unmap() away, and is exactly
// what the mapped-address case above exists for.
func TestLoopbackIsContainedByTheObviousPrefixes(t *testing.T) {
	r, err := clientip.NewResolver(0)
	if err != nil {
		t.Fatalf("building the resolver: %v", err)
	}

	v4 := netip.MustParsePrefix("127.0.0.0/8")
	v6 := netip.MustParsePrefix("::1/128")

	for _, peer := range []string{"127.0.0.1:1", "[::1]:1", "[::ffff:127.0.0.1]:1"} {
		addr, ok := r.Address(peer, nil)
		if !ok {
			t.Fatalf("Address(%q) could not resolve an origin", peer)
		}
		if !v4.Contains(addr) && !v6.Contains(addr) {
			t.Errorf("Address(%q) = %v, which neither 127.0.0.0/8 nor ::1/128 contains — "+
				"an operator plane restricted to loopback would refuse its own console", peer, addr)
		}
	}
}

// TestAddressReportsFalseForWhatIsNotAnIP is the fail-closed half.
//
// A unix socket path or an in-process transport's label is not an address, and
// a caller making an ACCESS decision must be told so rather than handed a zero
// value that silently fails every Contains check for a different reason.
func TestAddressReportsFalseForWhatIsNotAnIP(t *testing.T) {
	r, err := clientip.NewResolver(0)
	if err != nil {
		t.Fatalf("building the resolver: %v", err)
	}

	for _, peer := range []string{"", "  ", "/var/run/chronos.sock", "pipe", "bufconn"} {
		if _, ok := r.Address(peer, nil); ok {
			t.Errorf("Address(%q) claimed to resolve an origin", peer)
		}
	}
}

// TestAddressAndScopeAgreeOnWhichHop is the property that makes the two methods
// safe to have side by side.
//
// If "which hop we count against" and "which hop we allow" could disagree, a
// caller could be rate-limited as one address and admitted as another. Both go
// through the same policy, so the address Scope bucketed is the address Address
// returns.
func TestAddressAndScopeAgreeOnWhichHop(t *testing.T) {
	r, err := clientip.NewResolver(1)
	if err != nil {
		t.Fatalf("building the resolver: %v", err)
	}

	forwarded := []string{"203.0.113.9, 198.51.100.4"}
	addr, ok := r.Address("10.0.0.1:1234", forwarded)
	if !ok {
		t.Fatal("could not resolve an origin")
	}
	// One trusted hop: the client is the LAST entry, appended by the nearest
	// proxy.
	if want := netip.MustParseAddr("198.51.100.4"); addr != want {
		t.Fatalf("Address chose %v, want %v", addr, want)
	}
	if got := r.Scope("10.0.0.1:1234", forwarded); got != "198.51.100.4" {
		t.Fatalf("Scope chose %q while Address chose %v", got, addr)
	}
}
