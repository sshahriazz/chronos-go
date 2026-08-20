// Package clientip answers one question: which network identity does a
// per-caller ceiling count against?
//
// It is deliberately NOT specific to any one ceiling. The verification-mail
// caller rule needs it today and any future per-source rule needs the same
// answer, and a second implementation of this logic is a second chance to get
// it wrong in the direction that matters.
//
// # The whole problem in one paragraph
//
// The connection's peer address is the only thing about a caller the server
// knows first-hand. Behind a proxy that terminates connections it is the
// PROXY's address, so every caller collapses into one bucket and a per-caller
// rule silently becomes a global one. The fix is to read the client address out
// of `X-Forwarded-For` — but that header is written by whoever is calling, so
// reading it without a configured trust boundary is strictly worse than not
// reading it at all: an attacker mints a fresh bucket per request to evade the
// ceiling, or borrows a victim's address to burn their budget.
//
// # The design, and the two properties that carry it
//
// A Resolver holds a COUNT of proxies that append to X-Forwarded-For.
//
//  1. The zero value trusts nothing. A Resolver nobody configured — a forgotten
//     wiring, a field left off a struct literal, a deployment with no
//     environment variable — returns the peer address, which is today's
//     behaviour and the conservative one. Same discipline as authz.Decision:
//     the property is carried by the type rather than by remembering to set it.
//
//  2. Entries are counted from the RIGHT. Every entry to the left of our own
//     infrastructure's appended ones is caller-supplied, so the leftmost entry —
//     the one the classic implementation takes — is precisely the value an
//     attacker chooses. Nothing an attacker writes can change the position of an
//     entry counted from the right, however much junk, however many commas and
//     however many empty fields they send.
//
// Everything that cannot be resolved falls back to the peer address. That is not
// an error path bolted on: a caller who sends a short, absent or malformed
// header must never get a BETTER outcome than one who sends nothing.
package clientip

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// ForwardedForHeader is the header a trusted proxy appends to. Exported so the
// transport layer that reads it and this package that parses it cannot drift
// apart on spelling.
const ForwardedForHeader = "X-Forwarded-For"

// Unattributed is the scope for a caller with no usable address at all — an
// in-process transport, a test, a bufconn.
//
// A non-empty constant rather than an empty string: ratelimit.Limiter refuses an
// empty scope outright, so returning one would turn a transport quirk into a
// 500 on every request that path serves. Everything unattributable shares ONE
// bucket, which is the conservative direction.
const Unattributed = "unattributed"

// MaxTrustedHops caps how many proxies a Resolver will trust.
//
// The number is a bound on damage rather than on architecture: each hop hands
// one more entry of the header over to whoever is calling, and a deployment that
// genuinely chains nine appending proxies has a bigger problem than this
// setting. A fat-fingered 100 would otherwise mean "take the leftmost thing the
// attacker wrote", which is the exact bug this package exists to prevent.
const MaxTrustedHops = 8

// IPv6ScopePrefixBits is the prefix an IPv6 address is reduced to before it
// becomes a bucket.
//
// # Why an IPv6 address is not used whole
//
// A rate limit is only a limit if buckets are scarce. IPv4 makes them scarce by
// accident — an attacker needs to acquire each address. IPv6 does not: the
// SMALLEST allocation anybody receives is a /64, which is 18 quintillion
// addresses, all of which one host can source from at will. Keyed on the full
// address, a 20-per-hour ceiling is 20 per hour per address and therefore no
// ceiling at all, defeated at zero cost by anyone with an ordinary VPS.
//
// /64 is the coarsest unit an attacker cannot subdivide without obtaining more
// address space, and it is the unit ISPs hand to one subscriber — so the cost is
// that one household, or one datacentre tenant's subnet, shares one bucket.
// Against limits in the tens per hour that is the intended reading of "one
// caller" anyway.
//
// The residual is stated rather than papered over: an attacker holding a /48 or
// a /32 still has 65,536 or 4 billion buckets. Reducing further would put
// unrelated subscribers of one ISP in one bucket, which trades an attacker's
// inconvenience for real users' refusals. /64 is where that trade stops paying.
const IPv6ScopePrefixBits = 64

// Resolver turns a connection and its headers into a rate-limit scope.
//
// The zero value is usable and trusts NOTHING: it ignores X-Forwarded-For
// entirely and answers with the peer address.
type Resolver struct {
	// trustedHops is unexported so the zero value is the only value that can be
	// obtained without passing through NewResolver's bounds check — and the zero
	// value is the safe one.
	trustedHops int
}

// NewResolver builds a resolver that trusts trustedHops proxies.
//
// # The deployment contract
//
// trustedHops is the number of proxies IN FRONT of this server that APPEND to
// X-Forwarded-For — and no more. It is not "how many network devices are in the
// path", and it is not a safety margin.
//
//   - Set too LOW (or zero, the default): the peer address is used. Every caller
//     behind the proxy shares one bucket. The ceiling becomes global — annoying,
//     never exploitable.
//   - Set too HIGH: the selected entry moves left, into the part of the header
//     the CALLER wrote. Spoofing is fully re-enabled, and the ceiling can be both
//     evaded and aimed at a victim.
//
// The two failure directions are not symmetric, which is why the default is zero
// and why this is the number an operator has to justify.
func NewResolver(trustedHops int) (Resolver, error) {
	switch {
	case trustedHops < 0:
		return Resolver{}, fmt.Errorf(
			"clientip: trusted proxy hops is %d; it cannot be negative (0 means "+
				"trust nothing and use the connection's peer address)", trustedHops)
	case trustedHops > MaxTrustedHops:
		return Resolver{}, fmt.Errorf(
			"clientip: trusted proxy hops is %d, above the cap of %d; each hop hands one "+
				"more X-Forwarded-For entry to whoever is calling, and a count above the "+
				"number of proxies that actually append makes the client address spoofable",
			trustedHops, MaxTrustedHops)
	}
	return Resolver{trustedHops: trustedHops}, nil
}

// TrustedHops reports the configured count, for the startup log line and for the
// composition-root test that asserts a policy was actually wired.
func (r Resolver) TrustedHops() int { return r.trustedHops }

// Scope names the caller a per-source ceiling counts against.
//
// peer is the connection's peer address, with or without a port. forwarded is
// every X-Forwarded-For field line IN ARRIVAL ORDER — http.Header.Values gives
// exactly that, and several field lines mean the same as one comma-joined line,
// so they are concatenated rather than picked between.
//
// The result is never empty.
func (r Resolver) Scope(peer string, forwarded []string) string {
	fallback := peerScope(peer)

	// Zero hops does not merely fail to find a client address — it never looks.
	// An unconfigured deployment must not read the header at all.
	if r.trustedHops == 0 {
		return fallback
	}

	entries := forwardedEntries(forwarded)

	// With N appending proxies the client is the Nth entry from the right: the
	// nearest proxy appends the address IT saw, which is the client's when N is 1
	// and the previous proxy's otherwise.
	//
	// Fewer entries than hops means the header cannot contain what the
	// configuration promises — a caller who stripped it, or a hop count set above
	// the real topology. Either way the peer address is the answer, because the
	// alternative is to reach further left into what the caller wrote.
	if len(entries) < r.trustedHops {
		return fallback
	}
	addr, ok := parseHop(entries[len(entries)-r.trustedHops])
	if !ok {
		// Fails CLOSED to the peer address. A malformed entry is either broken
		// infrastructure or a deliberate probe, and neither may be permitted to
		// choose its own bucket by writing something unparseable.
		return fallback
	}
	return normalize(addr)
}

// peerScope reduces the connection's peer address to a bucket.
//
// An address that parses is normalized; one that does not — a unix socket path,
// an in-process transport's label — is passed through verbatim rather than
// discarded. It is still first-hand information about the connection, and it is
// still unforgeable, which is the only property that matters here.
func peerScope(peer string) string {
	peer = strings.TrimSpace(peer)
	if peer == "" {
		return Unattributed
	}
	// The port is stripped so every connection from one host shares a bucket.
	// Keyed with the ephemeral port, each new TCP connection would get a fresh
	// budget and the ceiling would be free to defeat.
	if host, _, err := net.SplitHostPort(peer); err == nil && host != "" {
		if addr, ok := parseAddr(host); ok {
			return normalize(addr)
		}
		return host
	}
	if addr, ok := parseAddr(peer); ok {
		return normalize(addr)
	}
	return peer
}

// forwardedEntries splits every field line into its comma-separated entries,
// preserving ORDER and preserving EMPTY entries.
//
// Empties are kept deliberately. Counting is positional and counted from the
// right, and dropping entries is a rewrite of the list an attacker partly
// controls — cheap to reason about only until somebody sends the trailing comma
// that makes dropping and keeping disagree. An empty entry that ends up selected
// fails to parse and falls back to the peer address, which is the correct
// outcome anyway.
func forwardedEntries(forwarded []string) []string {
	var entries []string
	for _, line := range forwarded {
		if line == "" {
			continue
		}
		for entry := range strings.SplitSeq(line, ",") {
			entries = append(entries, strings.TrimSpace(entry))
		}
	}
	return entries
}

// parseHop parses ONE X-Forwarded-For entry.
//
// The header is specified as bare addresses, and real infrastructure emits at
// least three other shapes: `1.2.3.4:5678` from a proxy that logged the source
// port, `[2001:db8::1]:5678`, and bare `[2001:db8::1]`. All are accepted; the
// port is discarded. Anything that is not an IP address after that is rejected,
// which is what stops a hostname, a header injection or a `for=` fragment from
// becoming a bucket key.
func parseHop(entry string) (netip.Addr, bool) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return netip.Addr{}, false
	}
	if addr, ok := parseAddr(entry); ok {
		return addr, true
	}
	if ap, err := netip.ParseAddrPort(entry); err == nil {
		return canonical(ap.Addr()), true
	}
	if strings.HasPrefix(entry, "[") && strings.HasSuffix(entry, "]") {
		return parseAddr(entry[1 : len(entry)-1])
	}
	return netip.Addr{}, false
}

// parseAddr is netip.ParseAddr plus canonicalization.
func parseAddr(s string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return canonical(addr), true
}

// canonical removes the two ways one host can present as two buckets.
//
// Unmap folds `::ffff:1.2.3.4` onto `1.2.3.4`; a dual-stack listener produces
// the mapped form for an IPv4 client on some platforms, and two spellings of one
// address is two budgets. WithZone("") drops a scope identifier, which is
// meaningful only on the local link and is attacker-suffixable in a header.
func canonical(addr netip.Addr) netip.Addr {
	return addr.Unmap().WithZone("")
}

// normalize renders an address as a bucket key: IPv4 whole, IPv6 reduced to its
// /64 (see IPv6ScopePrefixBits).
func normalize(addr netip.Addr) string {
	if !addr.IsValid() {
		return Unattributed
	}
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(IPv6ScopePrefixBits)
	if err != nil {
		// Unreachable for a valid 16-byte address: 64 is in range. Falling back to
		// the full address keeps a bucket rather than inventing a shared one.
		return addr.String()
	}
	return prefix.String()
}
