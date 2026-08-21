package domain

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/chronos/chronos-go/internal/platform/ids"
)

// ErrEndpointRefused is a push endpoint this system will not post to.
var ErrEndpointRefused = errors.New("notification: push endpoint refused")

// PushEndpoint is a validated, normalised push service URL.
//
// A type rather than a string, so that "checked" is carried by the value instead
// of by the reader's memory of which call site checked it. The only way to get
// one is ParsePushEndpoint.
type PushEndpoint struct {
	url  string
	host string
}

func (e PushEndpoint) String() string { return e.url }

// Host is the push service's hostname, lowercased. Useful for metrics — the
// delivery rate of one push service is an operational question — and safe to
// log, unlike the endpoint, which is a per-device credential.
func (e PushEndpoint) Host() string { return e.host }

// IsZero reports the unparsed value.
func (e PushEndpoint) IsZero() bool { return e.url == "" }

// ParsePushEndpoint validates a push service URL and normalises it.
//
// # Why this is not merely a format check
//
// The server POSTs to this URL. A caller who can choose it freely can choose one
// that names something only the server can reach — a cloud metadata service, an
// internal admin port, a database's HTTP interface — and the request goes out
// with the server's own network position behind it. That is server-side request
// forgery, and an endpoint field is exactly the shape it arrives in.
//
// protovalidate already refuses anything that is not an `https://` URI, and that
// rule is real enforcement rather than decoration. It is repeated here because
// this is the invariant's home: the schema constrains what a CLIENT may send,
// and this constrains what the system will ever hold, including values that
// arrive from a replayed event, a test, or a future caller that is not an RPC.
//
// # What is refused, and why each one
//
//   - Anything but https. A push endpoint is a bearer-ish credential in a URL;
//     plaintext would put it on the wire for anyone on the path.
//   - Credentials in the URL. `https://user:pass@host/` is a way to smuggle a
//     different authority past a naive host check, and no push service uses it.
//   - A host that is an IP literal. Every real push service is named by DNS.
//     Allowing a literal is allowing 127.0.0.1, 169.254.169.254 and every RFC
//     1918 address in one stroke, and it is the only form that cannot be
//     re-resolved to something safe later.
//   - localhost, and the .local / .internal / .localhost suffixes. The named
//     equivalents of the above.
//   - A port other than 443. A push service listens on https' own port; a
//     numbered port is how an internal service is usually reached.
//
// # What it deliberately does NOT do
//
// It does not resolve the host. A DNS lookup here would be a check against an
// answer that can change between this call and the send — the rebinding problem
// — and it would put a network round trip inside a domain function. Pinning the
// egress path is the transport's job and belongs beside the HTTP client, not
// here; this closes the shapes that need no lookup to be obviously wrong.
func ParsePushEndpoint(raw string) (PushEndpoint, error) {
	if raw == "" {
		return PushEndpoint{}, fmt.Errorf("%w: it is empty", ErrEndpointRefused)
	}
	if len(raw) > 2048 {
		return PushEndpoint{}, fmt.Errorf("%w: it is %d bytes", ErrEndpointRefused, len(raw))
	}

	u, err := url.Parse(raw)
	if err != nil {
		return PushEndpoint{}, fmt.Errorf("%w: it is not a URL", ErrEndpointRefused)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return PushEndpoint{}, fmt.Errorf("%w: %q is not https", ErrEndpointRefused, u.Scheme)
	}
	if u.User != nil {
		return PushEndpoint{}, fmt.Errorf("%w: it carries credentials in the URL", ErrEndpointRefused)
	}

	host := strings.ToLower(u.Hostname())
	if host == "" {
		return PushEndpoint{}, fmt.Errorf("%w: it names no host", ErrEndpointRefused)
	}
	if net.ParseIP(host) != nil {
		return PushEndpoint{}, fmt.Errorf(
			"%w: %q is an address rather than a push service name", ErrEndpointRefused, host)
	}
	if host == "localhost" {
		return PushEndpoint{}, fmt.Errorf("%w: %q is this machine", ErrEndpointRefused, host)
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".home.arpa"} {
		if strings.HasSuffix(host, suffix) {
			return PushEndpoint{}, fmt.Errorf(
				"%w: %q is a private name", ErrEndpointRefused, host)
		}
	}
	if port := u.Port(); port != "" && port != "443" {
		return PushEndpoint{}, fmt.Errorf(
			"%w: %q is not the https port", ErrEndpointRefused, port)
	}

	// Normalised so that two spellings of one endpoint cannot become two
	// subscriptions pushing to one device twice. Scheme and host are
	// case-insensitive and are lowered; the PATH is left exactly as given,
	// because a push service's path is an opaque, case-sensitive token and
	// "normalising" it would produce a URL that 404s.
	u.Scheme = "https"
	u.Host = host
	if p := u.Port(); p == "443" {
		u.Host = host
	}
	return PushEndpoint{url: u.String(), host: host}, nil
}

// PushSubscriptionID is the identity of one browser, in one organization.
//
// DERIVED from the organization and the endpoint rather than minted at random,
// and the derivation is the point:
//
//   - Re-registering the same browser in the same organization resolves to the
//     same subscription, so a permission prompt answered twice collapses onto
//     one row instead of pushing to that device twice per notification.
//   - Unsubscribing needs no lookup. A service worker knows its own endpoint and
//     nothing else, and computing the id from it means removal works
//     immediately, rather than failing for as long as the projection lags the
//     registration that just happened.
//   - The SAME browser in a SECOND organization gets a DIFFERENT id. That is
//     ADR-043's `(org_id, endpoint)` uniqueness expressed in the identifier
//     itself rather than only in an index — and it is why org_id is hashed
//     first: dropping it here would give two organizations one id, one primary
//     key and one row for two subscriptions that must stay separate.
//
// SHA-256 truncated to 16 bytes, rendered as a ULID body. Truncation is safe for
// what this is: an identifier, not an authenticator. Nothing is authorised by
// holding it — every statement it appears in is additionally scoped by
// organization under RLS — and 128 bits of a strong digest gives a collision
// probability that is not a real number at any subscription count this system
// will see.
//
// The separator is a NUL byte, so no organization id and endpoint pair can be
// re-spelled as another: without it, org "a" + endpoint "bc" and org "ab" +
// endpoint "c" would hash alike.
func PushSubscriptionID(orgID string, endpoint PushEndpoint) ids.PushSubscriptionID {
	sum := sha256.Sum256([]byte("chronos.push.subscription\x00" + orgID + "\x00" + endpoint.String()))
	var body [16]byte
	copy(body[:], sum[:16])
	return ids.FromUUID[ids.PushSubscription](body)
}
