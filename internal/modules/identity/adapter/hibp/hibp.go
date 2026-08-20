// Package hibp screens passwords against the Have I Been Pwned corpus.
//
// # The password never leaves this process
//
// The k-anonymity protocol is the whole reason this is acceptable at all. We
// compute SHA-1 of the password, send the FIRST FIVE HEX CHARACTERS, and get
// back every suffix in the corpus sharing that prefix — several hundred to a few
// thousand lines. The match is decided here.
//
// So the service learns that somebody, somewhere, checked a password whose hash
// starts with those 20 bits. It cannot learn which password, and it cannot learn
// which of the returned suffixes was the answer, because it does not know
// whether any of them was.
//
// SHA-1 is fixed by the protocol, not chosen. It is not being used as a password
// hash here — the stored verifier is Argon2id — it is a lookup key into a public
// corpus, and its collision weaknesses do not apply to that use.
//
// # Why this fails open
//
// A breached password is a REASON TO ROTATE, not a reason to lock somebody out.
// Refusing the login would mean an outage at a third party locks every user out
// of the only place they could fix the problem, using information they cannot
// act on from a login screen (identity.md §4, IDENTITY-REVIEW A4).
//
// So an unreachable corpus returns (false, "", err) and the caller ALLOWS the
// login while recording that the check did not run. The signal is named rather
// than swallowed — a screening step that silently stopped screening is
// indistinguishable from one that keeps finding nothing.
package hibp

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // the k-anonymity protocol specifies SHA-1; it is a lookup key, not a password hash
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
)

// Source is the corpus name recorded in CredentialCompromiseDetected, so a false
// positive can be traced without re-querying.
const Source = "haveibeenpwned"

// DefaultEndpoint is the range API. The prefix is appended to it.
const DefaultEndpoint = "https://api.pwnedpasswords.com/range/"

// UserAgent identifies this client to the service, which rejects generic ones.
const UserAgent = "chronos-identity"

// DefaultTimeout bounds the call.
//
// Short, because this sits on the login path in front of a 51 ms hash and the
// answer is advisory. A slow corpus must degrade the login's latency, not
// dominate it — and the fail-open path means a timeout costs nothing but a
// missing signal.
const DefaultTimeout = 2 * time.Second

// prefixLen is fixed by the protocol: five hex characters, 20 bits.
const prefixLen = 5

// Checker implements app.BreachChecker.
type Checker struct {
	endpoint string
	client   *http.Client
}

var _ app.BreachChecker = (*Checker)(nil)

// Option configures a Checker.
type Option func(*Checker)

// WithEndpoint points the checker at a different range API. For tests and for
// an on-premise mirror.
func WithEndpoint(url string) Option {
	return func(c *Checker) { c.endpoint = url }
}

// WithHTTPClient replaces the client, including its timeout.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Checker) { c.client = client }
}

// New builds the checker.
func New(opts ...Option) *Checker {
	c := &Checker{
		endpoint: DefaultEndpoint,
		client:   &http.Client{Timeout: DefaultTimeout},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Breached reports whether the password appears in the corpus.
//
// Returns (false, "", err) when the check could not be performed. The caller
// must treat that as "unknown" and allow the login — see the package comment.
func (c *Checker) Breached(ctx context.Context, password string) (bool, string, error) {
	// Normalized first, and it matters: the stored verifier is of the NORMALIZED
	// password, so that is the secret protecting the account. Screening the raw
	// input would check a string the account does not actually accept.
	normalized, err := domain.NormalizePassword(password)
	if err != nil {
		// Below policy, so it will never be accepted anyway. Not an error — the
		// caller's validation reports that, and returning an error here would
		// make a short password look like a corpus outage.
		return false, "", nil
	}

	sum := sha1.Sum([]byte(normalized)) //nolint:gosec // protocol-mandated, see the package comment
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix, suffix := full[:prefixLen], full[prefixLen:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+prefix, nil)
	if err != nil {
		return false, "", fmt.Errorf("hibp: building the request: %w", err)
	}
	// Padding asks the service to return a random number of fake entries, so the
	// RESPONSE SIZE stops correlating with how many real suffixes share the
	// prefix. Without it a network observer learns something about the prefix
	// from the length alone, which erodes the k-anonymity the protocol exists to
	// provide.
	req.Header.Set("Add-Padding", "true")
	// The service requires a DESCRIPTIVE agent and rejects requests without one.
	// Go sets its own default ("Go-http-client/..."), so omitting this does not
	// produce an empty header — it produces a generic one the service refuses,
	// which is why the test asserts the exact value rather than merely non-empty.
	req.Header.Set("User-Agent", UserAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("hibp: querying the corpus: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("hibp: the corpus returned %s", resp.Status)
	}

	count, err := findSuffix(resp.Body, suffix)
	if err != nil {
		return false, "", fmt.Errorf("hibp: reading the response: %w", err)
	}
	if count <= 0 {
		return false, "", nil
	}
	return true, Source, nil
}

// findSuffix scans the response for our suffix and returns its occurrence count.
//
// Each line is "SUFFIX:COUNT". A count of ZERO is a PADDING ENTRY — the service
// inserts fabricated suffixes with count 0 when Add-Padding is set, and treating
// one as a hit would mark a perfectly good password as breached, at random,
// for reasons no log line would explain.
func findSuffix(body interface{ Read([]byte) (int, error) }, suffix string) (int, error) {
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := scanner.Text()
		before, after, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(before), suffix) {
			continue
		}
		var count int
		if _, err := fmt.Sscanf(strings.TrimSpace(after), "%d", &count); err != nil {
			// A malformed count on a line that DID match. Reported as a hit with
			// an unknown count rather than as no match or as an error: the suffix
			// is present, which is the finding, and the count only distinguishes
			// a real entry from a zero-count padding one. Failing the whole check
			// here would let one unparseable line in a thousand turn a positive
			// result into an outage.
			//nolint:nilerr // a matched suffix is a hit regardless of its count
			return 1, nil
		}
		return count, nil
	}
	return 0, scanner.Err()
}
