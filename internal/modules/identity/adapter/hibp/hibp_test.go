package hibp_test

import (
	"context"
	"crypto/sha1" //nolint:gosec // mirrors the protocol under test
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/adapter/hibp"
)

// corpus is a fake range API that records what it was asked.
type corpus struct {
	mu       sync.Mutex
	requests []string
	headers  []http.Header

	// entries maps a prefix to the raw body returned for it.
	entries map[string]string

	status int
	delay  time.Duration
}

func (c *corpus) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.requests = append(c.requests, r.URL.Path)
		c.headers = append(c.headers, r.Header.Clone())
		c.mu.Unlock()

		if c.delay > 0 {
			// Respect the client's cancellation rather than sleeping through it,
			// so the suite does not pay the full delay on every run.
			select {
			case <-time.After(c.delay):
			case <-r.Context().Done():
				return
			}
		}
		if c.status != 0 && c.status != http.StatusOK {
			w.WriteHeader(c.status)
			return
		}
		prefix := strings.TrimPrefix(r.URL.Path, "/")
		_, _ = w.Write([]byte(c.entries[prefix]))
	})
}

func (c *corpus) asked() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.requests...)
}

// hashOf returns the uppercase SHA-1 of a password, as the protocol uses it.
func hashOf(t *testing.T, password string) (prefix, suffix string) {
	t.Helper()
	sum := sha1.Sum([]byte(password)) //nolint:gosec // mirrors the protocol under test
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	return full[:5], full[5:]
}

func newChecker(t *testing.T, c *corpus) *hibp.Checker {
	t.Helper()
	srv := httptest.NewServer(c.handler())
	t.Cleanup(srv.Close)
	return hibp.New(hibp.WithEndpoint(srv.URL + "/"))
}

// A password in the corpus is reported as breached.
func TestABreachedPasswordIsDetected(t *testing.T) {
	const password = "correct horse battery"
	prefix, suffix := hashOf(t, password)

	c := &corpus{entries: map[string]string{
		prefix: fmt.Sprintf("0000000000000000000000000000000000A:3\r\n%s:1927\r\n", suffix),
	}}
	got, source, err := newChecker(t, c).Breached(context.Background(), password)
	if err != nil {
		t.Fatalf("breached: %v", err)
	}
	if !got {
		t.Fatal("a password present in the corpus was not detected")
	}
	if source != hibp.Source {
		t.Errorf("source is %q, want %q", source, hibp.Source)
	}
}

// A password absent from the corpus is not reported.
func TestAnUnbreachedPasswordIsNotFlagged(t *testing.T) {
	const password = "correct horse battery"
	prefix, _ := hashOf(t, password)

	c := &corpus{entries: map[string]string{
		prefix: "0000000000000000000000000000000000A:3\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB:9\r\n",
	}}
	got, source, err := newChecker(t, c).Breached(context.Background(), password)
	if err != nil {
		t.Fatalf("breached: %v", err)
	}
	if got {
		t.Fatal("a password absent from the corpus was flagged as breached")
	}
	if source != "" {
		t.Errorf("a source was reported for an unbreached password: %q", source)
	}
}

// THE ONE THAT MATTERS: only five hex characters ever leave the process.
//
// The whole justification for sending anything at all is k-anonymity. If the
// full hash — or worse, the password — were sent, the service would learn the
// credential of every user who ever logged in.
func TestOnlyAFiveCharacterPrefixIsSent(t *testing.T) {
	const password = "correct horse battery"
	prefix, suffix := hashOf(t, password)

	c := &corpus{entries: map[string]string{prefix: suffix + ":5\r\n"}}
	if _, _, err := newChecker(t, c).Breached(context.Background(), password); err != nil {
		t.Fatalf("breached: %v", err)
	}

	asked := c.asked()
	if len(asked) != 1 {
		t.Fatalf("made %d requests, want 1", len(asked))
	}
	sent := strings.TrimPrefix(asked[0], "/")

	if len(sent) != 5 {
		t.Fatalf("sent %q (%d characters); the k-anonymity protocol sends exactly 5, and "+
			"anything longer narrows the set enough to identify the password", sent, len(sent))
	}
	if sent != prefix {
		t.Fatalf("sent %q, want the hash prefix %q", sent, prefix)
	}
	if strings.Contains(asked[0], suffix) {
		t.Fatal("the hash SUFFIX was sent: the service can reconstruct the full hash and " +
			"look up the password directly")
	}
	if strings.Contains(asked[0], password) || strings.Contains(asked[0], "correct") {
		t.Fatal("the PASSWORD itself appeared in the request")
	}
}

// Padding is requested, so the response size does not leak the prefix's
// popularity to a network observer.
func TestPaddingIsRequested(t *testing.T) {
	const password = "correct horse battery"
	prefix, _ := hashOf(t, password)
	c := &corpus{entries: map[string]string{prefix: ""}}

	if _, _, err := newChecker(t, c).Breached(context.Background(), password); err != nil {
		t.Fatalf("breached: %v", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if got := c.headers[0].Get("Add-Padding"); got != "true" {
		t.Errorf("Add-Padding is %q, want \"true\": without it the response length correlates "+
			"with how many real entries share the prefix", got)
	}
	// The EXACT value, not merely non-empty. Go's client sets its own default
	// User-Agent, so an assertion on non-emptiness passes even when the header is
	// never set — verified by mutation.
	if got := c.headers[0].Get("User-Agent"); got != hibp.UserAgent {
		t.Errorf("User-Agent is %q, want %q; the service rejects the generic Go default",
			got, hibp.UserAgent)
	}
}

// A PADDING ENTRY — count zero — is not a hit.
//
// The service inserts fabricated suffixes with count 0 when padding is on.
// Treating one as a match would mark a perfectly good password as breached, at
// random, for reasons no log line would explain.
func TestAPaddingEntryIsNotTreatedAsABreach(t *testing.T) {
	const password = "correct horse battery"
	prefix, suffix := hashOf(t, password)

	c := &corpus{entries: map[string]string{
		prefix: fmt.Sprintf("%s:0\r\n", suffix), // exactly our suffix, count zero
	}}
	got, _, err := newChecker(t, c).Breached(context.Background(), password)
	if err != nil {
		t.Fatalf("breached: %v", err)
	}
	if got {
		t.Fatal("a zero-count padding entry was treated as a breach: passwords are flagged " +
			"at random, and the user is told to rotate a credential that is fine")
	}
}

// An unreachable corpus FAILS OPEN, with a named error.
//
// Refusing the login would let an outage at a third party lock every user out of
// the only place they could fix the problem.
func TestAnUnreachableCorpusFailsOpen(t *testing.T) {
	checker := hibp.New(hibp.WithEndpoint("http://127.0.0.1:1/range/"))

	breached, source, err := checker.Breached(context.Background(), "correct horse battery")
	if breached {
		t.Fatal("an unreachable corpus reported the password as breached")
	}
	if source != "" {
		t.Errorf("a source was reported for a check that never ran: %q", source)
	}
	if err == nil {
		t.Fatal("an unreachable corpus was reported as a clean result: a screening step that " +
			"silently stopped screening is indistinguishable from one finding nothing")
	}
}

// A non-200 response is an error, not a clean result.
func TestAnErrorResponseIsNotACleanResult(t *testing.T) {
	for _, status := range []int{
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusServiceUnavailable,
		http.StatusForbidden,
	} {
		c := &corpus{entries: map[string]string{}, status: status}
		breached, _, err := newChecker(t, c).Breached(context.Background(), "correct horse battery")
		if breached {
			t.Errorf("status %d reported a breach", status)
		}
		if err == nil {
			t.Errorf("status %d was reported as a clean result, so an outage looks like every "+
				"password being fine", status)
		}
	}
}

// A cancelled context stops the call.
func TestACancelledContextStopsTheCall(t *testing.T) {
	c := &corpus{entries: map[string]string{}, delay: 5 * time.Second}
	checker := newChecker(t, c)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, _, err := checker.Breached(ctx, "correct horse battery")
	if err == nil {
		t.Fatal("a cancelled check returned a clean result")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("the call took %v after its context ended: the login path is held open by a "+
			"slow third party", elapsed)
	}
}

// The NORMALIZED password is screened, not the raw input.
//
// The stored verifier is of the normalized form, so that is the secret
// protecting the account. Screening the raw input would check a string the
// account does not actually accept.
func TestTheNormalizedPasswordIsScreened(t *testing.T) {
	// Composed and decomposed forms of the same password.
	composed := "café password"
	decomposed := "café password"
	if composed == decomposed {
		t.Fatal("the fixtures are byte-identical, so this test proves nothing")
	}

	prefix, suffix := hashOf(t, composed) // the normalized form's hash
	c := &corpus{entries: map[string]string{prefix: suffix + ":42\r\n"}}

	got, _, err := newChecker(t, c).Breached(context.Background(), decomposed)
	if err != nil {
		t.Fatalf("breached: %v", err)
	}
	if !got {
		t.Fatal("the raw input was screened rather than the normalized password: the corpus " +
			"is queried for a string the account would never accept, so a breached password " +
			"passes screening whenever it contains an accent")
	}
}

// A password below policy is not screened and is not an error.
//
// The caller's validation reports it. Returning an error here would make a short
// password look like a corpus outage.
func TestAPasswordBelowPolicyIsNotAnError(t *testing.T) {
	c := &corpus{entries: map[string]string{}}
	checker := newChecker(t, c)

	for _, password := range []string{"", "short", "pass\nword"} {
		breached, _, err := checker.Breached(context.Background(), password)
		if err != nil {
			t.Errorf("%q produced %v; a password below policy is the caller's validation "+
				"failure, not a corpus outage", password, err)
		}
		if breached {
			t.Errorf("%q was reported as breached", password)
		}
	}
	if n := len(c.asked()); n != 0 {
		t.Errorf("%d requests were made for passwords that can never be accepted", n)
	}
}

// Malformed corpus lines are skipped rather than crashing the check.
func TestMalformedCorpusLinesAreSkipped(t *testing.T) {
	const password = "correct horse battery"
	prefix, suffix := hashOf(t, password)

	c := &corpus{entries: map[string]string{
		prefix: "garbage-with-no-colon\r\n\r\n:::\r\n" + suffix + ":7\r\n",
	}}
	got, _, err := newChecker(t, c).Breached(context.Background(), password)
	if err != nil {
		t.Fatalf("breached: %v", err)
	}
	if !got {
		t.Fatal("a real entry after malformed lines was missed")
	}
}

// The suffix comparison is case-insensitive.
//
// The service returns uppercase, and a mirror or a cached copy may not.
func TestTheSuffixComparisonIgnoresCase(t *testing.T) {
	const password = "correct horse battery"
	prefix, suffix := hashOf(t, password)

	c := &corpus{entries: map[string]string{prefix: strings.ToLower(suffix) + ":11\r\n"}}
	got, _, err := newChecker(t, c).Breached(context.Background(), password)
	if err != nil {
		t.Fatalf("breached: %v", err)
	}
	if !got {
		t.Fatal("a lowercase suffix was not matched: a mirror that normalizes case differently " +
			"silently screens nothing")
	}
}

// An empty corpus response is a clean result, not an error.
func TestAnEmptyResponseIsAClean_Result(t *testing.T) {
	const password = "correct horse battery"
	prefix, _ := hashOf(t, password)
	c := &corpus{entries: map[string]string{prefix: ""}}

	breached, _, err := newChecker(t, c).Breached(context.Background(), password)
	if err != nil {
		t.Fatalf("an empty response produced %v", err)
	}
	if breached {
		t.Fatal("an empty response was reported as a breach")
	}
}
