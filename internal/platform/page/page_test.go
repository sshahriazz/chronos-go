package page_test

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/page"
)

func itoa(i int) string { return strconv.Itoa(i) }

func decodeBase64(s string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	return string(raw), err
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }

const q = page.QueryID("notification_feed:unread:desc")

func keyset(t *testing.T, keys ...page.Key) page.Keyset {
	t.Helper()
	k, err := page.NewKeyset(keys...)
	if err != nil {
		t.Fatalf("NewKeyset: %v", err)
	}
	return k
}

func cursor(t *testing.T, created time.Time, id string) page.Keyset {
	t.Helper()
	return keyset(t,
		page.Key{Column: "created_at", Value: created},
		page.Key{Column: "id", Value: id, Unique: true},
	)
}

// The sort key must end in a unique column.
//
// Without a tiebreaker the failure has no symptom at the boundary: rows sharing
// the last sort value straddle the page break, so a client walking the list
// skips some and sees others twice, and every request returns 200.
func TestASortKeyMustEndInAUniqueColumn(t *testing.T) {
	_, err := page.NewKeyset(
		page.Key{Column: "created_at", Value: time.Now()},
		page.Key{Column: "title", Value: "hello"},
	)
	if err == nil {
		t.Fatal("a keyset ending in a non-unique column was accepted: rows sharing that " +
			"value are skipped or repeated at every page boundary")
	}
	if !errors.Is(err, page.ErrInvalid) {
		t.Errorf("not reported as invalid: %v", err)
	}
}

// A token belongs to ONE query. Replayed against a different filter or sort it
// names a position in a list that no longer exists.
func TestATokenIsRefusedByADifferentQuery(t *testing.T) {
	tok, err := page.Encode(cursor(t, time.Now(), "ntf_1"), q)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := page.Decode(tok, "notification_feed:all:desc"); err == nil {
		t.Fatal("a cursor from a different filter was accepted: the rows returned would be " +
			"from a position in a list that does not exist")
	}
	// And the same query still works, so the check is discriminating rather than
	// refusing everything.
	if _, err := page.Decode(tok, q); err != nil {
		t.Fatalf("the token was refused by its own query: %v", err)
	}
}

// An unreadable token is an ERROR, never "start from the beginning".
//
// Decoding garbage to an empty cursor hands the client page one again, and a
// client following next_page_token loops forever with nothing in the loop
// looking like a failure.
func TestAnUnreadableTokenIsAnError(t *testing.T) {
	for name, tok := range map[string]page.Token{
		"not base64":     "!!!!not-base64!!!!",
		"not json":       page.Token("YWJjZGVm"), // "abcdef"
		"empty":          "",
		"truncated json": page.Token("eyJ2IjoxLCJx"),
	} {
		if _, err := page.Decode(tok, q); err == nil {
			t.Errorf("%s decoded successfully; a client would be handed page one forever", name)
		}
	}
}

// A token from a future or past encoding is rejected cleanly rather than
// misparsed. A client can recover by restarting the list; it cannot recover from
// rows taken from the wrong position.
//
// The version is bumped on a REAL token, so everything else about it — the
// fingerprint above all — stays valid. A hand-written forgery fails on the
// fingerprint first and never reaches the version check, which makes the test
// pass while testing nothing.
func TestATokenFromAnotherVersionIsRejected(t *testing.T) {
	real, err := page.Encode(cursor(t, time.Now(), "ntf_1"), q)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(string(real))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Into a map, so the forgery below can change one member and leave every
	// other byte the token already carried alone.
	wire, err := codec.Unmarshal[map[string]any](raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	wire["v"] = 99
	bumped, err := codec.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	forged := page.Token(base64.RawURLEncoding.EncodeToString(bumped))

	// Proves the forgery differs ONLY in the version: restore it and the token
	// must decode.
	if _, err := page.Decode(forged, q); err == nil {
		t.Fatal("a token from another encoding version was accepted; it will be misparsed " +
			"rather than rejected, and the client gets rows from the wrong position")
	}
	wire["v"] = 1
	restored, err := codec.Marshal(wire)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := page.Decode(page.Token(base64.RawURLEncoding.EncodeToString(restored)), q); err != nil {
		t.Fatalf("the re-encoded token was refused for some reason other than its version, "+
			"so the test above proves nothing: %v", err)
	}
}

// Values come back as the type they went in as.
//
// Returning everything as a string is the easy version and a silent bug: a
// timestamp bound as text compares lexically in Postgres, and "9" > "10".
func TestValuesRoundTripWithTheirTypes(t *testing.T) {
	when := time.Date(2026, 8, 10, 12, 34, 56, 123456789, time.UTC)
	in := keyset(t,
		page.Key{Column: "created_at", Value: when},
		page.Key{Column: "score", Value: 3.5},
		page.Key{Column: "unread", Value: true},
		page.Key{Column: "seq", Value: int64(42)},
		page.Key{Column: "id", Value: "ntf_1", Unique: true},
	)
	tok, err := page.Encode(in, q)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	out, err := page.Decode(tok, q)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	args := out.Args()
	if len(args) != 5 {
		t.Fatalf("got %d cursor values, want 5", len(args))
	}
	ts, ok := args[0].(time.Time)
	if !ok {
		t.Fatalf("created_at came back as %T, not time.Time: bound as text it would compare "+
			"lexically", args[0])
	}
	if !ts.Equal(when) {
		t.Errorf("created_at round tripped as %v, want %v — sub-second precision decides which "+
			"side of the boundary a row falls on", ts, when)
	}
	if _, ok := args[1].(float64); !ok {
		t.Errorf("score came back as %T", args[1])
	}
	if _, ok := args[2].(bool); !ok {
		t.Errorf("unread came back as %T", args[2])
	}
	if n, ok := args[3].(int64); !ok || n != 42 {
		t.Errorf("seq came back as %T (%v)", args[3], args[3])
	}
	if s, ok := args[4].(string); !ok || s != "ntf_1" {
		t.Errorf("id came back as %T (%v)", args[4], args[4])
	}
}

// Column names survive, so a decoded cursor can be checked against the query
// about to bind it.
func TestColumnsSurviveTheRoundTrip(t *testing.T) {
	tok, err := page.Encode(cursor(t, time.Now(), "ntf_1"), q)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	out, err := page.Decode(tok, q)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	got := out.Columns()
	if len(got) != 2 || got[0] != "created_at" || got[1] != "id" {
		t.Fatalf("columns round tripped as %v, want [created_at id]", got)
	}
}

// A NULL cursor value is refused.
//
// `x > NULL` is NULL, which is not true, so the next page comes back empty and
// the list appears to end early. A nullable sort column needs COALESCE in the
// query, not a NULL in the cursor.
func TestANullCursorValueIsRefused(t *testing.T) {
	_, err := page.NewKeyset(
		page.Key{Column: "archived_at", Value: nil},
		page.Key{Column: "id", Value: "ntf_1", Unique: true},
	)
	if err == nil {
		t.Fatal("a NULL cursor value was accepted: the next page would silently be empty")
	}
}

// The same column twice makes the comparison ambiguous.
func TestADuplicateSortColumnIsRefused(t *testing.T) {
	_, err := page.NewKeyset(
		page.Key{Column: "created_at", Value: time.Now()},
		page.Key{Column: "created_at", Value: time.Now()},
		page.Key{Column: "id", Value: "x", Unique: true},
	)
	if err == nil {
		t.Fatal("the same sort column was accepted twice")
	}
}

// Page size: unspecified takes the default, oversized is capped, negative is a
// caller bug.
func TestPageSizeIsClamped(t *testing.T) {
	if got, err := page.Clamp(0); err != nil || got != page.DefaultSize {
		t.Errorf("Clamp(0) = %d, %v; want %d", got, err, page.DefaultSize)
	}
	if got, err := page.Clamp(10_000); err != nil || got != page.MaxSize {
		t.Errorf("Clamp(10000) = %d, %v; want %d — one unbounded list is how a single "+
			"tenant's query becomes everybody's outage", got, err, page.MaxSize)
	}
	if got, err := page.Clamp(25); err != nil || got != 25 {
		t.Errorf("Clamp(25) = %d, %v; want 25", got, err)
	}
	if _, err := page.Clamp(-1); err == nil {
		t.Error("a negative page size was accepted")
	}
}

// Limit asks for one more row than the page size — that extra row is how "is
// there a next page?" is answered without a COUNT(*).
func TestLimitAsksForOneExtraRow(t *testing.T) {
	s, err := page.Clamp(10)
	if err != nil {
		t.Fatalf("Clamp: %v", err)
	}
	if s.Limit() != 11 {
		t.Fatalf("Limit() = %d, want 11: without the extra row, whether another page exists "+
			"needs a second query", s.Limit())
	}
}

type row struct {
	at time.Time
	id string
}

func rows(n int) []row {
	base := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	out := make([]row, n)
	for i := range out {
		out[i] = row{at: base.Add(time.Duration(i) * time.Minute), id: "ntf_" + itoa(i)}
	}
	return out
}

func rowKey(r row) page.Keyset {
	k, _ := page.NewKeyset(
		page.Key{Column: "created_at", Value: r.at},
		page.Key{Column: "id", Value: r.id, Unique: true},
	)
	return k
}

// A full page plus the peeked row returns exactly the page, and a token.
//
// The peeked row must NOT be returned: it belongs to the next page, and handing
// it over here means the client sees it twice.
func TestTheExtraRowIsNotReturned(t *testing.T) {
	p, err := page.Of(rows(11), 10, q, rowKey)
	if err != nil {
		t.Fatalf("Of: %v", err)
	}
	if len(p.Items) != 10 {
		t.Fatalf("returned %d rows for a page size of 10: the peeked row was handed to the "+
			"client and will appear again on the next page", len(p.Items))
	}
	if p.Next == "" {
		t.Fatal("no next token although another row exists: the client stops early and never " +
			"sees the rest of the list")
	}
}

// The cursor names the LAST RETURNED row, not the peeked one.
//
// Keying the peeked row resumes one row past the boundary, so exactly one row is
// skipped at every page break — the kind of loss that is only visible by
// counting.
func TestTheCursorNamesTheLastReturnedRow(t *testing.T) {
	all := rows(11)
	p, err := page.Of(all, 10, q, rowKey)
	if err != nil {
		t.Fatalf("Of: %v", err)
	}
	got, err := page.Decode(p.Next, q)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	args := got.Args()
	if id, _ := args[1].(string); id != all[9].id {
		t.Fatalf("the cursor names %q; want %q (the last RETURNED row). Naming %q would skip "+
			"a row at every page boundary", id, all[9].id, all[10].id)
	}
}

// The last page carries no token. Empty means DONE, and a client stops on it.
func TestTheLastPageHasNoToken(t *testing.T) {
	p, err := page.Of(rows(4), 10, q, rowKey)
	if err != nil {
		t.Fatalf("Of: %v", err)
	}
	if len(p.Items) != 4 {
		t.Fatalf("returned %d rows, want 4", len(p.Items))
	}
	if p.Next != "" {
		t.Fatal("a next token was issued although the list is exhausted: the client makes a " +
			"round trip for an empty page")
	}
}

// An exactly-full page with nothing after it carries no token either.
func TestAnExactlyFullFinalPageHasNoToken(t *testing.T) {
	p, err := page.Of(rows(10), 10, q, rowKey)
	if err != nil {
		t.Fatalf("Of: %v", err)
	}
	if p.Next != "" {
		t.Fatal("a token was issued for a page with nothing after it")
	}
}

// An empty result carries no token.
func TestAnEmptyResultHasNoToken(t *testing.T) {
	p, err := page.Of([]row{}, 10, q, rowKey)
	if err != nil {
		t.Fatalf("Of: %v", err)
	}
	if len(p.Items) != 0 || p.Next != "" {
		t.Fatalf("empty result produced %d rows and token %q", len(p.Items), p.Next)
	}
}

// The first page is an empty token, and it must not be confused with an
// unreadable one.
func TestResumeTreatsAnEmptyTokenAsTheFirstPage(t *testing.T) {
	k, err := page.Resume("", q)
	if err != nil {
		t.Fatalf("Resume(\"\"): %v", err)
	}
	if !k.IsStart() {
		t.Fatal("an absent page token did not mean the first page")
	}
	if _, err := page.Resume("garbage!!", q); err == nil {
		t.Fatal("an unreadable token was treated as the first page")
	}
}

// Encoding a first-page cursor is refused: such a token decodes to "start", and
// a client following it loops on page one.
func TestTheFirstPageCannotBeEncoded(t *testing.T) {
	if _, err := page.Encode(page.Start(), q); err == nil {
		t.Fatal("a token was encoded for the first page")
	}
}

// A token must name its query at both ends. Without it the binding is optional,
// and an optional check is one a caller forgets.
func TestAQueryIDIsRequired(t *testing.T) {
	if _, err := page.Encode(cursor(t, time.Now(), "ntf_1"), ""); err == nil {
		t.Error("a token was encoded with no query id")
	}
	tok, err := page.Encode(cursor(t, time.Now(), "ntf_1"), q)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := page.Decode(tok, ""); err == nil {
		t.Error("a token was decoded with no query id")
	}
}

// A token carries no filter values in the clear.
//
// It ends up in access logs, browser history and referrer headers, and a filter
// value can be personal data (ADR-002).
func TestATokenDoesNotCarryTheQueryInTheClear(t *testing.T) {
	secret := page.QueryID("member_search:email=alice@example.com")
	tok, err := page.Encode(cursor(t, time.Now(), "ntf_1"), secret)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	raw, err := decodeBase64(string(tok))
	if err != nil {
		t.Fatalf("the token is not base64: %v", err)
	}
	if contains(raw, "alice@example.com") {
		t.Fatal("the page token carries the query's filter value in the clear; it will be " +
			"written to access logs and browser history")
	}
}

// A value type with no stable encoding is refused at construction, not at
// decode.
func TestAnUnencodableValueIsRefused(t *testing.T) {
	_, err := page.NewKeyset(
		page.Key{Column: "meta", Value: map[string]string{"a": "b"}},
		page.Key{Column: "id", Value: "x", Unique: true},
	)
	if err == nil {
		t.Fatal("a map was accepted as a cursor value")
	}
}
