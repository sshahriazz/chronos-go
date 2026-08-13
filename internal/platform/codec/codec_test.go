package codec_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/codec"
)

type person struct {
	Name    string            `json:"name"`
	Age     int               `json:"age"`
	Tags    []string          `json:"tags"`
	Labels  map[string]string `json:"labels"`
	Since   time.Time         `json:"since"`
	Nested  *person           `json:"nested,omitempty"`
	Ignored string            `json:"-"`
}

func sample() person {
	return person{
		Name: "alice", Age: 30,
		Tags:   []string{"a", "b"},
		Labels: map[string]string{"z": "1", "a": "2", "m": "3"},
		Since:  time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
	}
}

// The round trip preserves every field.
func TestRoundTrip(t *testing.T) {
	in := sample()
	b, err := codec.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	out, err := codec.Unmarshal[person](b)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.Name != in.Name || out.Age != in.Age {
		t.Fatalf("got %+v, want %+v", out, in)
	}
	if len(out.Tags) != 2 || out.Tags[0] != "a" {
		t.Errorf("tags round tripped as %v", out.Tags)
	}
	if out.Labels["a"] != "2" {
		t.Errorf("labels round tripped as %v", out.Labels)
	}
	if !out.Since.Equal(in.Since) {
		t.Errorf("since round tripped as %v", out.Since)
	}
}

// Encoding is DETERMINISTIC: the same value always produces the same bytes.
//
// Without it nothing here can be hashed or compared — the idempotency
// fingerprint, a content hash, a golden-file test. Map ordering is the part that
// varies, so the sample carries a map with keys whose natural hash order is not
// their sorted order.
func TestEncodingIsDeterministic(t *testing.T) {
	first, err := codec.Marshal(sample())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for i := range 50 {
		again, err := codec.Marshal(sample())
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("iteration %d produced different bytes:\n%s\n%s\n"+
				"a value that does not serialize identically cannot be fingerprinted, so "+
				"an idempotent retry would look like a reused key", i, first, again)
		}
	}
}

// An unknown member is an ERROR by default.
//
// The callers of Unmarshal are ours — a cursor, a cache entry, a config file —
// and an unknown member in any of those is a typo or a version mismatch.
// Ignoring it produces a value that is subtly wrong instead of an error saying so.
func TestUnknownMembersAreRejectedByDefault(t *testing.T) {
	_, err := codec.Unmarshal[person]([]byte(`{"name":"alice","nmae":"typo"}`))
	if err == nil {
		t.Fatal("an unknown member was accepted: a misspelled key is silently dropped and " +
			"the value is wrong with nothing reporting it")
	}
}

// Tolerant IGNORES unknown members, for the event log only.
//
// An event is immutable and forever, so a payload written by a newer producer
// carries fields this binary cannot name — and a rolling deploy runs both at
// once. Rejecting it would stall a projector on a valid event (ADR-029).
func TestTolerantAcceptsUnknownMembers(t *testing.T) {
	out, err := codec.Tolerant[person]([]byte(`{"name":"alice","addedLater":{"deep":[1,2]}}`))
	if err != nil {
		t.Fatalf("a payload from a newer producer was refused: %v", err)
	}
	if out.Name != "alice" {
		t.Fatalf("the known fields did not survive: %+v", out)
	}
}

// Field matching is CASE-SENSITIVE, unlike v1.
//
// Asserted rather than assumed, because it silently changes what old documents
// decode to: v1 populated UserID from "userid", and v2 does not.
func TestFieldMatchingIsCaseSensitive(t *testing.T) {
	out, err := codec.Tolerant[person]([]byte(`{"NAME":"alice"}`))
	if err != nil {
		t.Fatalf("Tolerant: %v", err)
	}
	if out.Name != "" {
		t.Fatal("a differently-cased key populated the field; v1 did this and v2 must not, " +
			"or the migration silently changes what stored documents mean")
	}
}

// A duplicate object name is an ERROR, where v1 took the last one.
//
// This is a security-relevant difference: two consumers disagreeing about which
// value wins is how a request gets authorized against one value and executed
// against another.
func TestDuplicateNamesAreRejected(t *testing.T) {
	_, err := codec.Tolerant[person]([]byte(`{"name":"alice","name":"mallory"}`))
	if err == nil {
		t.Fatal("a duplicate object member was accepted; two parsers can then disagree about " +
			"which value is real")
	}
}

// A nil slice or map marshals as `[]` / `{}`, not `null`.
//
// The v1 shape is available through NullEmpty for a format somebody else already
// parses. Pinned here because it is the difference most likely to surprise a
// consumer during the migration.
func TestNilCollectionsMarshalAsEmpty(t *testing.T) {
	b, err := codec.Marshal(person{Name: "alice"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(b), `"tags":[]`) {
		t.Errorf("a nil slice did not marshal as []: %s", b)
	}
	if !strings.Contains(string(b), `"labels":{}`) {
		t.Errorf("a nil map did not marshal as {}: %s", b)
	}

	withNull, err := codec.Marshal(person{Name: "alice"}, codec.NullEmpty())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(withNull), `"tags":null`) {
		t.Errorf("NullEmpty did not restore the v1 shape: %s", withNull)
	}
}

// Marshal never returns nil, even for a value that encodes to nothing.
//
// A nil slice is how several stores here spell "nothing recorded". An empty
// document is not nothing, and conflating them made an empty idempotency
// response indistinguishable from an unfinished one.
func TestMarshalNeverReturnsNil(t *testing.T) {
	b, err := codec.Marshal(struct{}{})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if b == nil {
		t.Fatal("an empty value marshalled to a nil slice, which callers read as 'nothing " +
			"was recorded'")
	}
}

// Append writes into a caller's buffer and leaves what was already there alone.
func TestAppendPreservesTheExistingBuffer(t *testing.T) {
	dst := []byte("prefix:")
	out, err := codec.Append(dst, person{Name: "alice"})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !bytes.HasPrefix(out, []byte("prefix:")) {
		t.Fatalf("Append clobbered the buffer: %s", out)
	}
	if !bytes.Contains(out, []byte(`"name":"alice"`)) {
		t.Fatalf("Append wrote no value: %s", out)
	}
}

// Append and Marshal agree, byte for byte.
//
// Two encoders producing different bytes for one value would break every
// fingerprint the moment a caller switched paths for performance.
func TestAppendMatchesMarshal(t *testing.T) {
	want, err := codec.Marshal(sample())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := codec.Append(nil, sample())
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(want)) {
		t.Fatalf("Append produced\n%s\nMarshal produced\n%s", got, want)
	}
}

// The encoder pool is safe to hammer, and reuse never leaks one call's bytes
// into another's.
func TestPooledEncodingIsIsolated(t *testing.T) {
	const n = 200
	results := make([][]byte, n)
	done := make(chan int, n)
	for i := range n {
		go func(i int) {
			b, err := codec.Append(nil, person{Name: strings.Repeat("x", i%17+1), Age: i})
			if err == nil {
				results[i] = b
			}
			done <- i
		}(i)
	}
	for range n {
		<-done
	}
	for i, b := range results {
		want := `"age":` + itoa(i)
		if !bytes.Contains(b, []byte(want)) {
			t.Fatalf("result %d is %s; a pooled buffer leaked another call's bytes", i, b)
		}
	}
}

// Streaming round trip.
func TestStreamRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := codec.EncodeTo(&buf, sample()); err != nil {
		t.Fatalf("EncodeTo: %v", err)
	}
	out, err := codec.DecodeFrom[person](&buf)
	if err != nil {
		t.Fatalf("DecodeFrom: %v", err)
	}
	if out.Name != "alice" {
		t.Fatalf("got %+v", out)
	}
}

// Trailing content is an error, so a doubled or truncated document cannot be
// mistaken for a good one.
func TestTrailingContentIsRejected(t *testing.T) {
	if _, err := codec.DecodeFrom[person](strings.NewReader(`{"name":"a"}{"name":"b"}`)); err == nil {
		t.Fatal("two documents decoded as one; the second was silently discarded")
	}
}

// Malformed input is an error, and the message names the type being decoded.
func TestMalformedInputIsAnError(t *testing.T) {
	_, err := codec.Unmarshal[person]([]byte(`{"name":`))
	if err == nil {
		t.Fatal("truncated JSON decoded successfully")
	}
	if !strings.Contains(err.Error(), "codec_test.person") {
		t.Errorf("the error does not name the target type: %v", err)
	}
}

// Valid checks syntax only, and says nothing about whether a document fits a
// type — the distinction matters, because using it as a substitute for decoding
// would accept a well-formed document with entirely wrong contents.
func TestValidChecksSyntaxOnly(t *testing.T) {
	if !codec.Valid([]byte(`{"anything":[1,2,3]}`)) {
		t.Error("well-formed JSON reported invalid")
	}
	if codec.Valid([]byte(`{"a":`)) {
		t.Error("truncated JSON reported valid")
	}
}

func TestCompactAndIndent(t *testing.T) {
	pretty, err := codec.Indent([]byte(`{"a":1,"b":[2,3]}`), "", "  ")
	if err != nil {
		t.Fatalf("Indent: %v", err)
	}
	if !bytes.Contains(pretty, []byte("\n")) {
		t.Fatalf("Indent produced no newlines: %s", pretty)
	}
	compact, err := codec.Compact(pretty)
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if bytes.Contains(compact, []byte("\n")) {
		t.Fatalf("Compact left whitespace: %s", compact)
	}
}

// Compact and Indent do not mutate the caller's slice.
//
// jsontext works in place on a Value, so operating on the caller's bytes
// directly would corrupt a buffer somebody else still holds — including one that
// came straight out of a database row.
func TestCompactAndIndentDoNotMutateTheInput(t *testing.T) {
	original := []byte(`{"a":1,  "b":2}`)
	keep := bytes.Clone(original)

	if _, err := codec.Compact(original); err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if !bytes.Equal(original, keep) {
		t.Fatalf("Compact mutated the caller's slice: %s", original)
	}
	if _, err := codec.Indent(original, "", "  "); err != nil {
		t.Fatalf("Indent: %v", err)
	}
	if !bytes.Equal(original, keep) {
		t.Fatalf("Indent mutated the caller's slice: %s", original)
	}
}

// Into decodes into a pre-allocated target and is strict like Unmarshal.
func TestIntoIsStrict(t *testing.T) {
	var p person
	if err := codec.Into([]byte(`{"name":"alice"}`), &p); err != nil {
		t.Fatalf("Into: %v", err)
	}
	if p.Name != "alice" {
		t.Fatalf("got %+v", p)
	}
	if err := codec.Into([]byte(`{"nmae":"typo"}`), &p); err == nil {
		t.Fatal("Into accepted an unknown member")
	}
}

// A decode error is wrapped, so callers can match on it without string
// comparison.
func TestErrorsAreWrapped(t *testing.T) {
	_, err := codec.Unmarshal[person]([]byte(`not json`))
	if err == nil {
		t.Fatal("garbage decoded successfully")
	}
	if errors.Unwrap(err) == nil {
		t.Error("the underlying error was discarded, so a caller cannot inspect it")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
