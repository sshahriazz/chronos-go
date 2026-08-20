// Package codec is the only place this codebase encodes or decodes JSON.
//
// It wraps encoding/json/v2 (stdlib since Go 1.27; no build flag) behind generic
// primitives, for three reasons that are not about performance:
//
//  1. **The strictness decision is forced.** v2 can reject unknown members, and
//     whether that is right depends entirely on what is being read. A stored
//     event MUST tolerate fields a newer producer added (ADR-029 upcasting); a
//     config file or a page cursor must NOT, because a typo'd key silently
//     ignored is a setting that never took effect. Two named entry points make
//     the caller choose, instead of inheriting whichever default the library
//     happens to have.
//
//  2. **Determinism is available and usually required here.** Anything hashed,
//     fingerprinted or compared byte-for-byte — the idempotency fingerprint, an
//     event payload written twice during a replay — must serialize identically
//     every time. v1 could not promise that for maps; v2 can, on request.
//
//  3. **v2 changes observable behaviour**, and a codebase that reads a permanent
//     append-only log cannot absorb that by accident. The differences are listed
//     in Compatibility below.
//
// # Performance
//
// v2 is faster than v1 for decoding and roughly comparable for encoding, but the
// real win here is [Append] and [DecodeFrom], which avoid the intermediate
// allocation v1's API forces on every call. Numbers, and the conditions they
// were measured under, are in the package benchmarks — not in this comment,
// where they would rot.
//
// # Compatibility with encoding/json v1
//
// These are behaviour changes, not style differences. Each one has bitten a real
// codebase somewhere:
//
//   - A nil slice or map marshals as `[]` / `{}`, not `null`. v1 emitted null.
//     [NullEmpty] restores the v1 shape where a consumer depends on it.
//   - Field matching is CASE-SENSITIVE. v1 matched case-insensitively, so
//     `{"userid":...}` used to populate a `UserID` field and now does not.
//   - Duplicate object names are an ERROR. v1 silently took the last one.
//   - `time.Duration` marshals as a string ("1.5s"), not an integer nanosecond
//     count.
//
// The first two are the dangerous ones for stored data, which is why
// [Tolerant] exists and why the event codec's tests decode real historical
// payloads rather than freshly-marshalled ones.
package codec

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"io"
	"sync"
)

// Option configures one call. A thin alias so callers never import the
// experimental package directly — when v2 lands in the standard library under a
// different path, this is the only file that changes.
type Option = json.Options

// Deterministic makes map ordering stable.
//
// On by default in every function here, and that is deliberate: the alternative
// is a value that serializes differently on each call, which breaks any
// comparison by bytes — an idempotency fingerprint, a content hash, a test that
// compares golden output. The cost is a sort of the map keys, paid only by
// values that actually contain maps.
func Deterministic() Option { return json.Deterministic(true) }

// NullEmpty restores v1's shape for nil slices and maps: `null` rather than
// `[]` and `{}`.
//
// Only for a wire format somebody else already parses. For anything we own, the
// v2 default is better — a consumer that must distinguish "absent" from "empty"
// is a consumer that will one day get it wrong.
func NullEmpty() Option {
	return json.JoinOptions(json.FormatNilSliceAsNull(true), json.FormatNilMapAsNull(true))
}

// Marshal encodes a value.
//
// Deterministic, so the same value always produces the same bytes. Nothing here
// is safe to compare or hash otherwise.
func Marshal[T any](v T, opts ...Option) ([]byte, error) {
	b, err := json.Marshal(v, withDefaults(opts)...)
	if err != nil {
		return nil, fmt.Errorf("codec: encoding %T: %w", v, err)
	}
	if b == nil {
		// Never nil. A nil slice is how several stores in this codebase spell
		// "nothing recorded", and an empty JSON document is not nothing — the
		// idempotency gate learned this the hard way, where an empty response
		// became indistinguishable from an unfinished one.
		b = []byte{}
	}
	return b, nil
}

// Append encodes into a caller-supplied buffer, returning the extended slice.
//
// The allocation-free path. Marshal has to allocate a fresh slice on every call
// by construction; this one reuses whatever the caller already has, which is
// what makes a per-event or per-request encode cheap.
func Append[T any](dst []byte, v T, opts ...Option) ([]byte, error) {
	enc := getEncoder(dst)
	defer putEncoder(enc)

	if err := json.MarshalEncode(enc.encoder, v, withDefaults(opts)...); err != nil {
		return dst, fmt.Errorf("codec: encoding %T: %w", v, err)
	}
	return append(dst, enc.buf.Bytes()...), nil
}

// Unmarshal decodes into a value of type T, REJECTING unknown members.
//
// Strict is the default because the callers are ours: a page cursor, a cached
// entry, a config document. An unknown member in any of those is a typo or a
// version mismatch, and silently ignoring it produces a value that is subtly
// wrong rather than an error that says so.
//
// For anything read from the event log, use [Tolerant] instead — an event
// written by a newer producer legitimately carries fields this binary has never
// heard of, and rejecting it would stall a projector on a perfectly valid event
// (ADR-029).
func Unmarshal[T any](data []byte, opts ...Option) (T, error) {
	var v T
	all := append([]Option{json.RejectUnknownMembers(true)}, opts...)
	if err := json.Unmarshal(data, &v, all...); err != nil {
		return v, fmt.Errorf("codec: decoding %T: %w", v, err)
	}
	return v, nil
}

// Tolerant decodes while IGNORING unknown members.
//
// The event-log path. An event is immutable and forever, so a payload written by
// a later version of this service will carry fields an older binary cannot name
// — and a rolling deploy has both running at once. Rejecting the unknown field
// would stop a projector on an event that is entirely valid.
//
// This is the ONLY sanctioned way to be lenient. Every other decode is strict,
// so "which of these tolerates junk?" is answered by the function name.
func Tolerant[T any](data []byte, opts ...Option) (T, error) {
	var v T
	if err := json.Unmarshal(data, &v, opts...); err != nil {
		return v, fmt.Errorf("codec: decoding %T: %w", v, err)
	}
	return v, nil
}

// Into decodes into an existing value, for the cases where T cannot be inferred
// or the target is pre-allocated.
//
// Strict, like [Unmarshal].
func Into(data []byte, target any, opts ...Option) error {
	all := append([]Option{json.RejectUnknownMembers(true)}, opts...)
	if err := json.Unmarshal(data, target, all...); err != nil {
		return fmt.Errorf("codec: decoding %T: %w", target, err)
	}
	return nil
}

// IntoTolerant decodes into an existing value, IGNORING unknown members.
//
// The event-log counterpart of [Into]: the target is constructed by a registry
// and therefore cannot be a type parameter, but the payload still comes from a
// permanent append-only log and still has to survive a newer producer's fields.
func IntoTolerant(data []byte, target any, opts ...Option) error {
	if err := json.Unmarshal(data, target, opts...); err != nil {
		return fmt.Errorf("codec: decoding %T: %w", target, err)
	}
	return nil
}

// EncodeTo streams a value to a writer, without building the whole document in
// memory.
//
// For a response body or a file. Note it does NOT hold the value in a buffer
// first, so a mid-encode failure has already written a partial document — which
// is correct for a stream and wrong for anything the caller means to retry.
func EncodeTo[T any](w io.Writer, v T, opts ...Option) error {
	if err := json.MarshalWrite(w, v, withDefaults(opts)...); err != nil {
		return fmt.Errorf("codec: encoding %T: %w", v, err)
	}
	return nil
}

// DecodeFrom streams a value from a reader.
//
// Strict, like [Unmarshal]. It reads exactly one JSON value and reports an error
// if the input holds more, so a truncated or doubled document cannot be mistaken
// for a good one.
func DecodeFrom[T any](r io.Reader, opts ...Option) (T, error) {
	var v T
	all := append([]Option{json.RejectUnknownMembers(true)}, opts...)
	if err := json.UnmarshalRead(r, &v, all...); err != nil {
		return v, fmt.Errorf("codec: decoding %T: %w", v, err)
	}
	return v, nil
}

// Valid reports whether the bytes are well-formed JSON, without decoding them.
//
// Syntax only. It says nothing about whether the document matches any Go type,
// so it is a cheap pre-filter and never a substitute for decoding.
func Valid(data []byte) bool { return jsontext.Value(data).IsValid() }

// Compact removes insignificant whitespace in place where it can.
func Compact(data []byte) ([]byte, error) {
	v := jsontext.Value(bytes.Clone(data))
	if err := v.Compact(); err != nil {
		return nil, fmt.Errorf("codec: compacting: %w", err)
	}
	return v, nil
}

// Indent renders a document for a human — a log line an operator reads, a
// generated file kept in git.
//
// Never for a wire format: whitespace is bytes, and every consumer pays for it.
func Indent(data []byte, prefix, indent string) ([]byte, error) {
	v := jsontext.Value(bytes.Clone(data))
	if err := v.Indent(jsontext.WithIndentPrefix(prefix), jsontext.WithIndent(indent)); err != nil {
		return nil, fmt.Errorf("codec: indenting: %w", err)
	}
	return v, nil
}

// withDefaults prepends the options every encode gets.
//
// Deterministic is not optional, and is first so a caller-supplied option can
// still override it deliberately — v2 resolves duplicates last-wins.
func withDefaults(opts []Option) []Option {
	if len(opts) == 0 {
		return defaultOpts
	}
	all := make([]Option, 0, len(opts)+1)
	all = append(all, Deterministic())
	return append(all, opts...)
}

var defaultOpts = []Option{Deterministic()}

// encoderPool reuses the encoder and its buffer.
//
// jsontext.Encoder carries internal state worth keeping — that is the whole
// reason v2 exposes it separately from the marshal call. Without pooling, the
// streaming path allocates as much as the simple one and the extra API buys
// nothing.
type pooledEncoder struct {
	buf     *bytes.Buffer
	encoder *jsontext.Encoder
}

var encoderPool = sync.Pool{New: func() any {
	buf := new(bytes.Buffer)
	return &pooledEncoder{buf: buf, encoder: jsontext.NewEncoder(buf)}
}}

func getEncoder(dst []byte) *pooledEncoder {
	e, _ := encoderPool.Get().(*pooledEncoder)
	e.buf.Reset()
	e.buf.Grow(len(dst))
	e.encoder.Reset(e.buf)
	return e
}

// putEncoder returns an encoder to the pool, dropping any that grew too large.
//
// A single huge document would otherwise keep its buffer alive for the process's
// lifetime, in every pool slot it touched — the classic sync.Pool leak, where
// memory rises after one outlier and never comes back down.
const maxPooledBuffer = 64 << 10

func putEncoder(e *pooledEncoder) {
	if e.buf.Cap() > maxPooledBuffer {
		return
	}
	encoderPool.Put(e)
}
