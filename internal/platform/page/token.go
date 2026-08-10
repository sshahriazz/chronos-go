package page

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strconv"
	"time"
)

// Token is an opaque page cursor. It is the `next_page_token` on the wire.
//
// Opaque means clients must not parse it — not that it is secret. It carries no
// authority: a forged cursor names a position in a list the caller can already
// walk to, and every row it reaches is still filtered by row-level security. So
// it is NOT signed, deliberately. A MAC here would suggest the token is a
// capability, and the next person would be tempted to put something in it that
// relies on that.
type Token string

// QueryID identifies the query a token belongs to — its table, filters and sort.
//
// A cursor is a position in one specific ordering. Replayed against a different
// filter or a different ORDER BY, it names a position in a list that no longer
// exists, and the rows that come back are wrong with no error anywhere. Binding
// the token to the query makes that a decode failure instead.
//
// It must therefore vary with everything the ordering depends on — include the
// filter values, not just the query's name:
//
//	page.QueryID("notification_feed:unread:desc")
type QueryID string

// tokenVersion is stamped into every token.
//
// It exists so a change to the encoding is a clean rejection of old tokens
// rather than a misparse. A client holding a token across a deploy gets an
// error it can recover from by restarting the list; a misparse would give it
// rows from the wrong place.
const tokenVersion = 1

type wireToken struct {
	V int       `json:"v"`
	Q string    `json:"q"`
	K []wireKey `json:"k"`
}

type wireKey struct {
	C string `json:"c"`
	T string `json:"t"`
	X string `json:"x"`
}

// Encode renders a cursor position as a token bound to its query.
func Encode(k Keyset, q QueryID) (Token, error) {
	if k.IsStart() {
		// The first page has no cursor. Encoding one would produce a token that
		// decodes to "start", and a client following it would loop on page one.
		return "", fmt.Errorf("%w: refusing to encode a token for the first page", ErrInvalid)
	}
	if q == "" {
		return "", fmt.Errorf("%w: a token must name the query it belongs to", ErrInvalid)
	}
	w := wireToken{V: tokenVersion, Q: fingerprint(q), K: make([]wireKey, 0, len(k.keys))}
	for _, key := range k.keys {
		t, x, err := encodeValue(key.Column, key.Value)
		if err != nil {
			return "", err
		}
		w.K = append(w.K, wireKey{C: key.Column, T: t, X: x})
	}
	raw, err := json.Marshal(w)
	if err != nil {
		return "", fmt.Errorf("page: encoding cursor: %w", err)
	}
	// URL-safe and unpadded: a page token travels in a query string, and '+',
	// '/' and '=' all survive a round trip through some clients and not others.
	return Token(base64.RawURLEncoding.EncodeToString(raw)), nil
}

// Decode reads a token, refusing one that does not belong to this query.
//
// Every failure is an ERROR. Returning a zero Keyset for an unreadable token
// would mean "start from the beginning", and a client that keeps being handed
// page one loops forever with nothing in the loop looking like a failure.
func Decode(tok Token, q QueryID) (Keyset, error) {
	if tok == "" {
		return Keyset{}, fmt.Errorf("%w: empty page token", ErrInvalid)
	}
	if q == "" {
		return Keyset{}, fmt.Errorf("%w: a token must be decoded against a query", ErrInvalid)
	}
	raw, err := base64.RawURLEncoding.DecodeString(string(tok))
	if err != nil {
		return Keyset{}, fmt.Errorf("%w: page token is not valid base64: %w", ErrInvalid, err)
	}
	var w wireToken
	if err := json.Unmarshal(raw, &w); err != nil {
		return Keyset{}, fmt.Errorf("%w: page token is not readable: %w", ErrInvalid, err)
	}
	if w.V != tokenVersion {
		return Keyset{}, fmt.Errorf("%w: page token is version %d, this server writes %d; "+
			"restart the list", ErrInvalid, w.V, tokenVersion)
	}
	if w.Q != fingerprint(q) {
		return Keyset{}, fmt.Errorf("%w: this page token belongs to a different query; "+
			"a cursor is a position in one specific filter and sort, and reusing it across "+
			"a change returns the wrong rows", ErrInvalid)
	}
	keys := make([]Key, 0, len(w.K))
	for _, wk := range w.K {
		v, err := decodeValue(wk.C, wk.T, wk.X)
		if err != nil {
			return Keyset{}, err
		}
		keys = append(keys, Key{Column: wk.C, Value: v})
	}
	if len(keys) == 0 {
		return Keyset{}, fmt.Errorf("%w: page token names no columns", ErrInvalid)
	}
	// The uniqueness of the last column was established when the token was
	// WRITTEN. Re-asserting it here would mean trusting the token to describe
	// its own correctness, so it is set rather than read.
	keys[len(keys)-1].Unique = true
	return NewKeyset(keys...)
}

// fingerprint hashes a QueryID.
//
// A hash rather than the string itself, so the token does not carry the query's
// filter values — a page token ends up in access logs, browser history and
// referrer headers, and those values can be personal data (ADR-002).
func fingerprint(q QueryID) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(q))
	return strconv.FormatUint(h.Sum64(), 36)
}

// Value type tags. Short, because a token is repeated in every response.
const (
	tagString = "s"
	tagInt    = "i"
	tagFloat  = "f"
	tagBool   = "b"
	tagTime   = "t"
)

func encodeValue(column string, v any) (tag, enc string, err error) {
	switch t := v.(type) {
	case string:
		return tagString, t, nil
	case int:
		return tagInt, strconv.FormatInt(int64(t), 10), nil
	case int32:
		return tagInt, strconv.FormatInt(int64(t), 10), nil
	case int64:
		return tagInt, strconv.FormatInt(t, 10), nil
	case float64:
		// 'g' with -1 precision round trips exactly, where %f silently truncates.
		return tagFloat, strconv.FormatFloat(t, 'g', -1, 64), nil
	case bool:
		return tagBool, strconv.FormatBool(t), nil
	case time.Time:
		// RFC3339 with nanoseconds, in UTC. Seconds-only precision would put
		// every row written in the same second on the wrong side of the boundary
		// (CLAUDE.md: all times UTC).
		return tagTime, t.UTC().Format(time.RFC3339Nano), nil
	default:
		return "", "", fmt.Errorf("%w: column %q has value type %T, which has no stable "+
			"cursor encoding", ErrInvalid, column, v)
	}
}

// decodeValue restores the ORIGINAL Go type.
//
// Returning everything as a string would be the easy version and a silent bug: a
// timestamp bound as text compares lexically in Postgres, and an int compares
// wrongly at every digit boundary — "9" > "10".
func decodeValue(column, tag, enc string) (any, error) {
	switch tag {
	case tagString:
		return enc, nil
	case tagInt:
		n, err := strconv.ParseInt(enc, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: column %q is not an integer: %w", ErrInvalid, column, err)
		}
		return n, nil
	case tagFloat:
		f, err := strconv.ParseFloat(enc, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: column %q is not a number: %w", ErrInvalid, column, err)
		}
		return f, nil
	case tagBool:
		b, err := strconv.ParseBool(enc)
		if err != nil {
			return nil, fmt.Errorf("%w: column %q is not a boolean: %w", ErrInvalid, column, err)
		}
		return b, nil
	case tagTime:
		ts, err := time.Parse(time.RFC3339Nano, enc)
		if err != nil {
			return nil, fmt.Errorf("%w: column %q is not a timestamp: %w", ErrInvalid, column, err)
		}
		return ts.UTC(), nil
	default:
		return nil, fmt.Errorf("%w: column %q has unknown cursor type %q", ErrInvalid, column, tag)
	}
}
