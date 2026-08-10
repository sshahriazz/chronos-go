// Package page is cursor pagination, and the rules that keep it correct.
//
// Offsets are banned (CONVENTIONS §7): `OFFSET 200` re-counts two hundred rows
// on every page, and a row inserted or deleted between two requests shifts every
// later page — so a client walking a list silently skips rows or sees them
// twice. Neither produces an error. Keyset pagination asks "give me what comes
// after this exact row", which is stable under concurrent writes and uses the
// index the ORDER BY already needs.
//
// The correctness of that rests on three things this package refuses to leave to
// the caller:
//
//  1. The sort key must end in a UNIQUE column. Without a tiebreaker, rows
//     sharing a sort value straddle the page boundary and are skipped or
//     repeated.
//  2. A token must not be usable against a different query. Reused across a
//     changed filter or sort, it names a position in a list that no longer
//     exists, and the rows returned are simply wrong.
//  3. An unreadable token is an ERROR, never "start from the beginning". A
//     client that keeps receiving page one loops forever, and nothing in that
//     loop looks like a failure.
package page

import "fmt"

// Size is a validated page size.
//
// Zero means "the caller did not say", which takes DefaultSize. Anything over
// MaxSize is capped rather than refused: a client asking for too much still gets
// a correct answer plus a next token, so capping costs it a round trip and
// refusing costs it the feature.
type Size int

const (
	// DefaultSize is what an unspecified page_size becomes.
	DefaultSize = 50

	// MaxSize bounds one response. It exists to bound MEMORY and time on the
	// server, not to be polite: a single unbounded list is how one tenant's
	// query becomes everybody's outage.
	MaxSize = 200
)

// Clamp resolves a requested page size.
//
// A negative size is a caller bug rather than a client one — the wire type is
// unsigned — so it is an error instead of being quietly treated as zero.
func Clamp(requested int) (Size, error) {
	switch {
	case requested < 0:
		return 0, fmt.Errorf("%w: a page size of %d is negative", ErrInvalid, requested)
	case requested == 0:
		return DefaultSize, nil
	case requested > MaxSize:
		return MaxSize, nil
	default:
		return Size(requested), nil
	}
}

// Limit is how many rows to ask the database for: one more than the page size.
//
// The extra row is how "is there a next page?" is answered without a second
// query and without COUNT(*). Counting is the alternative and it is worse on
// both axes — an extra scan, and an answer that was true a moment ago.
func (s Size) Limit() int32 {
	return int32(s) + 1 //nolint:gosec // Clamp bounds this at MaxSize
}

// Page is one response: the rows, and where to resume.
type Page[T any] struct {
	Items []T

	// Next is empty when the list is exhausted. Empty means DONE, and a client
	// stops on it — so it must never be produced while rows remain, and never
	// withheld when they do not.
	Next Token
}

// Of builds a page from the rows a Limit()-sized query returned.
//
// rows carries at most Size+1 entries. The extra one is not returned to the
// client; it only proves another page exists. key is asked for the cursor of the
// LAST returned row, which is why it is called after trimming and not before —
// keying the peeked row would resume one row late and skip it.
func Of[T any](rows []T, size Size, q QueryID, key func(T) Keyset) (Page[T], error) {
	more := len(rows) > int(size)
	if more {
		rows = rows[:size]
	}
	p := Page[T]{Items: rows}
	if !more || len(rows) == 0 {
		// No token. The client stops here, which is correct in both cases: the
		// query is exhausted, or it returned nothing at all.
		return p, nil
	}
	tok, err := Encode(key(rows[len(rows)-1]), q)
	if err != nil {
		return Page[T]{}, err
	}
	p.Next = tok
	return p, nil
}

// Start is the cursor for a request with no page token: the first page.
//
// It is a distinct, named value rather than a zero Keyset so that "the caller
// asked for the first page" and "the caller sent something we could not read"
// can never be confused — the second is an error, and conflating them is what
// makes a client loop on page one forever.
func Start() Keyset { return Keyset{} }

// Resume decodes a request's page token.
//
// An empty token is the first page. A non-empty one that does not belong to this
// query is an error, not a fresh start.
func Resume(tok Token, q QueryID) (Keyset, error) {
	if tok == "" {
		return Start(), nil
	}
	return Decode(tok, q)
}
