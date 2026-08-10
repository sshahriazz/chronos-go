package page

import (
	"errors"
	"fmt"
	"time"
)

// ErrInvalid is a malformed page size, keyset or token.
var ErrInvalid = errors.New("page: invalid")

// Keyset is the position of one row in a sorted list: the values of the sort
// columns, in ORDER BY order.
//
// The last component must be UNIQUE. That is the whole reason this is a type
// rather than a []any — a keyset ending in a non-unique column produces a bug
// with no symptom at the boundary: rows sharing the last sort value either all
// land on both sides of the page break, or none of them do.
type Keyset struct {
	keys []Key
}

// Key is one sort column's value at the cursor position.
type Key struct {
	// Column names the column, so a decoded token can be checked against the
	// query it is being used for rather than merely having the right arity.
	Column string

	// Value is the row's value. Only the types below are permitted; anything
	// else has no stable encoding and would come back as something the SQL
	// comparison silently mis-orders.
	Value any

	// Unique marks a column whose value identifies at most one row. At least the
	// LAST key must set it.
	Unique bool
}

// NewKeyset builds a cursor position, refusing one that cannot paginate
// correctly.
func NewKeyset(keys ...Key) (Keyset, error) {
	if len(keys) == 0 {
		return Keyset{}, fmt.Errorf("%w: a keyset names no columns", ErrInvalid)
	}
	seen := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		if k.Column == "" {
			return Keyset{}, fmt.Errorf("%w: a key has no column name", ErrInvalid)
		}
		if _, dup := seen[k.Column]; dup {
			// The same column twice makes the comparison ambiguous, and the
			// second occurrence would silently win.
			return Keyset{}, fmt.Errorf("%w: column %q appears twice in the sort key",
				ErrInvalid, k.Column)
		}
		seen[k.Column] = struct{}{}
		if err := checkValue(k.Column, k.Value); err != nil {
			return Keyset{}, err
		}
	}
	if last := keys[len(keys)-1]; !last.Unique {
		// The failure this prevents has no error and no log line: rows sharing
		// the last sort value straddle the page boundary, so a client walking the
		// list skips some and sees others twice.
		return Keyset{}, fmt.Errorf("%w: the sort key ends in %q, which is not unique; "+
			"append a unique tiebreaker or rows sharing that value will be skipped or "+
			"repeated at every page boundary", ErrInvalid, last.Column)
	}
	return Keyset{keys: append([]Key(nil), keys...)}, nil
}

// IsStart reports whether this is the first page.
func (k Keyset) IsStart() bool { return len(k.keys) == 0 }

// Keys returns the cursor's columns in ORDER BY order.
func (k Keyset) Keys() []Key { return append([]Key(nil), k.keys...) }

// Columns returns just the column names, for checking a decoded token against
// the query about to use it.
func (k Keyset) Columns() []string {
	out := make([]string, len(k.keys))
	for i, key := range k.keys {
		out[i] = key.Column
	}
	return out
}

// Args returns the values in ORDER BY order, ready to bind to a sqlc query's
// parameters.
//
// Values, never SQL. The comparison — `(created_at, id) < ($1, $2)` — is
// authored in db/query/**.sql and checked against the real schema by sqlc
// (CONVENTIONS §8); this package supplies what goes in the placeholders and
// nothing else.
func (k Keyset) Args() []any {
	out := make([]any, len(k.keys))
	for i, key := range k.keys {
		out[i] = key.Value
	}
	return out
}

// checkValue rejects a type with no stable round trip.
//
// A value that decodes back as a different Go type is the dangerous case, not a
// decode failure: a timestamp returning as a string compares lexically in the
// driver and orders rows wrongly without erroring anywhere.
func checkValue(column string, v any) error {
	switch v.(type) {
	case string, int64, int32, int, float64, bool, time.Time:
		return nil
	case nil:
		// NULL cannot be compared with < or > in SQL — `x > NULL` is NULL, which
		// is not true, so the page silently returns nothing. A nullable sort
		// column needs COALESCE in the query, not a NULL in the cursor.
		return fmt.Errorf("%w: column %q has a NULL cursor value; comparing against NULL "+
			"yields NULL, so the next page would come back empty", ErrInvalid, column)
	default:
		return fmt.Errorf("%w: column %q has value type %T, which has no stable cursor "+
			"encoding", ErrInvalid, column, v)
	}
}
