package authz

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// Subject is who a tuple grants to.
//
// It is a Principal, optionally narrowed by a Relation to name a USERSET —
// "everyone related to this object by this relation", written `team:eng#member`
// in OpenFGA. That indirection is the scale lever the whole model rests on: one
// tuple grants a team, and adding a member to the team grants them every one of
// the team's resources without writing anything (access.md §4).
type Subject struct {
	Principal Principal

	// Relation, when set, makes this a userset rather than a single principal.
	Relation Relation
}

// String renders the OpenFGA user reference: `user:alice` or `team:eng#member`.
func (s Subject) String() string {
	if s.Relation == "" {
		return s.Principal.String()
	}
	return s.Principal.String() + "#" + string(s.Relation)
}

// IsUserset reports whether this names a set of principals rather than one.
func (s Subject) IsUserset() bool { return s.Relation != "" }

func (s Subject) valid() error {
	if err := s.Principal.valid(); err != nil {
		return err
	}
	if s.Relation == "" {
		return nil
	}
	// Principal.valid already rejects ':' and '#' in the id, which is what stops a
	// userset reference from naming a different set of people than the caller
	// meant.
	return s.Relation.valid()
}

// valid rejects a relation that would change which object a reference names.
//
// ':' separates type from id and '#' introduces a userset, so a relation
// carrying either is the authorization equivalent of SQL injection.
func (r Relation) valid() error {
	if r == "" {
		return fmt.Errorf("%w: no relation given", ErrInvalid)
	}
	if strings.ContainsAny(string(r), ":#") {
		return fmt.Errorf("%w: relation %q contains a reserved character", ErrInvalid, r)
	}
	return nil
}

// Tuple is one edge in the authorization graph: subject —relation→ resource.
//
// It is the only shape a projector writes. Everything else about a resource —
// its name, its contents, what it is — lives in PostgreSQL; OpenFGA stores who
// may touch it and nothing more (ADR-006).
type Tuple struct {
	Subject  Subject
	Relation Relation
	Resource ResourceRef
}

func (t Tuple) String() string {
	return fmt.Sprintf("%s %s %s", t.Subject, t.Relation, t.Resource)
}

// Validate rejects a tuple that must never reach the authorization service.
func (t Tuple) Validate() error {
	if err := t.Subject.valid(); err != nil {
		return err
	}
	if err := t.Relation.valid(); err != nil {
		return err
	}
	return t.Resource.valid()
}

// query is the tombstone this tuple's removal confirms.
//
// A tombstone is keyed on a PRINCIPAL, so a userset tuple has none: removing
// `team:eng#member editor folder:f` revokes access for everyone in the team, and
// the module that ordered it writes one tombstone per affected principal. Those
// are confirmed with ConfirmAll, not by this tuple.
func (t Tuple) query() (Query, bool) {
	if t.Subject.IsUserset() {
		return Query{}, false
	}
	return Query{
		Principal: t.Subject.Principal,
		Relation:  t.Relation,
		Resource:  t.Resource,
	}, true
}

// TupleWriter is the write side of the authorization graph.
//
// Reachable from a PROJECTOR only. A use case that writes a tuple directly has
// bypassed the event log, so the graph now holds an edge no event explains and
// no rebuild can reproduce — which is drift the reconciler will fight forever
// (access.md §15).
//
// Both methods must be idempotent. A projector is replayed on restart and on
// rebuild, so the same event WILL arrive twice; a write that failed on a
// duplicate would stall the projection permanently the first time it happened.
type TupleWriter interface {
	// Write adds edges. Writing one that already exists is not an error.
	Write(ctx context.Context, tuples []Tuple) error

	// Delete removes edges. Deleting one that is already gone is not an error.
	Delete(ctx context.Context, tuples []Tuple) error
}

// Revocations is the tombstone lifecycle seen from the projector's side.
//
// The Guard consults tombstones; the projector clears them. Splitting the
// interface is what keeps the hot path unable to delete one.
type Revocations interface {
	// Confirm clears a tombstone because the tuple behind it is gone.
	Confirm(ctx context.Context, q Query) error
}

// ConfirmingWriter deletes tuples and then clears the tombstones they justified.
//
// The order is the entire point and it is not interchangeable:
//
//	delete the tuple  →  confirm the tombstone
//
// Reversed — or confirmed regardless of whether the delete succeeded — a failed
// deletion leaves the tuple in place with nothing denying against it, and a
// revoked principal silently regains access. There is no event, no log line and
// no failing check when that happens, which is why the sequence lives in one
// place instead of in every projector that removes a grant.
//
// A tombstone is therefore only ever cleared by positive confirmation. Nothing
// here is on a timer (ADR-045).
type ConfirmingWriter struct {
	writer      TupleWriter
	revocations Revocations
	log         *slog.Logger
}

var _ TupleWriter = (*ConfirmingWriter)(nil)

// NewConfirmingWriter wraps a TupleWriter.
//
// Revocations is required. Optional would mean a deployment could lose
// confirmation silently and only discover it as tombstones aging out to their
// TTL — which is exactly the failure the confirmation design exists to prevent.
func NewConfirmingWriter(w TupleWriter, r Revocations, log *slog.Logger) (*ConfirmingWriter, error) {
	if w == nil {
		return nil, fmt.Errorf("authz: a TupleWriter is required")
	}
	if r == nil {
		return nil, fmt.Errorf("authz: a Revocations store is required: without it a tombstone " +
			"can only be cleared by its TTL, and a TTL that fires before the tuple is " +
			"removed restores access to a revoked principal")
	}
	if log == nil {
		log = slog.Default()
	}
	return &ConfirmingWriter{writer: w, revocations: r, log: log}, nil
}

// Write adds edges and touches no tombstone.
//
// Deliberately: a grant landing does not mean an unrelated revocation has been
// applied, and clearing a tombstone here would let an arriving grant cancel a
// revocation the projector has not caught up to yet.
func (c *ConfirmingWriter) Write(ctx context.Context, tuples []Tuple) error {
	return c.writer.Write(ctx, tuples)
}

// Delete removes edges, then confirms the matching tombstones.
//
// A confirmation failure is REPORTED, not swallowed. The projector retries,
// which is safe because Delete is idempotent, and the alternative is a tombstone
// left to reach its TTL — an over-denial that looks like a permissions bug and
// arrives an hour after the cause.
func (c *ConfirmingWriter) Delete(ctx context.Context, tuples []Tuple) error {
	if err := c.writer.Delete(ctx, tuples); err != nil {
		// Nothing is confirmed. The tuple may still be there, so the tombstone is
		// the only thing denying access, and clearing it now would restore it.
		return err
	}
	for _, t := range tuples {
		q, ok := t.query()
		if !ok {
			// A userset removal has no single tombstone; see Tuple.query.
			continue
		}
		if err := c.revocations.Confirm(ctx, q); err != nil {
			return fmt.Errorf("authz: tuple %s removed but its revocation was not confirmed: %w",
				t, err)
		}
	}
	return nil
}

// ConfirmAll clears tombstones directly, for the fan-out a userset removal
// causes: removing a team's grant revokes every member, and each of those
// revocations has its own tombstone.
//
// Callable only after the tuples are gone. It is exported so the owning module
// can confirm what it revoked, and it does the same thing Delete does — reports
// the first failure rather than continuing, so a partial confirmation is visible
// instead of being mistaken for a complete one.
func (c *ConfirmingWriter) ConfirmAll(ctx context.Context, qs []Query) error {
	for _, q := range qs {
		if err := c.revocations.Confirm(ctx, q); err != nil {
			return fmt.Errorf("authz: confirming the revocation of %s on %s: %w",
				q.Principal, q.Resource, err)
		}
	}
	return nil
}
