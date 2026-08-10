// Package cqrs carries the two rules that keep the command and query sides
// apart, and the idempotency gate that sits in front of every mutation.
//
// The split itself is structural rather than conventional (CONVENTIONS §1.3):
// commands load aggregates from KurrentDB and append events, queries read
// Postgres projections and write nothing. They share no package, so a query
// handler cannot quietly acquire an aggregate load — which is how CQRS erodes in
// practice, one "just this once" at a time.
//
// What lives HERE is only what both sides genuinely share: the shape of a
// handler, and the idempotency rules. Anything else added to this package is
// almost certainly a domain type in disguise.
package cqrs

import (
	"context"
	"errors"
)

// ErrInvalid is a malformed command, query or idempotency scope.
var ErrInvalid = errors.New("cqrs: invalid")

// Command is a request to change something. It names itself so idempotency,
// metrics and logs can scope by operation without an interceptor guessing from
// the transport.
type Command interface {
	// CommandName is stable and versioned with the API, because it is part of
	// the idempotency scope — renaming it makes every in-flight key miss.
	CommandName() string
}

// Query is a request to read something.
//
// Deliberately a DIFFERENT interface from Command with a different method name,
// rather than one `Name()` both satisfy. A single interface would let a type
// drift from one side to the other by accident; two mean a query used as a
// command does not compile.
type Query interface {
	QueryName() string
}

// CommandHandler executes one command.
//
// It returns a result because the API needs one — an id, a revision — not
// because the caller may read state back. A handler that returned a projection
// row would be reading its own write, which is the one thing eventual
// consistency does not promise (ADR-019).
type CommandHandler[C Command, R any] interface {
	Handle(ctx context.Context, cmd C) (R, error)
}

// QueryHandler answers one query.
type QueryHandler[Q Query, R any] interface {
	Answer(ctx context.Context, q Q) (R, error)
}

// CommandFunc adapts a function to CommandHandler.
type CommandFunc[C Command, R any] func(context.Context, C) (R, error)

func (f CommandFunc[C, R]) Handle(ctx context.Context, cmd C) (R, error) { return f(ctx, cmd) }

// QueryFunc adapts a function to QueryHandler.
type QueryFunc[Q Query, R any] func(context.Context, Q) (R, error)

func (f QueryFunc[Q, R]) Answer(ctx context.Context, q Q) (R, error) { return f(ctx, q) }
