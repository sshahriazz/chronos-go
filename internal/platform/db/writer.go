package db

import (
	"context"
	"fmt"
)

// Writer collects statements to be sent together.
//
// Queueing, not executing, is the point: everything queued goes to PostgreSQL
// in ONE round trip and runs as a single transaction. Measured, that is the
// difference between five network round trips per event and one.
//
// Exec deliberately returns nothing. A batched statement has no result yet —
// it has not run — and returning a rows-affected count that is always zero
// would be a lie the caller could build logic on. Errors surface when the batch
// is sent, naming the statement that failed.
type Writer interface {
	Exec(sql string, args ...any)
}

// StatementCounter reports how many statements a Writer has queued so far.
//
// OPTIONAL, and probed with a type assertion. It exists so that a caller which
// queues statements on behalf of several units of work — a projector applying a
// batch of events — can record which statements belong to which unit, and
// therefore say which unit a failure belongs to.
//
// It has to be a separate interface rather than a method on Writer because the
// number is meaningless to almost every caller: one unit of work per batch has
// nothing to attribute.
type StatementCounter interface {
	// Queued is the number of statements queued so far, counting everything the
	// batch itself queued before the caller got the Writer.
	Queued() int
}

// BatchStatementError names the statement that failed inside a batch.
//
// TYPED rather than only a message, because the index is what lets a caller
// attribute the failure. A projector queues several statements per event and
// sends fifty events in one batch; without the index the only honest thing it
// can say is "something in this batch failed", and the only convenient thing it
// can say — the batch's last event — is WRONG. That misattribution cost an hour
// of debugging: the message named EmailVerificationRequested, the event that
// happened to close the batch, while the statement that failed was the
// UpsertUser of a different event several positions earlier.
type BatchStatementError struct {
	// Index is the ZERO-BASED position of the failing statement in the batch,
	// on the same scale StatementCounter.Queued reports.
	Index int
	// Count is how many statements the batch held.
	Count int
	// SQL is the failing statement, summarised for a log line.
	SQL string
	// Err is the error PostgreSQL returned.
	Err error
}

func (e *BatchStatementError) Error() string {
	return fmt.Sprintf("batch statement %d of %d (%s): %v", e.Index+1, e.Count, e.SQL, e.Err)
}

func (e *BatchStatementError) Unwrap() error { return e.Err }

// Durability states whether a batch must survive a crash.
//
// It is an explicit argument rather than a global setting because the answer
// differs by table, and getting it wrong in the silent direction loses data
// nobody can recover.
type Durability uint8

const (
	// Durable waits for the write-ahead log to reach disk before returning.
	// This is the default for anything that is a system of record.
	Durable Durability = iota

	// Replayable skips the WAL flush (synchronous_commit = off).
	//
	// Legitimate ONLY for data that can be reconstructed from the event log
	// (ADR-013). A crash can lose the last fraction of a second of commits —
	// but a projector's rows and its checkpoint are written in the SAME
	// transaction, so they are lost together and the projection stays
	// self-consistent. It simply resumes from the older checkpoint and reapplies
	// those events, which is safe because Apply is idempotent.
	//
	// Never use this for the PII vault or any other mutable system of record:
	// there is nothing to replay it from.
	Replayable
)

// BatchTX sends a set of writes as one pipelined, atomic round trip.
//
// PostgreSQL executes a pipelined batch as a single implicit transaction: if
// any statement fails, every earlier one in the batch is rolled back. That is
// what lets a projector keep its "rows and checkpoint commit together"
// guarantee while paying for one round trip instead of five — verified against
// the running server, with a failure forced at execution time rather than at
// prepare time.
type BatchTX interface {
	// InTenantBatch applies the tenant scope, runs fn to collect statements,
	// then sends them. A zero Tenant means no scope, which under RLS means the
	// batch can touch only tables without row security.
	InTenantBatch(ctx context.Context, t Tenant, d Durability, fn func(Writer) error) error
}
