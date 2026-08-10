package db

import "context"

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
