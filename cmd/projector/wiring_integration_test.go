//go:build integration

package main

import (
	"log/slog"
	"testing"
)

// The projector is the ONLY binary that may write an authorization tuple, so it
// is the only binary where that writer can be missing without anything failing.
//
// Nothing at runtime notices its absence: events keep applying, checkpoints keep
// advancing, every probe stays green, and the permission graph silently stops
// changing. Three adapters in this codebase were once built, fully tested and
// constructed by no binary at all — this is the assertion that catches the same
// class of failure here.
//
// Tagged integration because the writer is deliberately refused without a
// revocation store, so a live Valkey is a precondition of it existing at all.
func TestTheTupleWriterIsWired(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec(), 2)
	defer closeAll()

	if d.tuples == nil {
		t.Fatal("no tuple writer was constructed: grants will never land in OpenFGA and " +
			"revocations will never be confirmed, while every projection reports healthy")
	}
}

// Without a store id the writer must NOT be constructed.
//
// A writer pointed at no store accepts every tuple and applies none of them,
// which is the worst outcome available on this path: the projector records the
// event as applied, its checkpoint advances past it, and the grant is gone with
// no replay that can bring it back.
//
// The positive control runs FIRST and in the same process. Without it this test
// passes whenever Valkey is merely unreachable — a nil writer for a reason that
// has nothing to do with the store id, which is a test that cannot fail.
func TestNoTupleWriterWithoutAStore(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec(), 2)
	if d.tuples == nil {
		closeAll()
		t.Fatal("precondition: no writer is constructed even WITH a store id, so this test " +
			"would pass without exercising anything")
	}
	closeAll()

	cfg.OpenFGA.StoreID = ""
	d, closeAll = newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec(), 2)
	defer closeAll()

	if d.tuples != nil {
		t.Fatal("a tuple writer was constructed with no store id: every write would be " +
			"accepted and none applied, and the checkpoint would advance past it anyway")
	}
}

// A projector that cannot confirm revocations must not get a tuple writer at
// all.
//
// Degrading to a bare writer here is the tempting mistake and the wrong one: it
// would remove tuples and clear nothing, so every tombstone survives to its TTL
// — an over-denial arriving an hour after its cause, which reads as a
// permissions bug rather than as the wiring mistake it is (ADR-045).
func TestNoTupleWriterWithoutARevocationStore(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec(), 2)
	if d.tuples == nil {
		closeAll()
		t.Fatal("precondition: no writer with a healthy Valkey")
	}
	closeAll()

	cfg.Valkey.Addr = []string{"127.0.0.1:1"}
	d, closeAll = newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec(), 2)
	defer closeAll()

	if d.tuples != nil {
		t.Fatal("a tuple writer was constructed with no revocation store: it would remove " +
			"tuples and confirm nothing, leaving every tombstone to expire on its TTL")
	}
}
