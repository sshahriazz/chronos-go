package projection

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"sync"

	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// DefaultRebuildShards is the parallelism a sharded rebuild uses when the
// caller does not choose one. One means sequential — the previous behaviour,
// and the only safe default for a projection nobody has thought about.
const DefaultRebuildShards = 1

// MaxRebuildShards bounds the fan-out. Each shard holds a pooled connection for
// the duration of the rebuild, and a rebuild that exhausts the pool starves the
// live projectors sharing it.
const MaxRebuildShards = 16

// shardOf routes an event to a worker by its STREAM, never by its position.
//
// This is the whole correctness argument for sharding, so it is worth stating
// plainly. Slicing a link stream into revision RANGES and replaying the ranges
// in parallel is the obvious design and it is wrong here: two events for the
// same aggregate land in different ranges, every projection in this codebase
// upserts by row, and the surviving row is then whichever range happened to
// commit last. That is a read model that is wrong in a way nothing detects —
// no error, no failed test, just a value from the middle of an aggregate's
// history.
//
// Hashing the stream name puts every event of one aggregate in one worker, in
// order. Ordering ACROSS aggregates is lost, which is exactly the guarantee a
// rebuild already gives up by reading a link stream at all.
func shardOf(stream eventsourcing.StreamID, shards int) int {
	if shards <= 1 {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(stream))
	return int(h.Sum32() % uint32(shards)) //nolint:gosec // bounded by shards
}

// shardedReplay applies a link stream through N workers partitioned by stream.
//
// No worker writes a checkpoint. During a sharded rebuild the position advances
// out of order by construction, so a per-event checkpoint would name a position
// whose predecessors have not all been applied — and a crash would then resume
// from it and skip them. Instead the checkpoint stays where Rebuild cleared it
// until the whole replay finishes, and the coordinator writes it once. A crash
// mid-rebuild therefore restarts the rebuild, which is correct: a half-rebuilt
// projection is not a state anything should resume from.
type shardedReplay struct {
	runner *Runner
	shards int

	mu       sync.Mutex
	furthest eventsourcing.Position
	applied  int64

	work []chan eventsourcing.RecordedEvent
	errs []error
	wg   sync.WaitGroup
}

func newShardedReplay(r *Runner, shards int) *shardedReplay {
	s := &shardedReplay{runner: r, shards: shards}
	s.work = make([]chan eventsourcing.RecordedEvent, shards)
	s.errs = make([]error, shards)
	for i := range s.work {
		// A small buffer keeps the reader from blocking on a busy worker without
		// letting one worker run far ahead in memory.
		s.work[i] = make(chan eventsourcing.RecordedEvent, 64)
	}
	return s
}

// start launches the workers.
//
// Each worker owns its own buffer. A rebuild is entirely "behind" by
// definition, so the same amortisation the sequential path gets applies here —
// and it applies per shard, because a buffer shared across workers would need a
// lock on the hot path and would mix streams from different partitions into one
// transaction for no gain.
func (s *shardedReplay) start(ctx context.Context) {
	for i := range s.shards {
		s.wg.Add(1)
		go func(shard int) {
			defer s.wg.Done()

			w := &shardWorker{replay: s}
			for e := range s.work[shard] {
				if ctx.Err() != nil {
					return
				}
				if err := w.offer(ctx, e); err != nil {
					if s.errs[shard] == nil {
						s.errs[shard] = err
					}
					// Drain rather than return: the reader is still writing to
					// this channel and would block forever on a closed worker.
					continue
				}
			}
			// The tail of the partition. Without this the last partial batch is
			// never written, and the coordinator would checkpoint a position
			// whose rows are still in memory.
			if err := w.flush(ctx); err != nil && s.errs[shard] == nil {
				s.errs[shard] = err
			}
		}(i)
	}
}

// shardWorker applies one partition, buffering rows the way the sequential
// catch-up path does. It is owned by exactly one goroutine; only the counters it
// publishes on flush are shared.
type shardWorker struct {
	replay  *shardedReplay
	pending batch
}

// offer decodes an event and adds it to the worker's buffer, flushing first when
// the tenant changes or the buffer is full.
//
// No checkpoint is ever written here. During a sharded rebuild the position
// advances out of order by construction, so the coordinator writes one position
// at the end — see the type comment on shardedReplay.
func (w *shardWorker) offer(ctx context.Context, e eventsourcing.RecordedEvent) error {
	r := w.replay.runner
	if e.IsSystem() {
		return nil
	}
	meta, err := r.decodeMeta(e)
	if err != nil {
		return fmt.Errorf("%w: %w", errApply, err)
	}
	env := Envelope{
		ID: e.ID, Type: e.Type, Stream: e.Stream, Revision: e.Revision,
		Position: e.Position, Meta: meta, Payload: e.Payload,
		// Never live during a rebuild: a rebuild that announced would replay
		// every notification a browser ever received.
		Live: false,
	}

	if !w.pending.accepts(ScopeOf(env.Meta)) {
		if err := w.flush(ctx); err != nil {
			return err
		}
	}
	w.pending.add(env)
	if w.pending.len() >= r.batchSize() {
		return w.flush(ctx)
	}
	return nil
}

// flush writes the buffered rows in ONE transaction, WITHOUT a checkpoint.
func (w *shardWorker) flush(ctx context.Context) error {
	n := w.pending.len()
	if n == 0 {
		return nil
	}
	r := w.replay.runner
	last := w.pending.last()
	culprit := last

	started := r.deps.Clock.Now()
	err := r.deps.Batch.InTenantBatch(ctx, w.pending.scope, db.Replayable, func(bw db.Writer) error {
		for _, env := range w.pending.events {
			if err := r.proj.Apply(ctx, bw, env); err != nil {
				culprit = env
				return err
			}
		}
		return nil
	})
	if err != nil {
		w.pending.reset()
		r.deps.Metrics.Failed(r.name)
		return fmt.Errorf("%w: %s at %s#%d (in a batch of %d): %w",
			errApply, culprit.Type, culprit.Stream, culprit.Revision, n, err)
	}

	// One transaction's duration split across its events, so the histogram stays
	// comparable with the unbatched path.
	per := r.deps.Clock.Now().Sub(started).Seconds() / float64(n)
	for range n {
		r.deps.Metrics.Applied(r.name, per)
	}

	// Published under the lock because every shard reports into the same pair,
	// and the coordinator reads them once the workers have finished.
	replay := w.replay
	replay.mu.Lock()
	if last.Position.After(replay.furthest) {
		replay.furthest = last.Position
	}
	replay.applied += int64(n)
	replay.mu.Unlock()

	w.pending.reset()
	return nil
}

// dispatch is the Handler handed to the link-stream reader.
func (s *shardedReplay) dispatch(ctx context.Context, e eventsourcing.RecordedEvent) error {
	if err := s.firstError(); err != nil {
		// Stop reading as soon as any worker has failed. Continuing would spend
		// the whole rebuild discovering the same broken event again.
		return err
	}
	select {
	case s.work[shardOf(e.Stream, s.shards)] <- e:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// finish closes the workers, waits, and returns the first failure.
func (s *shardedReplay) finish() (eventsourcing.Position, int64, error) {
	for _, ch := range s.work {
		close(ch)
	}
	s.wg.Wait()
	if err := s.firstError(); err != nil {
		return eventsourcing.Position{}, 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.furthest, s.applied, nil
}

func (s *shardedReplay) firstError() error {
	for _, err := range s.errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// commit records the position the rebuild reached, once, at the end.
func (s *shardedReplay) commit(ctx context.Context, pos eventsourcing.Position, applied int64) error {
	r := s.runner
	next := Checkpoint{Position: pos, EventsProcessed: applied}
	if err := r.deps.TX.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		w := &querierWriter{ctx: ctx, q: q}
		r.deps.Checkpoints.Save(ctx, w, r.name, next, r.deps.Holder)
		return w.err
	}); err != nil {
		return fmt.Errorf("projection %s: recording the rebuilt position: %w", r.name, err)
	}
	r.state = next
	r.deps.Metrics.Position(r.name, pos.Commit)
	return nil
}

// errShardsUnsafe is returned when a caller asks for parallelism the runner
// cannot provide safely.
var errShardsUnsafe = errors.New("projection: unsafe shard count")

// replaySharded drains a link stream through N workers partitioned by stream.
//
// The read stays sequential — a link stream is already narrow, and reading it
// twice to parallelise the read would cost more than it saves. What parallelises
// is the WRITE, which is where the time goes: measured earlier in this project,
// 63% of per-event latency is the PostgreSQL round trip.
func (r *Runner) replaySharded(
	ctx context.Context, kind, name string, read func(eventsourcing.Handler) error,
) error {
	shards := r.deps.RebuildShards
	if shards > MaxRebuildShards {
		return fmt.Errorf("%w: %d shards exceeds the %d cap; each holds a pooled "+
			"connection for the whole rebuild and would starve the live projectors",
			errShardsUnsafe, shards, MaxRebuildShards)
	}

	r.deps.Log.InfoContext(ctx, "rebuilding from the "+kind+" stream", kind, name, "shards", shards)
	start := r.deps.Clock.Now()

	s := newShardedReplay(r, shards)
	s.start(ctx)

	// Paced at the READ, so the limit covers every shard together: N workers
	// against one pool is exactly the pressure the limit exists to bound.
	readErr := read(r.throttled(s.dispatch, newThrottle(r.deps.RebuildEventsPerSecond, r.deps.Clock)))
	pos, applied, workErr := s.finish()

	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case workErr != nil:
		// A projection that rejected an event will reject it again, sharded or
		// not. Stop and be loud, exactly as the sequential path does.
		return workErr
	case readErr != nil && errors.Is(readErr, errApply):
		return readErr
	case readErr != nil:
		// The link stream failed partway. The checkpoint was NOT written, so the
		// projection is still marked un-rebuilt and $all starts from zero — which
		// is correct, if slow. Writing a partial position here would strand the
		// rows already applied above a checkpoint that skips their predecessors.
		r.deps.Log.WarnContext(ctx, "link-stream read failed mid-rebuild; the checkpoint was not "+
			"advanced, so the rebuild restarts from $all",
			kind, name, "applied", applied, "error", readErr)
		return nil
	}

	if applied == 0 {
		// Nothing matched. Leave the checkpoint cleared so $all does the work.
		r.deps.Log.InfoContext(ctx, "replay complete", kind, name, "events", 0)
		return nil
	}
	if err := s.commit(ctx, pos, applied); err != nil {
		return err
	}

	r.deps.Log.InfoContext(ctx, "replay complete", kind, name,
		"events", applied, "shards", shards,
		"elapsed", r.deps.Clock.Now().Sub(start).String())
	return nil
}
