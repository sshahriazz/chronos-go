//go:build integration

package openfga_test

import (
	"context"
	"strings"
	"testing"
	"time"

	fgav1 "github.com/chronos/chronos-go/gen/thirdparty/openfga/v1"
	fgaadapter "github.com/chronos/chronos-go/internal/adapter/openfga"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"google.golang.org/grpc"
)

func writerFor(t *testing.T, conn *grpc.ClientConn, storeID, modelID string) *fgaadapter.Writer {
	t.Helper()
	w, err := fgaadapter.NewWriter(conn, fgaadapter.Config{StoreID: storeID, ModelID: modelID})
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	return w
}

func grant(u, relation, folder string) authz.Tuple {
	return authz.Tuple{
		Subject:  authz.Subject{Principal: user(u)},
		Relation: authz.Relation(relation),
		Resource: authz.ResourceRef{Type: "folder", ID: folder},
	}
}

// A tuple written by the adapter is really in the graph — the round trip, not
// just "the RPC returned nil".
func TestWrittenTuplesTakeEffect(t *testing.T) {
	conn := dial(t)
	storeID, modelID := store(t, conn)
	w := writerFor(t, conn, storeID, modelID)
	checker, err := fgaadapter.New(conn, fgaadapter.Config{StoreID: storeID, ModelID: modelID})
	if err != nil {
		t.Fatalf("checker: %v", err)
	}
	ctx := context.Background()
	q := authz.Query{Principal: user("alice"), Relation: "editor",
		Resource: authz.ResourceRef{Type: "folder", ID: "f1"}}

	if d, err := checker.Check(ctx, q); err != nil || d.Allowed() {
		t.Fatalf("precondition: access before the tuple exists (allowed=%v err=%v)", d.Allowed(), err)
	}
	if err := w.Write(ctx, []authz.Tuple{grant("alice", "editor", "f1")}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if d, err := checker.Check(ctx, q); err != nil || !d.Allowed() {
		t.Fatalf("the tuple was written but access was refused (allowed=%v err=%v)", d.Allowed(), err)
	}

	if err := w.Delete(ctx, []authz.Tuple{grant("alice", "editor", "f1")}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if d, err := checker.Check(ctx, q); err != nil || d.Allowed() {
		t.Fatalf("the tuple was deleted but access remained (allowed=%v err=%v)", d.Allowed(), err)
	}
}

// Writing the same tuple twice must succeed.
//
// This is the property a projector's whole restart story depends on: it replays
// events on every start and on every rebuild, so the SECOND write of a grant is
// the normal case, not an edge case. Probed against the running server rather
// than trusted from the field's existence in the proto — an unrecognised
// on_duplicate value falls back to "error", and the failure would only appear on
// the first restart after a deploy.
func TestWritingTheSameTupleTwiceIsNotAnError(t *testing.T) {
	conn := dial(t)
	storeID, modelID := store(t, conn)
	w := writerFor(t, conn, storeID, modelID)
	ctx := context.Background()

	tuples := []authz.Tuple{grant("bob", "editor", "f2")}
	if err := w.Write(ctx, tuples); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if err := w.Write(ctx, tuples); err != nil {
		t.Fatalf("re-applying an event stalls the projection permanently: %v", err)
	}
}

// And the same for a delete: a projector that re-applies a removal must not stop
// on "that tuple is already gone".
//
// It matters more than the duplicate-write case. An aborted delete batch means
// the tombstones behind it are never confirmed, so every principal in the batch
// stays denied until the TTL — an over-denial arriving an hour after its cause.
func TestDeletingAnAbsentTupleIsNotAnError(t *testing.T) {
	conn := dial(t)
	storeID, modelID := store(t, conn)
	w := writerFor(t, conn, storeID, modelID)
	ctx := context.Background()

	if err := w.Delete(ctx, []authz.Tuple{grant("carol", "editor", "f3")}); err != nil {
		t.Fatalf("deleting a tuple that was never written: %v", err)
	}
}

// The default really is an error, so the ignore flags above are load-bearing
// rather than decorative.
//
// Without this, `on_duplicate: "ignore"` could be a no-op — a typo, a field the
// server ignores, a version that predates it — and both tests above would pass
// for the wrong reason.
func TestTheServerRejectsADuplicateWithoutTheIgnoreFlag(t *testing.T) {
	conn := dial(t)
	storeID, modelID := store(t, conn)
	client := fgav1.NewOpenFGAServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req := &fgav1.WriteRequest{
		StoreId:              storeID,
		AuthorizationModelId: modelID,
		Writes: &fgav1.WriteRequestWrites{
			TupleKeys: []*fgav1.TupleKey{tuple("user:dave", "editor", "folder:f4")},
		},
	}
	if _, err := client.Write(ctx, req); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if _, err := client.Write(ctx, req); err == nil {
		t.Fatal("the server accepted a duplicate write with no on_duplicate flag: the adapter's " +
			"idempotency is untested, because nothing here would fail without it")
	}
}

// A malformed tuple is refused BEFORE anything is sent — including tuples that
// would have gone out in an EARLIER request.
//
// The set has to span more than one server batch to test anything. Inside a
// single batch the server rejects the whole request for us, so validating late
// looks correct; across batches it is not, because the first request has already
// committed by the time the bad tuple is reached. That leaves the graph holding
// part of one event's changes — drift no replay corrects, since the projector
// has already recorded the event as applied.
func TestAMalformedTupleStopsEveryBatch(t *testing.T) {
	conn := dial(t)
	storeID, modelID := store(t, conn)
	w := writerFor(t, conn, storeID, modelID)
	checker, err := fgaadapter.New(conn, fgaadapter.Config{StoreID: storeID, ModelID: modelID})
	if err != nil {
		t.Fatalf("checker: %v", err)
	}
	ctx := context.Background()

	// 120 good tuples, then a bad one: the first 100 form a complete batch that
	// would already have been applied if validation ran per batch.
	const good = 120
	tuples := make([]authz.Tuple, 0, good+1)
	for i := range good {
		tuples = append(tuples, grant("early"+itoa(i), "editor", "f5"))
	}
	bad := grant("eve", "editor", "f5")
	bad.Relation = "editor#viewer" // '#' introduces a userset
	tuples = append(tuples, bad)

	if err := w.Write(ctx, tuples); err == nil {
		t.Fatal("a tuple with a reserved character in its relation was accepted")
	}

	// The FIRST tuple is the one that proves it: it sits in a batch that would
	// have been sent and committed before the bad tuple was ever examined.
	d, cerr := checker.Check(ctx, authz.Query{Principal: user("early0"), Relation: "editor",
		Resource: authz.ResourceRef{Type: "folder", ID: "f5"}})
	if cerr != nil {
		t.Fatalf("Check: %v", cerr)
	}
	if d.Allowed() {
		t.Fatal("the write was partially applied: an earlier batch committed before the " +
			"malformed tuple was reached, so the graph now holds half of one event's changes")
	}
}

// More tuples than fit in one request still apply, all of them.
//
// A team of 200 given access to a folder is one event. Over the server's limit
// the whole request fails, so without batching that event would stall the
// projection rather than take longer.
func TestABatchLargerThanTheServerLimitIsSplit(t *testing.T) {
	conn := dial(t)
	storeID, modelID := store(t, conn)
	w := writerFor(t, conn, storeID, modelID)
	checker, err := fgaadapter.New(conn, fgaadapter.Config{StoreID: storeID, ModelID: modelID})
	if err != nil {
		t.Fatalf("checker: %v", err)
	}
	ctx := context.Background()

	const n = 250 // > maxTuplesPerWrite (100), and not a multiple of it
	tuples := make([]authz.Tuple, 0, n)
	for i := range n {
		tuples = append(tuples, grant("member"+itoa(i), "editor", "big"))
	}
	if err := w.Write(ctx, tuples); err != nil {
		t.Fatalf("Write of %d tuples: %v", n, err)
	}

	// Check the LAST one specifically. A loop that dropped the final partial
	// batch would still pass a check of the first.
	d, err := checker.Check(ctx, authz.Query{Principal: user("member" + itoa(n-1)),
		Relation: "editor", Resource: authz.ResourceRef{Type: "folder", ID: "big"}})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !d.Allowed() {
		t.Fatalf("tuple %d of %d was never applied: the final partial batch was dropped", n-1, n)
	}
}

// An unreachable service is an ERROR, never a silent success.
//
// A write that quietly did nothing is the worst outcome available here: the
// projector records the event as applied, its checkpoint advances past it, and
// the grant is gone from the graph with no replay that can bring it back.
func TestAnUnreachableServiceFailsTheWrite(t *testing.T) {
	conn, err := fgaadapter.Dial("127.0.0.1:1", presharedKey())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	w, err := fgaadapter.NewWriter(conn, fgaadapter.Config{StoreID: "store"})
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err = w.Write(ctx, []authz.Tuple{grant("frank", "editor", "f6")})
	if err == nil {
		t.Fatal("writing to an unreachable service reported success: the projector would " +
			"advance its checkpoint past a grant that was never applied")
	}
	if !authz.IsUnavailable(err) {
		t.Errorf("the failure is not reported as unavailable, so a caller cannot tell it apart "+
			"from a rejected tuple: %v", err)
	}
}

// A store id is required at construction. Without one, writes would go to no
// store at all and every one of them would look like it succeeded.
func TestAWriterWithoutAStoreIsRefused(t *testing.T) {
	conn := dial(t)
	if _, err := fgaadapter.NewWriter(conn, fgaadapter.Config{}); err == nil {
		t.Fatal("a writer was constructed with no store id")
	} else if !strings.Contains(err.Error(), "store id") {
		t.Errorf("the error does not name the missing store id: %v", err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
