//go:build integration

package kurrentdb_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	kdb "github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	es "github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// ---- a minimal aggregate, defined here so the kernel stays domain-free ----

type accountOpened struct {
	Owner string `json:"owner"`
}

func (accountOpened) EventType() string { return "test.AccountOpened.v1" }

type accountRenamed struct {
	Name string `json:"name"`
}

func (accountRenamed) EventType() string { return "test.AccountRenamed.v1" }

type account struct {
	es.Base
	owner string
	name  string
}

func (a *account) Apply(e es.Event) {
	switch ev := e.(type) {
	case *accountOpened:
		a.owner = ev.Owner
	case *accountRenamed:
		a.name = ev.Name
	}
}

func newAccount() *account { return &account{} }

// ---- harness -------------------------------------------------------------

func newRepo(t *testing.T) (*es.Repository[*account], func()) {
	t.Helper()

	conn := os.Getenv("KURRENTDB_CONNECTION_STRING")
	if conn == "" {
		conn = "kurrentdb://localhost:2113?tls=false"
	}
	client, err := kdb.Dial(conn)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	up := es.NewUpcasterRegistry()
	up.Register("test.AccountOpened.v1", 1)
	up.Register("test.AccountRenamed.v1", 1)

	codec := eventcodec.NewJSON(up)
	codec.Register("test.AccountOpened.v1", func() es.Event { return &accountOpened{} })
	codec.Register("test.AccountRenamed.v1", func() es.Event { return &accountRenamed{} })

	store := kdb.NewStore(client, codec)
	repo := es.NewRepository(store, codec, up, "testaccount", newAccount)
	return repo, func() { client.Close() }
}

func uniqueKey() string {
	return "acct" + ids.New[ids.Org](time.Now(), ids.Entropy()).String()[4:16]
}

func meta() es.Metadata {
	return es.Metadata{OccurredAt: time.Now().UTC(), OrgID: "org_test", Residency: "eu"}
}

// ---- tests ---------------------------------------------------------------

func TestRoundTrip(t *testing.T) {
	repo, done := newRepo(t)
	defer done()
	ctx := context.Background()
	key := uniqueKey()

	a, err := repo.Load(ctx, key)
	if err != nil {
		t.Fatalf("load new: %v", err)
	}
	if !es.IsNew(a) {
		t.Fatal("an unwritten aggregate must report as new")
	}

	es.Record(a, &accountOpened{Owner: "alice"})
	es.Record(a, &accountRenamed{Name: "Payroll"})

	res, err := repo.Save(ctx, key, a, "idem-"+key, meta())
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if res.Position.IsStart() {
		t.Error("append must report a real commit position (the consistency token)")
	}

	reloaded, err := repo.Load(ctx, key)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.owner != "alice" || reloaded.name != "Payroll" {
		t.Fatalf("state not rebuilt: owner=%q name=%q", reloaded.owner, reloaded.name)
	}
	if es.IsNew(reloaded) {
		t.Error("a persisted aggregate must not report as new")
	}
	if reloaded.Version() != 1 {
		t.Errorf("version: got %d want 1 (two events, zero-based)", reloaded.Version())
	}
}

// The aggregate consistency boundary: a stale expected revision is rejected.
func TestOptimisticConcurrency(t *testing.T) {
	repo, done := newRepo(t)
	defer done()
	ctx := context.Background()
	key := uniqueKey()

	seed, _ := repo.Load(ctx, key)
	es.Record(seed, &accountOpened{Owner: "alice"})
	if _, err := repo.Save(ctx, key, seed, "seed-"+key, meta()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Two readers load the same revision; both decide; the second must lose.
	first, _ := repo.Load(ctx, key)
	second, _ := repo.Load(ctx, key)

	es.Record(first, &accountRenamed{Name: "First"})
	if _, err := repo.Save(ctx, key, first, "first-"+key, meta()); err != nil {
		t.Fatalf("first writer: %v", err)
	}

	es.Record(second, &accountRenamed{Name: "Second"})
	_, err := repo.Save(ctx, key, second, "second-"+key, meta())
	if !errors.Is(err, es.ErrWrongExpectedRevision) {
		t.Fatalf("stale write must be rejected, got %v", err)
	}

	final, _ := repo.Load(ctx, key)
	if final.name != "First" {
		t.Fatalf("the losing write must not have landed: %q", final.name)
	}
}

// Deterministic event ids mean a retried command cannot duplicate events.
func TestRetryIsIdempotent(t *testing.T) {
	repo, done := newRepo(t)
	defer done()
	ctx := context.Background()
	key := uniqueKey()
	idem := "same-command-" + key

	a, _ := repo.Load(ctx, key)
	es.Record(a, &accountOpened{Owner: "alice"})
	if _, err := repo.Save(ctx, key, a, idem, meta()); err != nil {
		t.Fatalf("first append: %v", err)
	}

	// Replay the identical command. The client never saw the response, so it
	// retries from a fresh aggregate: same NoStream precondition, same derived
	// event ids.
	replay := es.NewAggregate(newAccount)
	es.Record(replay, &accountOpened{Owner: "alice"})
	if _, err := repo.Save(ctx, key, replay, idem, meta()); err != nil {
		t.Fatalf("replayed append must be accepted: %v", err)
	}

	final, _ := repo.Load(ctx, key)
	if got := final.Version(); got != 0 {
		t.Fatalf("replay duplicated events: version %d, want 0", got)
	}
}

func TestLoadMissingStreamIsNotAnError(t *testing.T) {
	repo, done := newRepo(t)
	defer done()

	a, err := repo.Load(context.Background(), uniqueKey())
	if err != nil {
		t.Fatalf("a missing stream must not be an error: %v", err)
	}
	if !es.IsNew(a) {
		t.Fatal("expected a new aggregate")
	}
}

func TestStreamNamingIsEnforced(t *testing.T) {
	repo, done := newRepo(t)
	defer done()
	// A dash would make KurrentDB read the category as only part of the name.
	if _, err := repo.Load(context.Background(), "has-dash"); !errors.Is(err, es.ErrDashInStreamKey) {
		t.Fatalf("got %v want ErrDashInStreamKey", err)
	}
}

func TestMain(m *testing.M) {
	fmt.Println("integration: requires a running KurrentDB (make up)")
	os.Exit(m.Run())
}
