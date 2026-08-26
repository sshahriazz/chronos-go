//go:build integration

package projection_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	kurrentadapter "github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/organization"
	orgcontract "github.com/chronos/chronos-go/internal/modules/organization/contract"
	orgdomain "github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/modules/workspace"
	wscontract "github.com/chronos/chronos-go/internal/modules/workspace/contract"
	wsdomain "github.com/chronos/chronos-go/internal/modules/workspace/domain"
	operatorprojection "github.com/chronos/chronos-go/internal/operator/projection"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// TestTheCustomerDirectoryIsActuallyBuilt exists because an empty directory and
// a broken one look identical.
//
// This environment has no organizations, so `operator_customer_list` is empty
// and every panel that reads it says so — which is exactly what a projection
// subscribed to the wrong streams would produce. WORKFLOW.md's rule applies
// directly: ask what the test would do if the feature were deleted. Reading the
// table proves nothing; appending real events and watching the row appear
// proves the filter, the handlers and the SQL together.
//
// # The filter is what this is really for
//
// Membership events live on `membership-`, NOT on `workspace-`: a membership is
// its own aggregate so that adding a person does not contend with every other
// change to the workspace. A filter of the two obvious categories compiles,
// runs, and produces a directory whose member count is permanently zero — which
// reads as "this customer has nobody" rather than as a bug. The member-count
// assertion below is the one that catches it.
func TestTheCustomerDirectoryIsActuallyBuilt(t *testing.T) {
	h := newHarness(t)

	orgID := "org_" + ids.New[ids.Org](time.Now(), ids.Entropy()).String()[4:]
	wsID := "ws_" + ids.New[ids.Workspace](time.Now(), ids.Entropy()).String()[3:]
	now := time.Now().UTC().Truncate(time.Microsecond)

	// Three events on THREE different categories, which is the point.
	h.append(t, orgdomain.Category, orgID, orgID, &orgcontract.OrganizationCreated{
		OrgID: orgID, Name: "Kettle & Sons", Slug: "kettle-and-sons",
		OwnerID: "subj_owner", CreatedAt: now,
	})
	h.append(t, wsdomain.Category, wsID, orgID, &wscontract.WorkspaceCreated{
		WorkspaceID: wsID, OrgID: orgID, Name: "Main", CreatedBy: "subj_owner", CreatedAt: now,
	})
	h.append(t, wsdomain.MembershipCategory, wsID+":subj_owner", orgID, &wscontract.MemberJoined{
		WorkspaceID: wsID, OrgID: orgID, SubjectID: "subj_owner",
		SeatConsumed: true, JoinedAt: now,
	})

	h.runUntil(t, orgID, func(c customer) bool {
		return c.workspaces == 1 && c.members == 1
	})

	got := h.read(t, orgID)

	if got.name != "Kettle & Sons" {
		t.Errorf("org_name = %q, want %q", got.name, "Kettle & Sons")
	}
	if got.slug != "kettle-and-sons" {
		t.Errorf("slug = %q", got.slug)
	}
	if got.state != "active" {
		t.Errorf("lifecycle_state = %q, want active", got.state)
	}
	if got.workspaces != 1 {
		t.Errorf("workspace_count = %d, want 1", got.workspaces)
	}
	if got.members != 1 {
		t.Errorf("member_count = %d, want 1.\n\n"+
			"Zero here is the failure this test exists for: membership events live on "+
			"the `membership-` category, and a filter that names only organization and "+
			"workspace produces a directory that reads as 'this customer has nobody'.",
			got.members)
	}
	if got.lastActive == nil {
		t.Error("last_active_at is unset; the workspace and the membership both touch it")
	}

	// # The replay is the assertion that matters
	//
	// The first version of this projection maintained the counts with
	// `count = count + 1`, and this test read back 3 and 3 for one workspace
	// and one member — because the projector replayed and because the live
	// plane was applying the same events to the same table.
	//
	// Both are ordinary. A projector is replayed on every restart and on every
	// rebuild, and two of them run against one table during any rolling
	// deploy. So the property is not "it counted right once", it is "applying
	// the same events again changes nothing".
	h.replayFromZero(t, orgID)

	after := h.read(t, orgID)
	if after.workspaces != got.workspaces || after.members != got.members {
		t.Fatalf("a replay changed the counts: %d/%d became %d/%d.\n\n"+
			"A projection handler that accumulates is not replay-safe, and a "+
			"directory whose numbers grow on every restart is one a support "+
			"engineer has no reason to distrust.",
			got.workspaces, got.members, after.workspaces, after.members)
	}
}

// TestASuspensionReachesTheDirectoryAndIsCleared covers the support context
// operator.md §2 asks for — "is this org suspended, why, and since when" — and
// the clear on the way back, which is the half that is easy to omit.
//
// A stale "payment failed" beside an active customer is what makes a support
// engineer open with an apology for a problem that is already fixed.
func TestASuspensionReachesTheDirectoryAndIsCleared(t *testing.T) {
	h := newHarness(t)

	orgID := "org_" + ids.New[ids.Org](time.Now(), ids.Entropy()).String()[4:]
	now := time.Now().UTC().Truncate(time.Microsecond)

	h.append(t, orgdomain.Category, orgID, orgID, &orgcontract.OrganizationCreated{
		OrgID: orgID, Name: "Braithwaite Ltd", Slug: "braithwaite",
		OwnerID: "subj_owner", CreatedAt: now,
	})
	h.append(t, orgdomain.Category, orgID, orgID, &orgcontract.OrganizationSuspended{
		OrgID: orgID, Reason: orgcontract.PaymentFailed, SuspendedAt: now.Add(time.Minute),
	})

	h.runUntil(t, orgID, func(c customer) bool { return c.state == "suspended" })

	got := h.read(t, orgID)
	if got.suspendedAt == nil {
		t.Error("suspended_at is unset on a suspended customer")
	}
	if got.reason != string(orgcontract.PaymentFailed) {
		t.Errorf("suspension_reason = %q, want %q", got.reason, orgcontract.PaymentFailed)
	}

	h.append(t, orgdomain.Category, orgID, orgID, &orgcontract.OrganizationActivated{
		OrgID: orgID, ActivatedAt: now.Add(2 * time.Minute),
	})

	h.runUntil(t, orgID, func(c customer) bool { return c.state == "active" })

	got = h.read(t, orgID)
	if got.suspendedAt != nil {
		t.Error("suspended_at survived reactivation; a support engineer would read a " +
			"resolved problem as current")
	}
	if got.reason != "" {
		t.Errorf("suspension_reason = %q after reactivation", got.reason)
	}
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

type customer struct {
	name, slug, state, reason string
	workspaces, members       int32
	suspendedAt, lastActive   *time.Time
}

type harness struct {
	pool   *pgxpool.Pool
	pg     *pgadapter.DB
	store  *kurrentadapter.Store
	codec  *eventcodec.JSON
	suffix string
	view   string
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	var b [4]byte
	if _, err := io.ReadFull(ids.Entropy(), b[:]); err != nil {
		t.Fatalf("entropy: %v", err)
	}
	suffix := hex.EncodeToString(b[:])

	// The OPERATOR role, because that is what cmd/operator runs these
	// projections as — and it is the only role granted the table they write.
	// Running this as chronos_app would pass on a machine where the revoke in
	// migration 00037 had not been applied, which is precisely the case the
	// isolation tests exist to catch.
	pool, err := pgxpool.New(t.Context(), operatorDSN())
	if err != nil {
		t.Fatalf("connecting as the operator role: %v", err)
	}
	t.Cleanup(pool.Close)

	upcasters := eventsourcing.NewUpcasterRegistry()
	codec := eventcodec.NewJSON(upcasters)
	organization.RegisterEvents(codec)
	organization.RegisterSchemas(upcasters)
	workspace.RegisterEvents(codec)
	workspace.RegisterSchemas(upcasters)

	client, err := kurrentadapter.Dial(kurrentDSN())
	if err != nil {
		t.Fatalf("kurrentdb: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	h := &harness{
		pool: pool, pg: pgadapter.New(pool),
		store: kurrentadapter.NewStore(client, codec),
		codec: codec, suffix: suffix,
		// ONE fixed name across every run, not a per-run one.
		//
		// The name keys the checkpoint row and the single-writer lease. A
		// per-run name would leave a checkpoint row behind after every run and
		// this role cannot delete them — chronos_operator holds SELECT, INSERT
		// and UPDATE on projection_checkpoint and deliberately not DELETE,
		// because a projector has no business removing another's position.
		//
		// It still does not fight the live plane: the lease is per NAME, and
		// this is not the production one. Two tests in this package share it and
		// run sequentially, which the lease retry absorbs.
		view: operatorprojection.CustomersName + "_integration_test",
	}
	return h
}

// rewind sets this view's checkpoint back to the start of the log.
//
// An UPDATE rather than a DELETE, because the operator role cannot delete a
// checkpoint — see the comment on `view` above. Zeroing the position has the
// same effect for a test and stays inside the grants the plane actually runs
// with, which is the point: a test that needed wider privileges than the code
// would be proving something about a database this system never connects to.
func (h *harness) rewind(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := h.pg.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx, `
			UPDATE projection_checkpoint
			SET commit_position = 0, prepare_position = 0, events_processed = 0
			WHERE name = $1`, h.view)
		return err
	}); err != nil {
		t.Fatalf("rewinding the checkpoint: %v", err)
	}
}

// namedCustomers wraps the real projection under a test-scoped NAME.
//
// The name keys the checkpoint row and the single-writer lease, so reusing the
// production one would make this test fight cmd/operator for the lease on a
// developer machine where both are running — and then wind the real
// projection's checkpoint backwards.
type namedCustomers struct {
	projection.Projection
	name string
}

func (n namedCustomers) Name() string { return n.name }

func (h *harness) append(t *testing.T, category eventsourcing.Category, key, org string, e eventsourcing.Event) {
	t.Helper()

	stream, err := eventsourcing.NewStreamID(category, key)
	if err != nil {
		t.Fatalf("stream id: %v", err)
	}
	_, err = h.store.Append(t.Context(), stream, eventsourcing.AnyRevision(),
		[]eventsourcing.PendingEvent{{
			ID:    eventsourcing.DeriveEventID(h.suffix+key+e.EventType(), 0),
			Event: e,
			Meta: eventsourcing.Metadata{
				SchemaVersion: 1,
				OccurredAt:    time.Now().UTC(),
				OrgID:         org,
				Residency:     "eu",
			},
		}})
	if err != nil {
		t.Fatalf("appending %s: %v", e.EventType(), err)
	}
}

// runUntil drives the projector until the row satisfies `done`, or fails.
//
// It polls the ROW rather than the checkpoint, because the checkpoint moves for
// every event the filter matched — including the ones from other tests and from
// the rest of this environment's log — and "the projector advanced" is not the
// question. "The row is what these events should have made it" is.
func (h *harness) runUntil(t *testing.T, orgID string, done func(customer) bool) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	view := namedCustomers{
		Projection: operatorprojection.NewCustomers(h.codec),
		name:       h.view,
	}
	runner := projection.NewRunner(view, projection.Deps{
		Subscriber:     h.store,
		Codec:          h.codec,
		Categories:     h.store,
		Types:          h.store,
		Batch:          h.pg,
		TX:             h.pg,
		Checkpoints:    pgadapter.Checkpoints{},
		Lease:          pgadapter.NewLease(h.pool),
		Clock:          clock.System{},
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Holder:         "operator-projection-test-" + h.suffix,
		LeaseRetry:     50 * time.Millisecond,
		SubscribeRetry: 50 * time.Millisecond,
	})

	errs := make(chan error, 1)
	go func() { errs <- runner.Run(ctx) }()

	deadline := time.After(40 * time.Second)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()

	for {
		select {
		case err := <-errs:
			t.Fatalf("the projector stopped: %v", err)
		case <-deadline:
			cancel()
			t.Fatalf("the row for %s never reached the expected state.\n\n"+
				"Either the filter does not cover the categories these events were "+
				"appended to, or a handler is missing.", orgID)
		case <-tick.C:
			if c, ok := h.tryRead(orgID); ok && done(c) {
				cancel()
				<-errs
				return
			}
		}
	}
}

// replayFromZero drops this view's checkpoint and runs it again, so every event
// in the log is applied a second time.
//
// It deliberately does NOT call Rebuild: a rebuild truncates first, which would
// test a different and easier property. What has to hold is that applying the
// same events ON TOP of the rows they already produced changes nothing — which
// is what a restart does.
func (h *harness) replayFromZero(t *testing.T, orgID string) {
	t.Helper()

	h.rewind(t)

	// Wait for the row to be present again rather than for a count to change —
	// the whole point is that nothing changes, so there is no edge to wait on.
	// One full pass over the log is enough, and runUntil's deadline bounds it.
	h.runUntil(t, orgID, func(c customer) bool { return c.name != "" })
}

func (h *harness) read(t *testing.T, orgID string) customer {
	t.Helper()
	c, ok := h.tryRead(orgID)
	if !ok {
		t.Fatalf("no row for %s", orgID)
	}
	return c
}

func (h *harness) tryRead(orgID string) (customer, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var (
		c              customer
		reason         *string
		suspended, act *time.Time
	)
	err := h.pg.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, `
			SELECT org_name, slug, lifecycle_state, workspace_count, member_count,
			       suspended_at, suspension_reason, last_active_at
			FROM operator_customer_list WHERE org_id = $1`, orgID).
			Scan(&c.name, &c.slug, &c.state, &c.workspaces, &c.members,
				&suspended, &reason, &act)
	})
	if err != nil {
		return customer{}, false
	}
	if reason != nil {
		c.reason = *reason
	}
	c.suspendedAt = suspended
	c.lastActive = act
	return c, true
}

func operatorDSN() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		envOr("POSTGRES_OPERATOR_USER", "chronos_operator"),
		envOr("POSTGRES_OPERATOR_PASSWORD", "chronos_operator_dev_password"),
		envOr("POSTGRES_HOST", "localhost"),
		envOr("POSTGRES_PORT", "5432"),
		envOr("POSTGRES_DB", "chronos"))
}

func kurrentDSN() string {
	return envOr("KURRENTDB_CONNECTION_STRING", "kurrentdb://localhost:2113?tls=false")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
