//go:build integration

package projection_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	kurrentadapter "github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/notification/contract"
	notificationprojection "github.com/chronos/chronos-go/internal/modules/notification/projection"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type harness struct {
	pg    *pgadapter.DB
	pool  *pgxpool.Pool
	store *kurrentadapter.Store
	codec *eventcodec.JSON
	org   string
	subj  string
	sfx   string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), appDSN())
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	codec := eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())
	eventcodec.Register[contract.NotificationCreated](codec)
	eventcodec.Register[contract.NotificationRead](codec)
	eventcodec.Register[contract.PushSubscribed](codec)
	eventcodec.Register[contract.PushSubscriptionExpired](codec)
	eventcodec.Register[contract.PushSent](codec)

	client, err := kurrentadapter.Dial(envOr("KURRENTDB_CONNECTION_STRING", "kurrentdb://localhost:2113?tls=false"))
	if err != nil {
		t.Fatalf("kurrentdb: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	sfx := uuid.NewString()[:8]
	return &harness{
		pg: pgadapter.New(pool), pool: pool,
		store: kurrentadapter.NewStore(client, codec), codec: codec,
		org: "org_" + sfx, subj: "sub_" + sfx, sfx: sfx,
	}
}

// append writes one notification event and applies it through the real
// projection, exactly as the projector would.
func (h *harness) apply(t *testing.T, p projection.Projection, e eventsourcing.Event, meta eventsourcing.Metadata) {
	t.Helper()
	payload, err := h.codec.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	env := projection.Envelope{
		Type:    e.EventType(),
		Stream:  eventsourcing.StreamID("notification-" + h.sfx),
		Meta:    meta,
		Payload: payload,
	}
	// The same batch the runner uses: scope, rows and checkpoint in one
	// pipelined round trip (ADR-019).
	if err := h.pg.InTenantBatch(context.Background(),
		db.Tenant{OrgID: meta.OrgID, WorkspaceID: meta.WorkspaceID, Residency: "eu"},
		db.Replayable,
		func(w db.Writer) error { return p.Apply(context.Background(), w, env) },
	); err != nil {
		t.Fatalf("apply %s: %v", e.EventType(), err)
	}
}

func (h *harness) meta() eventsourcing.Metadata {
	return eventsourcing.Metadata{
		SchemaVersion: 1,
		OccurredAt:    time.Now().UTC(),
		OrgID:         h.org,
		WorkspaceID:   "ws_" + h.sfx,
		SubjectIDs:    []string{h.subj},
	}
}

// tenant reads through the ordinary scoped path, so what the test sees is what
// a request would see.
func (h *harness) tenant(t *testing.T, org string, fn func(context.Context, db.Querier) error) {
	t.Helper()
	ctx := db.WithTenant(context.Background(), db.Tenant{
		OrgID: org, WorkspaceID: "ws_" + h.sfx, UserID: "usr_test", Residency: "eu",
	})
	if err := h.pg.InTenantTx(ctx, fn); err != nil {
		t.Fatalf("read: %v", err)
	}
}

// ---------------------------------------------------------------------------

func TestFeedProjection(t *testing.T) {
	h := newHarness(t)
	feed := notificationprojection.NewFeed(h.codec)
	notificationID := "notif_" + h.sfx

	h.apply(t, feed, &contract.NotificationCreated{
		NotificationID: notificationID,
		SubjectID:      h.subj,
		Template:       "identity.password_changed",
		Class:          "security",
		OrgID:          h.org,
		WorkspaceID:    "ws_" + h.sfx,
		Data:           map[string]any{"Device": "Firefox"},
		OccurredAt:     time.Now().UTC(),
	}, h.meta())

	var template, class string
	var readAt *time.Time
	h.tenant(t, h.org, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx,
			`SELECT template, class, read_at FROM notification_feed WHERE notification_id = $1`,
			notificationID).Scan(&template, &class, &readAt)
	})
	if template != "identity.password_changed" || class != "security" {
		t.Fatalf("projected template=%q class=%q", template, class)
	}
	if readAt != nil {
		t.Error("a new notification must start unread")
	}

	// Reading it marks it read.
	readTime := time.Now().UTC().Truncate(time.Millisecond)
	h.apply(t, feed, &contract.NotificationRead{
		NotificationID: notificationID, SubjectID: h.subj, ReadAt: readTime,
	}, h.meta())

	h.tenant(t, h.org, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx,
			`SELECT read_at FROM notification_feed WHERE notification_id = $1`,
			notificationID).Scan(&readAt)
	})
	if readAt == nil {
		t.Fatal("the notification was not marked read")
	}
	first := *readAt

	// Reading twice must not move WHEN it was first seen — arbitration asks
	// exactly that question (ADR-026).
	h.apply(t, feed, &contract.NotificationRead{
		NotificationID: notificationID, SubjectID: h.subj,
		ReadAt: readTime.Add(time.Hour),
	}, h.meta())

	h.tenant(t, h.org, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx,
			`SELECT read_at FROM notification_feed WHERE notification_id = $1`,
			notificationID).Scan(&readAt)
	})
	if !readAt.Equal(first) {
		t.Errorf("a second read moved the first-read time from %v to %v", first, *readAt)
	}
}

// A projector is replayed on restart and on rebuild, so the same event WILL
// arrive twice. An insert would fail the second time and stall the projection.
func TestFeedProjectionIsIdempotent(t *testing.T) {
	h := newHarness(t)
	feed := notificationprojection.NewFeed(h.codec)
	notificationID := "notif_dup_" + h.sfx

	event := &contract.NotificationCreated{
		NotificationID: notificationID, SubjectID: h.subj,
		Template: "identity.welcome", Class: "transactional",
		OrgID: h.org, WorkspaceID: "ws_" + h.sfx, OccurredAt: time.Now().UTC(),
	}
	for range 3 {
		h.apply(t, feed, event, h.meta())
	}

	var rows int
	h.tenant(t, h.org, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx,
			`SELECT count(*) FROM notification_feed WHERE notification_id = $1`,
			notificationID).Scan(&rows)
	})
	if rows != 1 {
		t.Fatalf("three replays produced %d rows; a rebuild would duplicate the feed", rows)
	}
}

// A replay must not mark a read notification unread again.
func TestReplayDoesNotUnreadANotification(t *testing.T) {
	h := newHarness(t)
	feed := notificationprojection.NewFeed(h.codec)
	notificationID := "notif_reread_" + h.sfx

	created := &contract.NotificationCreated{
		NotificationID: notificationID, SubjectID: h.subj,
		Template: "identity.welcome", Class: "activity",
		OrgID: h.org, WorkspaceID: "ws_" + h.sfx, OccurredAt: time.Now().UTC(),
	}
	h.apply(t, feed, created, h.meta())
	h.apply(t, feed, &contract.NotificationRead{
		NotificationID: notificationID, SubjectID: h.subj, ReadAt: time.Now().UTC(),
	}, h.meta())

	// The created event arrives again, as it would during a rebuild.
	h.apply(t, feed, created, h.meta())

	var readAt *time.Time
	h.tenant(t, h.org, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx,
			`SELECT read_at FROM notification_feed WHERE notification_id = $1`,
			notificationID).Scan(&readAt)
	})
	if readAt == nil {
		t.Fatal("replaying the creation event marked a read notification unread again")
	}
}

// The feed is org-scoped like every other read model (ADR-020).
func TestFeedIsTenantIsolated(t *testing.T) {
	h := newHarness(t)
	feed := notificationprojection.NewFeed(h.codec)

	h.apply(t, feed, &contract.NotificationCreated{
		NotificationID: "notif_iso_" + h.sfx, SubjectID: h.subj,
		Template: "identity.welcome", Class: "activity",
		OrgID: h.org, WorkspaceID: "ws_" + h.sfx, OccurredAt: time.Now().UTC(),
	}, h.meta())

	var visible int
	h.tenant(t, "org_someone_else", func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx,
			`SELECT count(*) FROM notification_feed WHERE subject_id = $1`, h.subj).Scan(&visible)
	})
	if visible != 0 {
		t.Fatalf("another organization can read %d of this subject's notifications", visible)
	}
}

// ---------------------------------------------------------------------------

func TestPushSubscriptionProjection(t *testing.T) {
	h := newHarness(t)
	push := notificationprojection.NewPushSubscriptions(h.codec)
	endpoint := "https://push.example.test/" + h.sfx

	h.apply(t, push, &contract.PushSubscribed{
		SubscriptionID: "psub_" + h.sfx, SubjectID: h.subj,
		Endpoint: endpoint, P256dh: "key", Auth: "auth",
		UserAgent: "Firefox", SubscribedAt: time.Now().UTC(),
	}, h.meta())

	var active int
	h.tenant(t, h.org, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx,
			`SELECT count(*) FROM push_subscription WHERE subject_id = $1 AND expired_at IS NULL`,
			h.subj).Scan(&active)
	})
	if active != 1 {
		t.Fatalf("%d active subscriptions, want 1", active)
	}

	// A dead endpoint is marked expired, not deleted: "why did I stop getting
	// push?" is a real support question.
	h.apply(t, push, &contract.PushSubscriptionExpired{
		SubscriptionID: "psub_" + h.sfx, SubjectID: h.subj,
		Reason: "push service returned 410", ExpiredAt: time.Now().UTC(),
	}, h.meta())

	var total, stillActive int
	var reason *string
	h.tenant(t, h.org, func(ctx context.Context, q db.Querier) error {
		if err := q.QueryRow(ctx,
			`SELECT count(*) FROM push_subscription WHERE subject_id = $1`, h.subj).Scan(&total); err != nil {
			return err
		}
		if err := q.QueryRow(ctx,
			`SELECT count(*) FROM push_subscription WHERE subject_id = $1 AND expired_at IS NULL`,
			h.subj).Scan(&stillActive); err != nil {
			return err
		}
		return q.QueryRow(ctx,
			`SELECT expired_reason FROM push_subscription WHERE subscription_id = $1`,
			"psub_"+h.sfx).Scan(&reason)
	})
	if total != 1 {
		t.Errorf("the row was deleted rather than marked expired (%d rows)", total)
	}
	if stillActive != 0 {
		t.Error("an expired subscription is still being sent to")
	}
	if reason == nil || *reason == "" {
		t.Error("the expiry reason was not recorded, so support cannot answer why")
	}
}

// The same browser re-subscribing produces the same endpoint with a fresh id.
// Two rows would push to that device twice for every notification.
func TestResubscribingDoesNotDuplicateADevice(t *testing.T) {
	h := newHarness(t)
	push := notificationprojection.NewPushSubscriptions(h.codec)
	endpoint := "https://push.example.test/resub-" + h.sfx

	for i, id := range []string{"psub_a_" + h.sfx, "psub_b_" + h.sfx} {
		h.apply(t, push, &contract.PushSubscribed{
			SubscriptionID: id, SubjectID: h.subj, Endpoint: endpoint,
			P256dh: fmt.Sprintf("key%d", i), Auth: "auth",
			SubscribedAt: time.Now().UTC(),
		}, h.meta())
	}

	var rows int
	h.tenant(t, h.org, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx,
			`SELECT count(*) FROM push_subscription WHERE endpoint = $1`, endpoint).Scan(&rows)
	})
	if rows != 1 {
		t.Fatalf("one device produced %d subscription rows; it would receive every push twice", rows)
	}
}

// Re-subscribing after a 410 revives the row: the person granted permission
// again, and their earlier expiry is history.
func TestResubscribingRevivesAnExpiredDevice(t *testing.T) {
	h := newHarness(t)
	push := notificationprojection.NewPushSubscriptions(h.codec)
	endpoint := "https://push.example.test/revive-" + h.sfx
	id := "psub_revive_" + h.sfx

	h.apply(t, push, &contract.PushSubscribed{
		SubscriptionID: id, SubjectID: h.subj, Endpoint: endpoint,
		P256dh: "k", Auth: "a", SubscribedAt: time.Now().UTC(),
	}, h.meta())
	h.apply(t, push, &contract.PushSubscriptionExpired{
		SubscriptionID: id, SubjectID: h.subj,
		Reason: "410", ExpiredAt: time.Now().UTC(),
	}, h.meta())
	h.apply(t, push, &contract.PushSubscribed{
		SubscriptionID: id, SubjectID: h.subj, Endpoint: endpoint,
		P256dh: "k2", Auth: "a2", SubscribedAt: time.Now().UTC(),
	}, h.meta())

	var expiredAt *time.Time
	h.tenant(t, h.org, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx,
			`SELECT expired_at FROM push_subscription WHERE endpoint = $1`, endpoint).Scan(&expiredAt)
	})
	if expiredAt != nil {
		t.Fatal("re-granting permission left the subscription expired; the device would never be pushed to")
	}
}

// A rebuild empties the table from an UNSCOPED transaction, where RLS hides
// every row — DELETE would remove none (ADR-019).
func TestResetTruncates(t *testing.T) {
	h := newHarness(t)
	feed := notificationprojection.NewFeed(h.codec)

	h.apply(t, feed, &contract.NotificationCreated{
		NotificationID: "notif_reset_" + h.sfx, SubjectID: h.subj,
		Template: "identity.welcome", Class: "activity",
		OrgID: h.org, WorkspaceID: "ws_" + h.sfx, OccurredAt: time.Now().UTC(),
	}, h.meta())

	if err := h.pg.InSystemTx(context.Background(), func(ctx context.Context, q db.Querier) error {
		return feed.Reset(ctx, q)
	}); err != nil {
		t.Fatalf("reset: %v", err)
	}

	var remaining int
	h.tenant(t, h.org, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, `SELECT count(*) FROM notification_feed`).Scan(&remaining)
	})
	if remaining != 0 {
		t.Fatalf("%d rows survived the reset; the projection would rebuild on top of stale data", remaining)
	}
}

func appDSN() string {
	if v := os.Getenv("APP_DATABASE_URL"); v != "" {
		return v
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		envOr("POSTGRES_APP_USER", "chronos_app"), os.Getenv("POSTGRES_APP_PASSWORD"),
		envOr("POSTGRES_HOST", "localhost"), envOr("POSTGRES_PORT", "5432"),
		envOr("POSTGRES_DB", "chronos"))
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// One person, one browser, two organizations.
//
// This is not an edge case: a seat is per person per organization
// (workspace.md §2), so belonging to several is the normal shape, and a browser
// produces ONE push endpoint across all of them.
//
// Under the original schema the endpoint was globally unique and the upsert
// conflicted on it alone. ON CONFLICT DO UPDATE must READ the conflicting row to
// update it, RLS hid that row because it belonged to the other organization, and
// the insert failed outright:
//
//	ERROR: new row violates row-level security policy (USING expression)
//
// Not a duplicate, not a warning — that person simply received no web push in
// their second organization, and nothing reported it (migration 00006).
func TestPushEndpointIsPerOrganization(t *testing.T) {
	h := newHarness(t)
	p := notificationprojection.NewPushSubscriptions(h.codec)

	orgA := "org_a_" + h.sfx
	orgB := "org_b_" + h.sfx
	endpoint := "https://push.example/same-browser-" + h.sfx

	subscribe := func(org, subscriptionID string) contract.PushSubscribed {
		return contract.PushSubscribed{
			SubscriptionID: subscriptionID,
			SubjectID:      h.subj,
			Endpoint:       endpoint,
			P256dh:         "p256dh",
			Auth:           "auth",
			UserAgent:      "test",
			SubscribedAt:   time.Now().UTC(),
		}
	}

	metaFor := func(org string) eventsourcing.Metadata {
		m := h.meta()
		m.OrgID = org
		return m
	}

	h.apply(t, p, ptr(subscribe(orgA, "psb_a_"+h.sfx)), metaFor(orgA))
	// Before the fix this call failed with an RLS USING violation.
	h.apply(t, p, ptr(subscribe(orgB, "psb_b_"+h.sfx)), metaFor(orgB))

	// Both organizations must see their own live endpoint, and only their own.
	for org, want := range map[string]string{orgA: "psb_a_" + h.sfx, orgB: "psb_b_" + h.sfx} {
		var ids []string
		h.tenant(t, org, func(ctx context.Context, q db.Querier) error {
			rows, err := q.Query(ctx,
				`SELECT subscription_id FROM push_subscription
				 WHERE endpoint = $1 AND expired_at IS NULL`, endpoint)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					return err
				}
				ids = append(ids, id)
			}
			return rows.Err()
		})
		if len(ids) != 1 || ids[0] != want {
			t.Fatalf("%s sees %v, want exactly [%s]: this person cannot receive push there",
				org, ids, want)
		}
	}

	// Re-subscribing in one organization must still collapse onto the same row
	// rather than accumulating one per permission prompt — the property the
	// original global index was reaching for, now correctly scoped.
	h.apply(t, p, ptr(subscribe(orgA, "psb_a2_"+h.sfx)), metaFor(orgA))
	var count int
	h.tenant(t, orgA, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx,
			`SELECT count(*) FROM push_subscription WHERE endpoint = $1`, endpoint).Scan(&count)
	})
	if count != 1 {
		t.Fatalf("re-subscribing produced %d rows in one organization, want 1: "+
			"that device receives every notification %d times", count, count)
	}

	t.Cleanup(func() {
		_ = h.pg.InSystemTx(context.Background(), func(ctx context.Context, q db.Querier) error {
			_, err := q.Exec(ctx, `DELETE FROM push_subscription WHERE endpoint = $1`, endpoint)
			return err
		})
	})
}

func ptr[T any](v T) *T { return &v }
