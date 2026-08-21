//go:build integration

// Package profileit holds the end-to-end proof of the profile slice.
//
// Everything below this package has unit tests. Nothing had ever run as a
// whole: a signed upload target that a browser can actually POST to, an object
// SeaweedFS actually stores, a confirmation that becomes a KurrentDB event, a
// real projector turning that event into a `profile_view` row, and a
// `GetProfile` that hands back a signed URL those same bytes actually come back
// down. Each step is owned by a different package, and the seams between them
// are exactly where this repository has repeatedly found code that was built,
// tested, and connected to nothing.
//
// # What "the real stack" means here, and the one seam that is not real
//
// KurrentDB, PostgreSQL, OpenBao, SeaweedFS, the projection runner, the
// enforcement pipeline, protovalidate, the Connect codec and the generated
// client are all the production ones, constructed the way cmd/api constructs
// them, and reached over a real TCP listener.
//
// The AUTHENTICATOR is a stub. It is the one component this suite substitutes,
// and the reason is a module boundary rather than convenience: a real principal
// comes from an identity session, and building one here would make profile's
// integration suite depend on identity's registration flow, its second-factor
// enrolment and its token format — a coupling ADR-020's reasoning exists to
// prevent, and one that would make this suite fail for reasons that have
// nothing to do with profiles. What the stub produces is exactly what
// interceptor.SessionAuthenticator produces: a Principal with a KindUser
// subject and an assurance level. Everything downstream of it is production
// code.
package profileit_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	validate "connectrpc.com/validate"
	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/profile/v1/profilev1connect"
	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	kurrentadapter "github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	"github.com/chronos/chronos-go/internal/adapter/openbao"
	"github.com/chronos/chronos-go/internal/adapter/piivault"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	"github.com/chronos/chronos-go/internal/adapter/seaweedfs"
	"github.com/chronos/chronos-go/internal/modules/profile"
	profilepg "github.com/chronos/chronos-go/internal/modules/profile/adapter/postgres"
	profileapi "github.com/chronos/chronos-go/internal/modules/profile/api"
	"github.com/chronos/chronos-go/internal/modules/profile/app"
	"github.com/chronos/chronos-go/internal/modules/profile/domain"
	profileprojection "github.com/chronos/chronos-go/internal/modules/profile/projection"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/blob"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/cqrs"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/projection"
	srvconnect "github.com/chronos/chronos-go/internal/server/connect"
	"github.com/chronos/chronos-go/internal/server/interceptor"
	"github.com/chronos/chronos-go/internal/server/policy"
	"github.com/jackc/pgx/v5/pgxpool"
)

// h is the one harness for the package.
//
// A single API process, a single projector and a single object-store bucket are
// shared by every test, because starting them costs more than every assertion
// in this file put together.
//
// Test isolation comes from the SUBJECT instead. Every test invents its own
// pseudonym, and a pseudonym scopes a profile stream, a vault row, a projection
// row and an avatar key prefix all at once — so two tests running side by side
// cannot see each other's state through any of the four.
var h *harness

type harness struct {
	suffix string

	pool  *pgxpool.Pool
	pg    *pgadapter.DB
	store *kurrentadapter.Store
	codec *eventcodec.JSON

	// upcasters is the ONE registry this suite has, shared by the codec and by
	// the aggregate repository.
	//
	// A second, empty one here is not a hypothetical mistake: it was written
	// that way first, and every SECOND update to one subject failed to load its
	// own aggregate — the stored event declares schema version 1 and a registry
	// that has never heard of the type demands a 0-to-1 upcaster that should not
	// exist. The first write succeeded, so nothing looked wrong until a profile
	// was edited twice (ADR-029, and the same shape as the defect
	// eventsourcing.StampSchemaVersion documents).
	upcasters *eventsourcing.UpcasterRegistry

	blobs *seaweedfs.Store
	vault *piivault.Vault

	client profilev1connect.ProfileServiceClient
	authn  *stubAuthn

	// projector is driven on demand rather than left running, so a test can say
	// exactly when the read model has caught up instead of polling a table and
	// hoping.
	projectorOnce sync.Mutex
}

func TestMain(m *testing.M) {
	code, err := run(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "profileit:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func run(m *testing.M) (int, error) {
	ctx := context.Background()

	var b [4]byte
	if _, err := io.ReadFull(ids.Entropy(), b[:]); err != nil {
		return 0, fmt.Errorf("entropy: %w", err)
	}
	h = &harness{suffix: hex.EncodeToString(b[:])}

	pool, err := pgxpool.New(ctx, appDSN())
	if err != nil {
		return 0, fmt.Errorf("postgres: %w", err)
	}
	defer pool.Close()
	h.pool = pool
	h.pg = pgadapter.New(pool)

	// The SAME registry the API and the projector share. A second one here would
	// let an event be registered for writing and not for reading, which is the
	// exact drift internal/modules/profile/module.go exists to prevent — so this
	// suite uses that module's own registration rather than listing the type.
	h.upcasters = eventsourcing.NewUpcasterRegistry()
	profile.RegisterSchemas(h.upcasters)
	h.codec = eventcodec.NewJSON(h.upcasters)
	profile.RegisterEvents(h.codec)

	client, err := kurrentadapter.Dial(kurrentDSN())
	if err != nil {
		return 0, fmt.Errorf("kurrentdb: %w", err)
	}
	defer func() { _ = client.Close() }()
	h.store = kurrentadapter.NewStore(client, h.codec)

	bao, err := openbao.Dial(envOr("OPENBAO_ADDR", "http://localhost:8200"),
		envOr("OPENBAO_DEV_TOKEN", "chronos_dev_root_token"))
	if err != nil {
		return 0, fmt.Errorf("openbao: %w", err)
	}
	h.vault = piivault.New(h.pg,
		openbao.NewKeyRing(bao, envOr("OPENBAO_KEK_NAME", "chronos-kek")))

	limits, err := blob.Limits{
		MaxBytes:            domain.MaxAvatarBytes,
		AllowedContentTypes: domain.AllowedAvatarTypes(),
		MaxExpiry:           15 * time.Minute,
	}.Defaults()
	if err != nil {
		return 0, fmt.Errorf("blob limits: %w", err)
	}
	h.blobs = seaweedfs.New(seaweedfs.Config{
		Endpoint:  envOr("S3_ENDPOINT", "http://localhost:8333"),
		Region:    envOr("S3_REGION", "us-east-1"),
		Bucket:    envOr("S3_BUCKET", "chronos"),
		AccessKey: envOr("S3_ACCESS_KEY", "chronos"),
		SecretKey: envOr("S3_SECRET_KEY", "chronos-secret-key"),
		Limits:    limits,
	}, clock.System{})
	if err := h.blobs.EnsureBucket(ctx); err != nil {
		return 0, fmt.Errorf("bucket: %w", err)
	}

	stop, err := h.startAPI()
	if err != nil {
		return 0, fmt.Errorf("api: %w", err)
	}
	defer stop()

	return m.Run(), nil
}

// startAPI assembles the profile service the way cmd/api would and serves it
// over a real listener.
//
// This function IS the wiring reported for cmd/api, expressed as code: if the
// composition root ever drifts from it, this suite is what fails.
func (h *harness) startAPI() (func(), error) {
	reads, err := profilepg.NewReadModel(h.pg)
	if err != nil {
		return nil, err
	}
	repo := eventsourcing.NewRepository[*domain.Profile](
		h.store, h.codec, h.upcasters, domain.Category, domain.NewProfile)

	queries, err := app.NewQueries(app.QueriesDeps{
		Reader: reads, Vault: h.vault, Avatars: h.blobs,
	})
	if err != nil {
		return nil, err
	}
	updates, err := app.NewUpdates(app.UpdatesDeps{
		Repo: repo, Vault: h.vault, Avatars: h.blobs, Queries: queries, Clock: clock.System{},
	})
	if err != nil {
		return nil, err
	}
	avatars, err := app.NewAvatars(app.AvatarsDeps{Store: h.blobs})
	if err != nil {
		return nil, err
	}
	svc, err := profileapi.New(profileapi.Deps{
		Queries: queries, Updates: updates, Avatars: avatars,
	})
	if err != nil {
		return nil, err
	}

	policies, err := policy.Load(profilev1connect.ProfileServiceName)
	if err != nil {
		return nil, err
	}
	once, err := cqrs.NewOnce(cqrs.OnceDeps{
		Store: pgadapter.NewIdempotency(h.pg), TTL: time.Minute,
	})
	if err != nil {
		return nil, err
	}
	idem, err := interceptor.NewIdempotency(once)
	if err != nil {
		return nil, err
	}

	h.authn = &stubAuthn{}
	gates, err := interceptor.NewGates(interceptor.Deps{
		Policies: policies, Authn: h.authn, Idempotency: idem,
	})
	if err != nil {
		return nil, err
	}

	opts := []connect.HandlerOption{
		connect.WithInterceptors(
			interceptor.NewErrorLog(slog.New(slog.NewTextHandler(io.Discard, nil)), nil),
			gates,
			validate.NewInterceptor(),
		),
	}
	opts = append(opts, srvconnect.JSONOptions()...)

	_, handler := profilev1connect.NewProfileServiceHandler(svc, opts...)
	srv := httptest.NewServer(handler)
	h.client = profilev1connect.NewProfileServiceClient(srv.Client(), srv.URL)
	return srv.Close, nil
}

// stubAuthn is the one substituted component. See the package comment.
type stubAuthn struct {
	mu      sync.Mutex
	subject string
}

func (s *stubAuthn) Authenticate(context.Context, interceptor.Header) (interceptor.Principal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subject == "" {
		return interceptor.Principal{}, errors.New("no session")
	}
	return interceptor.Principal{
		Subject: authz.Principal{Kind: authz.KindUser, ID: s.subject},
		AAL:     optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1,
	}, nil
}

// as runs fn with a given pseudonym authenticated.
//
// The subject is set on the SERVER's authenticator rather than carried in a
// header, which is a deliberately faithful shape: a request cannot name its own
// caller, here or in production.
func (h *harness) as(subjectID string) {
	h.authn.mu.Lock()
	h.authn.subject = subjectID
	h.authn.mu.Unlock()
}

// newSubject invents a pseudonym for one test.
func newSubject(t *testing.T) string {
	t.Helper()
	return ids.New[ids.Subject](time.Now().UTC(), ids.Entropy()).String()
}

// ---------------------------------------------------------------------------
// Driving the projector
// ---------------------------------------------------------------------------

// catchUp runs the REAL projector until the profile of every named subject is
// present at or after the given instant.
//
// The real one, from internal/modules/profile/projection, driven by the same
// platform/projection runner cmd/projector uses. Nothing in this file writes
// `profile_view` — which is the point: a test that seeded the table itself
// would prove the query works and say nothing about whether the projection
// does.
func (h *harness) catchUp(t *testing.T, subjectID string, notBefore time.Time) {
	t.Helper()
	h.projectorOnce.Lock()
	defer h.projectorOnce.Unlock()

	runner := projection.NewRunner(profileprojection.NewProfile(h.codec), h.projectionDeps())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()

	deadline := time.After(45 * time.Second)
	for {
		select {
		case err := <-done:
			t.Fatalf("the projector stopped early: %v", err)
		case <-deadline:
			t.Fatalf("the projection did not reach %s for %s within the deadline",
				notBefore, subjectID)
		case <-time.After(100 * time.Millisecond):
			row, err := h.row(t, subjectID)
			if err != nil {
				t.Fatalf("reading profile_view: %v", err)
			}
			if row.exists && !row.updatedAt.Before(notBefore) {
				cancel()
				if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
					t.Fatalf("projector shutdown: %v", err)
				}
				return
			}
		}
	}
}

func (h *harness) projectionDeps() projection.Deps {
	return projection.Deps{
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
		Holder:         "profileit-" + h.suffix,
		LeaseRetry:     50 * time.Millisecond,
		SubscribeRetry: 50 * time.Millisecond,
	}
}

// ---------------------------------------------------------------------------
// Reading the two systems of record directly
// ---------------------------------------------------------------------------

type viewRow struct {
	exists                       bool
	displayNameSet               bool
	localeSet, timezoneSet       bool
	avatarKey, avatarContentType string
	avatarSize                   int64
	updatedAt                    time.Time
}

// row reads `profile_view` with SQL, not through the module's own reader.
//
// Deliberately: a test that read through the adapter under test would agree
// with it about a column it had misnamed.
func (h *harness) row(t *testing.T, subjectID string) (viewRow, error) {
	t.Helper()
	var out viewRow
	err := h.pg.InSystemTx(context.Background(), func(ctx context.Context, q db.Querier) error {
		rows, err := q.Query(ctx, `
			SELECT display_name_set, locale_set, timezone_set,
			       avatar_object_key, avatar_content_type, avatar_size_bytes, updated_at
			FROM profile_view WHERE subject_id = $1`, subjectID)
		if err != nil {
			return err
		}
		defer rows.Close()
		if !rows.Next() {
			return rows.Err()
		}
		out.exists = true
		return rows.Scan(&out.displayNameSet, &out.localeSet, &out.timezoneSet,
			&out.avatarKey, &out.avatarContentType, &out.avatarSize, &out.updatedAt)
	})
	return out, err
}

// events reads one subject's profile stream straight out of KurrentDB, still
// encoded.
//
// The LOG, not the projection. ADR-052 is the reason that distinction is worth
// the extra function: a unique index in a read model can conceal a duplicate
// and stall the projector, so an assertion about "how many changes happened"
// that reads a table can be satisfied by a table that is quietly wrong.
func (h *harness) events(t *testing.T, subjectID string) []eventsourcing.RecordedEvent {
	t.Helper()
	stream, err := eventsourcing.NewStreamID(domain.Category, domain.StreamKey(subjectID))
	if err != nil {
		t.Fatalf("stream id: %v", err)
	}
	recorded, err := h.store.ReadStream(context.Background(), stream, 0)
	if err != nil {
		if errors.Is(err, eventsourcing.ErrStreamNotFound) {
			return nil
		}
		t.Fatalf("reading %s: %v", stream, err)
	}
	return recorded
}

// ---------------------------------------------------------------------------
// The browser's half of the upload
// ---------------------------------------------------------------------------

// upload POSTs bytes to the object store exactly as a browser would: a
// multipart form carrying the grant's fields verbatim, then the file.
//
// This function is the proof that no image reaches the Go server. The bytes go
// from here to SeaweedFS over a separate HTTP connection that the API process
// is not part of.
func upload(t *testing.T, url string, fields map[string]string, data []byte) {
	t.Helper()

	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := form.WriteField(k, v); err != nil {
			t.Fatalf("writing field %s: %v", k, err)
		}
	}
	// The file part goes LAST. S3's POST policy requires it, and a form that put
	// it first is rejected with a signature error that says nothing about order.
	part, err := form.CreateFormFile("file", "avatar")
	if err != nil {
		t.Fatalf("file part: %v", err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatalf("writing file: %v", err)
	}
	if err := form.Close(); err != nil {
		t.Fatalf("closing form: %v", err)
	}

	req, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost, url, &body)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", form.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("uploading: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		got, _ := io.ReadAll(resp.Body)
		t.Fatalf("the object store refused the upload: %s\n%s", resp.Status, got)
	}
}

// download fetches a signed URL, as a browser rendering an avatar would.
func download(t *testing.T, url string) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("downloading: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the signed URL returned %s", resp.Status)
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the avatar: %v", err)
	}
	return got
}

// withKey attaches the idempotency header every mutating RPC needs.
func withKey[T any](req *connect.Request[T], key string) *connect.Request[T] {
	req.Header().Set(interceptor.IdempotencyHeader, key)
	return req
}

// pngBytes is a one-pixel PNG. Real bytes with a real signature, so a store
// sniffing the content type sees what the policy declared.
var pngBytes = []byte{
	0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
	0x00, 0x00, 0x00, 0x0d, 'I', 'H', 'D', 'R',
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
	0x89, 0x00, 0x00, 0x00, 0x0a, 'I', 'D', 'A', 'T',
	0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05,
	0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00,
	0x00, 0x00, 'I', 'E', 'N', 'D', 0xae, 0x42, 0x60, 0x82,
}

func ptr[T any](v T) *T { return &v }

func appDSN() string {
	if v := os.Getenv("APP_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://chronos_app:chronos_app_dev_password@localhost:5432/chronos?sslmode=disable"
}

func kurrentDSN() string {
	if v := os.Getenv("KURRENTDB_URL"); v != "" {
		return v
	}
	return "kurrentdb://localhost:2113?tls=false"
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
