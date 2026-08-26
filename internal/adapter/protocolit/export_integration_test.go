//go:build integration

package protocolit_test

import (
	"context"
	"strings"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"

	compliancev1 "github.com/chronos/chronos-go/gen/proto/chronos/compliance/v1"
	"io"
	"net/http"

	"github.com/chronos/chronos-go/internal/adapter/piivault"
	compliancepg "github.com/chronos/chronos-go/internal/modules/compliance/adapter/postgres"
	complianceapp "github.com/chronos/chronos-go/internal/modules/compliance/app"
	compliancedomain "github.com/chronos/chronos-go/internal/modules/compliance/domain"
	profiledomain "github.com/chronos/chronos-go/internal/modules/profile/domain"
	"github.com/chronos/chronos-go/internal/platform/blob"
	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/pii"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

// awaitExport polls until a request reaches one of the states it is waiting for.
//
// It polls the REAL endpoint rather than the table, which is the point: the
// question is whether a person asking "is my data ready yet" gets a true answer,
// and that path runs through the handler, the projection and the object store.
func awaitExport(
	t *testing.T, bearer, exportID string, want ...compliancev1.DataExportStatus,
) *compliancev1.GetDataExportResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	deadline := time.Now().Add(60 * time.Second)
	var last *compliancev1.GetDataExportResponse
	for time.Now().Before(deadline) {
		res, err := h.compliance.GetDataExport(ctx, authed(
			&compliancev1.GetDataExportRequest{ExportId: exportID}, bearer))
		if err != nil {
			t.Fatalf("GetDataExport: %v\n%s", err, h.serverLogs())
		}
		last = res.Msg
		for _, w := range want {
			if res.Msg.GetStatus() == w {
				return res.Msg
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("the export never reached %v within 60s; it is %v. Either no workflow is "+
		"building it, or the projection never applied the outcome\n%s",
		want, last.GetStatus(), h.serverLogs())
	return nil
}

// A DATA-SUBJECT REQUEST IS RECORDED, AND POLLABLE, AGAINST THE REAL STACK.
//
// # What only this test can settle
//
// Every layer below has unit tests and the workflow runs under Temporal's own
// test environment. None of that exercises the parts that broke in the
// email-change slice: a CHECK constraint the events violate, a projection that
// never applied, a handler wired to nothing. Those fail here and nowhere else.
//
// It asserts the REQUEST half unconditionally, because that is what cmd/api
// alone can do. The bundle is built by cmd/worker, which this suite does not
// run — so the completion is asserted only when something else in the
// environment is running the worker, and the test says which half it verified.
func TestADataExportRequestIsRecordedAndPollable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	account := h.disposableAccount(t, "export")

	res, err := h.compliance.ExportMyData(ctx, authed(
		&compliancev1.ExportMyDataRequest{}, account.bearer))
	if err != nil {
		t.Fatalf("ExportMyData: %v\n%s", err, h.serverLogs())
	}
	exportID := res.Msg.GetExportId()
	if exportID == "" {
		t.Fatal("the request returned no export id, so the person has nothing to poll with")
	}
	if !strings.HasPrefix(exportID, "export_") {
		t.Errorf("the export id is %q and does not carry its prefix (ADR-030)", exportID)
	}
	// PENDING and no link: the bundle does not exist yet, and a response that
	// claimed otherwise would send somebody to fetch nothing.
	if res.Msg.GetStatus() != compliancev1.DataExportStatus_DATA_EXPORT_STATUS_PENDING {
		t.Errorf("a freshly accepted request reports %v", res.Msg.GetStatus())
	}

	// The PROJECTION applied it. This is the half that would silently not exist
	// if the projection were missing from the projector's registry — the request
	// would be accepted, the log would agree, and the person's poll would answer
	// "not found" forever.
	got := awaitExport(t, account.bearer,
		exportID,
		compliancev1.DataExportStatus_DATA_EXPORT_STATUS_PENDING,
		compliancev1.DataExportStatus_DATA_EXPORT_STATUS_READY,
		compliancev1.DataExportStatus_DATA_EXPORT_STATUS_FAILED,
	)
	if got.GetRequestedAt() == nil {
		t.Error("the projected request carries no requested_at; Article 15's one-month " +
			"clock starts at a time nothing records")
	}

	switch got.GetStatus() {
	case compliancev1.DataExportStatus_DATA_EXPORT_STATUS_PENDING:
		t.Logf("the request is recorded and pending; cmd/worker is not running in this "+
			"environment, so the BUNDLE half is not verified here (export %s)", exportID)
	case compliancev1.DataExportStatus_DATA_EXPORT_STATUS_READY:
		if got.GetManifestUrl() == "" {
			t.Fatal("a READY export carries no manifest URL; the person is told their " +
				"data is ready and has nothing to fetch")
		}
		if !strings.HasPrefix(got.GetManifestUrl(), "https://") {
			t.Errorf("the manifest URL is %q, which is not a signed HTTPS link",
				got.GetManifestUrl())
		}
		if got.GetExpiresAt() == nil {
			t.Error("the links carry no expiry; a bearer capability for the most " +
				"concentrated personal data we hold must not be durable")
		}
		t.Logf("the bundle is ready with %d file(s)", len(got.GetFiles()))
	default:
		t.Fatalf("the export FAILED with %q", got.GetFailureReason())
	}
}

// A RETRY WITH THE SAME KEY IS ONE REQUEST.
//
// The export id is derived from the Idempotency-Key, so a client that retried a
// call whose answer it never saw recovers the same id. Without it, one person
// pressing a button twice gets two workflows, two bundles and two "your export
// is ready" mails — and cannot find the first request at all.
//
// Asserted against the real stack because the derivation has to survive the
// whole round trip: the header, the interceptor, the handler and the append.
func TestRetryingAnExportRequestReturnsTheSameID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	account := h.disposableAccount(t, "export-retry")
	req := func(key string) string {
		t.Helper()
		r := connectrpc.NewRequest(&compliancev1.ExportMyDataRequest{})
		r.Header().Set(interceptor.IdempotencyHeader, key)
		r.Header().Set(interceptor.AuthorizationHeader, "Bearer "+account.bearer)
		res, err := h.compliance.ExportMyData(ctx, r)
		if err != nil {
			t.Fatalf("ExportMyData(%s): %v\n%s", key, err, h.serverLogs())
		}
		return res.Msg.GetExportId()
	}

	first := req("idem_export_same")
	again := req("idem_export_same")
	if first != again {
		t.Fatalf("one Idempotency-Key produced two export ids, %q and %q. A retried "+
			"request starts a second workflow and the client cannot find the first",
			first, again)
	}

	other := req("idem_export_other")
	if other == first {
		t.Fatal("two different keys produced one export id; every request in the system " +
			"would share a stream")
	}
}

// ONE PERSON'S EXPORT IS NOT ANOTHER PERSON'S TO POLL.
//
// The export id is unguessable, and unguessable is not an authorization rule.
// One leaked id must not hand a stranger the manifest URL for the most
// concentrated copy of somebody's data in the system — and the refusal must be
// the SAME answer an unknown id gets, or the difference confirms that the id
// names a real request.
func TestAnotherSubjectsExportIsNotFound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	owner := h.disposableAccount(t, "export-owner")
	stranger := h.disposableAccount(t, "export-stranger")

	res, err := h.compliance.ExportMyData(ctx, authed(
		&compliancev1.ExportMyDataRequest{}, owner.bearer))
	if err != nil {
		t.Fatalf("ExportMyData: %v\n%s", err, h.serverLogs())
	}
	exportID := res.Msg.GetExportId()
	awaitExport(t, owner.bearer, exportID,
		compliancev1.DataExportStatus_DATA_EXPORT_STATUS_PENDING,
		compliancev1.DataExportStatus_DATA_EXPORT_STATUS_READY,
		compliancev1.DataExportStatus_DATA_EXPORT_STATUS_FAILED,
	)

	_, leaked := h.compliance.GetDataExport(ctx, authed(
		&compliancev1.GetDataExportRequest{ExportId: exportID}, stranger.bearer))
	if leaked == nil {
		t.Fatal("a stranger polled somebody else's export. One leaked id hands them the " +
			"manifest URL for the most concentrated copy of that person's data")
	}

	// The SAME answer an unknown id gets. A different code confirms the id names
	// a real request, which is the only thing a holder of a leaked id learns for
	// free.
	_, unknown := h.compliance.GetDataExport(ctx, authed(
		&compliancev1.GetDataExportRequest{
			ExportId: "export_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		}, stranger.bearer))
	if unknown == nil {
		t.Fatal("an export id nobody ever requested was answered")
	}
	if connectrpc.CodeOf(leaked) != connectrpc.CodeOf(unknown) {
		t.Errorf("somebody else's export answers %v and an unknown one answers %v; the "+
			"difference confirms the id is real",
			connectrpc.CodeOf(leaked), connectrpc.CodeOf(unknown))
	}
}

// THE REQUEST IS IN THE LOG AND IN THE PROJECTION, AND THEY AGREE.
//
// Article 15's evidence that somebody exercised the right is the EVENT; the row
// is what answers their poll. A build where one existed without the other would
// pass every unit test: the aggregate has its own, the projection has the
// statement, and nothing joins them.
func TestAnExportRequestReachesBothTheLogAndTheProjection(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	account := h.disposableAccount(t, "export-both")
	res, err := h.compliance.ExportMyData(ctx, authed(
		&compliancev1.ExportMyDataRequest{}, account.bearer))
	if err != nil {
		t.Fatalf("ExportMyData: %v\n%s", err, h.serverLogs())
	}
	exportID := res.Msg.GetExportId()
	awaitExport(t, account.bearer, exportID,
		compliancev1.DataExportStatus_DATA_EXPORT_STATUS_PENDING,
		compliancev1.DataExportStatus_DATA_EXPORT_STATUS_READY,
		compliancev1.DataExportStatus_DATA_EXPORT_STATUS_FAILED,
	)

	// The row, read directly — the one place this test looks past the API,
	// because "the projection agrees with the log" is not a question the API can
	// be asked.
	var subject, status string
	if err := h.pg.InSystemTx(ctx, func(qctx context.Context, q db.Querier) error {
		return q.QueryRow(qctx,
			`SELECT subject_id, status FROM data_export_view WHERE export_id = $1`,
			exportID).Scan(&subject, &status)
	}); err != nil {
		t.Fatalf("reading the projected request: %v", err)
	}
	if subject != account.subjectID {
		t.Fatalf("the projected request belongs to %q, want the caller %q. A request "+
			"attributed to the wrong subject is one THEY can poll and its owner cannot",
			subject, account.subjectID)
	}
	if status == "" {
		t.Fatal("the projected request has no status")
	}

	// And the LOG carries the request, which is the evidence that outlives every
	// projection and every workflow history.
	//
	// Read from the STREAM rather than from $all: the question is whether this
	// particular request was recorded, and a stream read answers it without
	// depending on where in the log it landed.
	events, err := h.store.ReadStream(ctx, mustStream(t, "dataexport", exportID), 0)
	if err != nil {
		t.Fatalf("reading the export's stream: %v. The projection answers the poll and "+
			"NOTHING records that this person exercised Article 15 — which is the half "+
			"that has to survive a rebuild and a workflow-history expiry", err)
	}
	if len(events) == 0 {
		t.Fatal("the export's stream is empty")
	}
	if events[0].Type != "compliance.DataExportRequested.v1" {
		t.Errorf("the stream opens with %q, want the request", events[0].Type)
	}
}

// mustStream builds a stream id, failing the test rather than the caller.
func mustStream(t *testing.T, category, key string) eventsourcing.StreamID {
	t.Helper()
	id, err := eventsourcing.NewStreamID(eventsourcing.Category(category), key)
	if err != nil {
		t.Fatalf("building the stream id: %v", err)
	}
	return id
}

// The test that used to sit here compared this suite's projection list against
// a hand-written copy of cmd/projector's. It is gone because both lists are
// gone: internal/projections holds the one registry and everything that runs
// projections calls it, so the drift it watched for cannot happen.
//
// It is worth recording that the test did not work. It caught compliance's two
// missing projections only because somebody had already found them and added
// their names to it; identity's API key projection went missing afterwards and
// the test said nothing, because the third copy was never updated either. A
// consistency check between two copies is only ever as good as a third copy.

// THE BUNDLE HALF, AGAINST REAL INFRASTRUCTURE.
//
// # Why this test drives the activities rather than the workflow
//
// cmd/worker is not running in this suite, so nothing would otherwise build the
// bundle — and the tests above say so rather than pretending. This runs the
// workflow's ACTIVITIES in-process against the real KurrentDB, the real vault
// and the real object store, which is the half no unit test can reach: the
// Temporal test environment exercises the orchestration with fakes, and the
// fakes cannot refuse a CHECK constraint, fail an S3 write, or hand back a
// manifest that will not decode.
//
// The orchestration itself is covered by the Temporal suite, so what is skipped
// here is exactly what is covered there.
//
// # What it would have caught
//
// The email-change slice shipped a flow whose every layer passed unit tests and
// whose token issuance was refused by a CHECK constraint the events violated —
// found only by a test like this one. compliance's three events go through the
// same append path and the same projection.
func TestTheExportBundleIsBuiltAgainstRealInfrastructure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	account := h.disposableAccount(t, "export-bundle")

	res, err := h.compliance.ExportMyData(ctx, authed(
		&compliancev1.ExportMyDataRequest{}, account.bearer))
	if err != nil {
		t.Fatalf("ExportMyData: %v\n%s", err, h.serverLogs())
	}
	exportID := res.Msg.GetExportId()

	runs := h.exportRuns(t)

	// (1) BEGIN. It loads the request from the log and reports what to walk —
	// which is also where Article 18 would stop the run.
	plan, err := runs.Begin(ctx, exportID)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if plan.SubjectID != account.subjectID {
		t.Fatalf("the plan is for %q, want the requester %q", plan.SubjectID, account.subjectID)
	}
	if len(plan.Prefixes) == 0 {
		t.Fatal("the plan walks no prefixes; every file the person uploaded is silently " +
			"missing from their bundle")
	}

	// (2) LIST. Against the real object store, which is what proves ListPage
	// speaks a dialect SeaweedFS actually answers — the unit tests use a fake
	// that cannot disagree about pagination.
	var objects []complianceapp.ExportedObject
	for _, prefix := range plan.Prefixes {
		cursor := ""
		for pages := 0; pages < 10; pages++ {
			page, listErr := runs.ListObjects(ctx, prefix, cursor)
			if listErr != nil {
				t.Fatalf("ListObjects(%s, %q): %v", prefix, cursor, listErr)
			}
			for _, o := range page.Objects {
				objects = append(objects, complianceapp.ExportedObject{
					Key: o.Key.String(), Size: o.Size, ModifiedAt: o.ModifiedAt,
				})
			}
			if page.Cursor == "" {
				break
			}
			cursor = page.Cursor
		}
	}

	// (3) WRITE. The vault read, the bundle, the object and the completion
	// event, in one activity — every one of them against the real thing.
	manifestKey, err := runs.WriteManifest(ctx, exportID, objects)
	if err != nil {
		t.Fatalf("WriteManifest: %v. This is the call that touches the vault, the object "+
			"store and the event log at once, and it is the one a CHECK constraint or a "+
			"store dialect mismatch fails\n%s", err, h.serverLogs())
	}
	if manifestKey == "" {
		t.Fatal("the manifest was written to no key")
	}

	// And the person's own poll now says READY, with a link that works.
	got := awaitExport(t, account.bearer, exportID,
		compliancev1.DataExportStatus_DATA_EXPORT_STATUS_READY)
	if got.GetManifestUrl() == "" {
		t.Fatal("a READY export carries no manifest URL; the person is told their data is " +
			"ready and has nothing to fetch")
	}
	if got.GetExpiresAt() == nil {
		t.Error("the link carries no expiry; a bearer capability for the most concentrated " +
			"personal data we hold must not be durable")
	}

	// THE BUNDLE IS REAL AND CONTAINS THE PERSON'S DATA. Read back through the
	// same signed URL the browser would use, so this asserts the whole delivery
	// path rather than the object's presence.
	body := fetch(t, got.GetManifestUrl())
	bundle, err := codec.Tolerant[complianceapp.Bundle](body)
	if err != nil {
		t.Fatalf("the manifest does not decode: %v\nbody: %s", err, truncate(body))
	}
	if bundle.SubjectID != account.subjectID {
		t.Fatalf("the bundle is for %q, want %q. A person handed somebody else's data is "+
			"the worst outcome this endpoint has", bundle.SubjectID, account.subjectID)
	}
	if bundle.FormatVersion == 0 {
		t.Error("the bundle carries no format version, so a tool reading it years from now " +
			"has nothing to branch on")
	}
	if len(bundle.PersonalData) == 0 {
		t.Fatal("the bundle carries no personal data at all; Article 15 was answered with " +
			"an empty file")
	}
	if bundle.PersonalData["email"] == "" {
		t.Errorf("the bundle holds %v and not the address the account signs in with",
			keysOf(bundle.PersonalData))
	}
	if len(bundle.Retained) == 0 {
		t.Error("the bundle does not say what we keep that is NOT in it; Article 15(1) " +
			"requires telling the subject about the processing, not only handing over " +
			"the values")
	}
}

// exportRuns builds the use case cmd/worker builds, from this harness's own
// infrastructure.
func (hh *harness) exportRuns(t *testing.T) *complianceapp.ExportRuns {
	t.Helper()

	restrictions, err := compliancepg.NewRestrictions(hh.pg)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := complianceapp.NewExportRuns(complianceapp.ExportRunsDeps{
		Exports: eventsourcing.NewRepository[*compliancedomain.Export](
			hh.store, hh.codec, hh.upcasters,
			compliancedomain.ExportCategory, compliancedomain.NewExport),
		Profile:      vaultProfile{vault: hh.vault},
		Objects:      hh.blobs,
		Prefixes:     complianceapp.SubjectPrefixes(func(s string) []string { return []string{profiledomain.AvatarPrefix(s)} }),
		Store:        hh.blobs,
		Prefix:       profiledomain.AvatarPrefix,
		Restrictions: restrictions,
		// The REAL resolver against the REAL schedule, built exactly as
		// cmd/worker does — not a fake.
		//
		// The point of this suite is that a bundle produced against live
		// infrastructure says what a bundle produced in production says. A
		// stubbed exemptions resolver would leave the one part of the manifest
		// that makes a legal claim — "these classes are retained, under this
		// article" — asserted only against a fixture.
		Exemptions: realExemptions(t),
		Now:        time.Now,
	})
	if err != nil {
		t.Fatalf("NewExportRuns: %v", err)
	}
	return runs
}

// vaultProfile narrows the vault to the one method an export may call.
type vaultProfile struct{ vault *piivault.Vault }

func (v vaultProfile) Profile(
	ctx context.Context, subjectID string,
) (map[string]string, error) {
	profile, err := v.vault.Profile(ctx, pii.SubjectID(subjectID))
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(profile.Fields))
	for field, value := range profile.Fields {
		out[string(field)] = value
	}
	return out, nil
}

// fetch reads a signed URL exactly as a browser would.
func fetch(t *testing.T, url string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("building the download request: %v", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("fetching the manifest: %v. The signed URL the person is handed does not "+
			"resolve from outside the process that minted it", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the manifest URL answered %d; the person clicks their download link and "+
			"gets an error", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		t.Fatalf("reading the manifest: %v", err)
	}
	return body
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func truncate(b []byte) string {
	if len(b) > 400 {
		return string(b[:400]) + "…"
	}
	return string(b)
}

// THE BUNDLE REFERENCES THE PERSON'S ACTUAL FILES, WITH FETCHABLE LINKS.
//
// # Why this is separate from the test above
//
// That one exercises the whole activity chain and happens to find NO objects,
// because a fresh account has uploaded nothing. So it proves the listing runs
// and proves nothing about what the listing FINDS — an implementation that
// returned an empty page unconditionally would pass it.
//
// This one puts real objects under the subject's own prefix first. Written
// directly to the store rather than through the profile module's upload flow,
// deliberately: how a file GOT there is profile's business, and the export's
// contract is "everything under this person's prefixes appears in the bundle
// with a working link". Coupling this test to the avatar ceremony would make it
// fail for reasons that are not about exports.
func TestTheBundleReferencesTheSubjectsFilesWithWorkingLinks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	account := h.disposableAccount(t, "export-files")
	prefix := profiledomain.AvatarPrefix(account.subjectID)

	// TWO objects, so "the bundle lists what it found" cannot be satisfied by a
	// implementation that returns the first key it sees.
	want := map[string]string{}
	for i, body := range []string{"first-file-bytes", "second-file-bytes"} {
		key, err := blob.NewKey(prefix)
		if err != nil {
			t.Fatalf("minting an object key: %v", err)
		}
		if err := h.blobs.Put(ctx, key, []byte(body), "application/octet-stream"); err != nil {
			t.Fatalf("seeding object %d: %v", i, err)
		}
		want[key.String()] = body
	}

	res, err := h.compliance.ExportMyData(ctx, authed(
		&compliancev1.ExportMyDataRequest{}, account.bearer))
	if err != nil {
		t.Fatalf("ExportMyData: %v\n%s", err, h.serverLogs())
	}
	exportID := res.Msg.GetExportId()

	// Drive the activities, as the neighbouring test does — the orchestration is
	// covered end to end elsewhere, and what is under test here is the CONTENT.
	runs := h.exportRuns(t)
	plan, err := runs.Begin(ctx, exportID)
	if err != nil {
		t.Fatal(err)
	}
	var objects []complianceapp.ExportedObject
	for _, p := range plan.Prefixes {
		cursor := ""
		for pages := 0; pages < 10; pages++ {
			page, listErr := runs.ListObjects(ctx, p, cursor)
			if listErr != nil {
				t.Fatalf("ListObjects: %v", listErr)
			}
			for _, o := range page.Objects {
				objects = append(objects, complianceapp.ExportedObject{
					Key: o.Key.String(), Size: o.Size, ModifiedAt: o.ModifiedAt,
				})
			}
			if page.Cursor == "" {
				break
			}
			cursor = page.Cursor
		}
	}
	if len(objects) != len(want) {
		t.Fatalf("the listing found %d objects and the subject holds %d. A person's files "+
			"are missing from their Article 15 bundle, and the erasure that follows will "+
			"delete them", len(objects), len(want))
	}
	if _, err := runs.WriteManifest(ctx, exportID, objects); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	got := awaitExport(t, account.bearer, exportID,
		compliancev1.DataExportStatus_DATA_EXPORT_STATUS_READY)
	if len(got.GetFiles()) != len(want) {
		t.Fatalf("the poll reports %d file(s) and the subject holds %d",
			len(got.GetFiles()), len(want))
	}

	// EVERY link works, and returns the bytes that were stored. This is what
	// makes the manifest a portability answer rather than a list of names.
	for _, f := range got.GetFiles() {
		expected, known := want[f.GetKey()]
		if !known {
			t.Errorf("the bundle references %q, which this subject does not hold", f.GetKey())
			continue
		}
		if f.GetDownloadUrl() == "" {
			t.Errorf("file %q has no download link; the person can see it exists and "+
				"cannot fetch it", f.GetKey())
			continue
		}
		if body := string(fetch(t, f.GetDownloadUrl())); body != expected {
			t.Errorf("file %q downloaded %q, want %q", f.GetKey(), body, expected)
		}
		if f.GetSizeBytes() != int64(len(expected)) {
			t.Errorf("file %q reports %d bytes and holds %d",
				f.GetKey(), f.GetSizeBytes(), len(expected))
		}
	}

	// And the MANIFEST agrees with the poll — the two are produced by different
	// code from the same stored bundle, so a mismatch means one of them is
	// inventing.
	bundle, err := codec.Tolerant[complianceapp.Bundle](fetch(t, got.GetManifestUrl()))
	if err != nil {
		t.Fatalf("the manifest does not decode: %v", err)
	}
	if len(bundle.Objects) != len(want) {
		t.Errorf("the manifest lists %d objects and the poll reported %d",
			len(bundle.Objects), len(got.GetFiles()))
	}
}

// realExemptions builds the retention resolver exactly as cmd/worker does.
//
// # Real, not a fake, and that is the point of this suite
//
// A bundle produced here must say what a bundle produced in production says.
// The manifest's retained-records section is the one part of it that makes a
// LEGAL claim — "these classes are retained, on this article" — and asserting
// it against a fixture would test the fixture.
//
// `AssumeRecordsExist` is the same placeholder the composition roots wire, and
// it is the honest one to use here for the same reason: nothing can yet ask
// billing whether a given subject appears on an invoice, so the resolver
// resolves toward STATING the class. Over-stating is the smaller wrong;
// compliance.md §7 names under-stating as the misleading answer.
func realExemptions(t *testing.T) *complianceapp.Exemptions {
	t.Helper()
	ex, err := complianceapp.NewExemptions(complianceapp.ExemptionsDeps{
		Records: complianceapp.AssumeRecordsExist{},
	})
	if err != nil {
		t.Fatalf("building the retention exemptions: %v", err)
	}
	return ex
}
