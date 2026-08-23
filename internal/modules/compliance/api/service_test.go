package api_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"net/http"
	"net/http/httptest"

	"connectrpc.com/connect"

	compliancev1 "github.com/chronos/chronos-go/gen/proto/chronos/compliance/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/compliance/v1/compliancev1connect"
	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	complianceapi "github.com/chronos/chronos-go/internal/modules/compliance/api"
	"github.com/chronos/chronos-go/internal/modules/compliance/app"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/cqrs"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/server/interceptor"
	"github.com/chronos/chronos-go/internal/server/policy"
)

const caller = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV"

var since = time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)

type fakeRestrictions struct {
	result app.RestrictionResult
	err    error

	restricted []app.RestrictionCommand
	lifted     []app.RestrictionCommand
	stated     []string
}

func (f *fakeRestrictions) Restrict(
	_ context.Context, cmd app.RestrictionCommand,
) (app.RestrictionResult, error) {
	f.restricted = append(f.restricted, cmd)
	return f.result, f.err
}

func (f *fakeRestrictions) Lift(
	_ context.Context, cmd app.RestrictionCommand,
) (app.RestrictionResult, error) {
	f.lifted = append(f.lifted, cmd)
	return f.result, f.err
}

func (f *fakeRestrictions) State(
	_ context.Context, subjectID string,
) (app.RestrictionResult, error) {
	f.stated = append(f.stated, subjectID)
	return f.result, f.err
}

// service drives the REAL generated types through the REAL gate pipeline.
//
// Not a handler called directly: `interceptor.PrincipalFrom` reads a context key
// whose type is unexported precisely so no other package — this test included —
// can forge a caller. The only honest way to give a handler a principal is to run
// the pipeline that puts one there, and a test that could inject one directly
// would prove nothing about where handlers get theirs.
// fakeExports stands in where a test is about restrictions.
type fakeExports struct {
	exportID string
	err      error
	asked    []app.RequestExportCommand
}

func (f *fakeExports) Request(
	_ context.Context, cmd app.RequestExportCommand,
) (string, error) {
	f.asked = append(f.asked, cmd)
	if f.err != nil {
		return "", f.err
	}
	id := f.exportID
	if id == "" {
		id = "export_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	}
	return id, nil
}

// fakeExportViews stands in for the READ half.
type fakeExportViews struct {
	view  app.ExportView
	list  []app.ExportView
	err   error
	asked []string
}

func (f *fakeExportViews) Get(
	_ context.Context, exportID, subjectID string,
) (app.ExportView, error) {
	f.asked = append(f.asked, exportID+"|"+subjectID)
	return f.view, f.err
}

func (f *fakeExportViews) List(
	_ context.Context, subjectID string, _ int,
) ([]app.ExportView, error) {
	f.asked = append(f.asked, "list|"+subjectID)
	return f.list, f.err
}

func service(
	t *testing.T, r *fakeRestrictions, principal authz.Principal,
) compliancev1connect.ComplianceServiceClient {
	t.Helper()

	svc, err := complianceapi.New(complianceapi.Deps{
		Restrictions: r, Exports: &fakeExports{}, ExportViews: &fakeExportViews{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return pipeline(t, svc, principal)
}

// pipeline puts one service behind the real gates and returns a client.
func pipeline(
	t *testing.T, svc *complianceapi.Service, principal authz.Principal,
) compliancev1connect.ComplianceServiceClient {
	t.Helper()

	policies, err := policy.Load("chronos.compliance.v1.ComplianceService")
	if err != nil {
		t.Fatalf("loading compliance's policies: %v", err)
	}
	guard, err := authz.NewGuard(authz.GuardDeps{Checker: allowChecker{}})
	if err != nil {
		t.Fatal(err)
	}
	once, err := cqrs.NewOnce(cqrs.OnceDeps{Store: newMemStore()})
	if err != nil {
		t.Fatal(err)
	}
	idem, err := interceptor.NewIdempotency(once)
	if err != nil {
		t.Fatal(err)
	}
	gates, err := interceptor.NewGates(interceptor.Deps{
		Policies: policies,
		Authn: stubAuthenticator{principal: interceptor.Principal{
			Subject: principal,
			// AAL2, because both mutations declare min_aal = ASSURANCE_LEVEL_2 and
			// the pipeline enforces it. A stub that omitted this would fail every
			// test with step-up — which is the gate working, and is why the
			// principal is built here rather than assumed.
			Context: authz.AuthContext{AAL: 2, ActiveOrg: "org_test", SessionID: "sess_test"},
			AAL:     optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2,
		}},
		Org:           stubOrgResolver{},
		Authz:         guard,
		Subscriptions: stubSubscriptions{},
		Idempotency:   idem,
	})
	if err != nil {
		t.Fatalf("building the gate pipeline: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle(compliancev1connect.NewComplianceServiceHandler(
		svc, connect.WithInterceptors(gates)))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return compliancev1connect.NewComplianceServiceClient(server.Client(), server.URL)
}

// user is the ordinary caller: an authenticated person acting on their own data.
func user(subjectID string) authz.Principal {
	return authz.Principal{Kind: authz.KindUser, ID: subjectID}
}

func withKey[T any](msg *T, key string) *connect.Request[T] {
	req := connect.NewRequest(msg)
	if key != "" {
		req.Header().Set(interceptor.IdempotencyHeader, key)
	}
	return req
}

// THE SUBJECT COMES FROM THE CONTEXT, AND IS ALSO THE ACTOR.
//
// There is no field for either in the schema and there must not be: a request
// that could name a subject is a request to exercise somebody else's rights, and
// this endpoint halts a person's mail.
func TestRestrictingActsOnTheAuthenticatedCaller(t *testing.T) {
	r := &fakeRestrictions{result: app.RestrictionResult{Changed: true, Since: since}}

	res, err := service(t, r, user(caller)).RestrictProcessing(context.Background(),
		withKey(&compliancev1.RestrictProcessingRequest{}, "key-1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.restricted) != 1 {
		t.Fatalf("restricted %d times", len(r.restricted))
	}
	cmd := r.restricted[0]
	if cmd.SubjectID != caller || cmd.ActorID != caller {
		t.Errorf("acted on subject=%q actor=%q, want both %q", cmd.SubjectID, cmd.ActorID, caller)
	}
	if !res.Msg.GetChanged() {
		t.Error("the response reports no change")
	}
	if got := res.Msg.GetRestrictedSince().AsTime(); !got.Equal(since) {
		t.Errorf("restricted since %v, want %v", got, since)
	}
}

// AN UNCHANGED RESTRICTION STILL REPORTS THE ORIGINAL INSTANT.
//
// A repeated request must not move a date the person has already been given.
func TestARepeatedRestrictionReportsTheFirstInstant(t *testing.T) {
	r := &fakeRestrictions{result: app.RestrictionResult{Changed: false, Since: since}}

	res, err := service(t, r, user(caller)).RestrictProcessing(context.Background(),
		withKey(&compliancev1.RestrictProcessingRequest{}, "key-1"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Msg.GetChanged() {
		t.Error("a repeated restriction reported a change")
	}
	if got := res.Msg.GetRestrictedSince().AsTime(); !got.Equal(since) {
		t.Errorf("restricted since %v, want the original %v", got, since)
	}
}

// LIFTING ACTS ON THE CALLER TOO.
func TestLiftingActsOnTheAuthenticatedCaller(t *testing.T) {
	r := &fakeRestrictions{result: app.RestrictionResult{Changed: true}}

	res, err := service(t, r, user(caller)).LiftProcessingRestriction(context.Background(),
		withKey(&compliancev1.LiftProcessingRestrictionRequest{}, "key-1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.lifted) != 1 || r.lifted[0].SubjectID != caller {
		t.Fatalf("lifted %+v", r.lifted)
	}
	if !res.Msg.GetChanged() {
		t.Error("the response reports no change")
	}
}

// READING THE STATE NEEDS NO IDEMPOTENCY KEY.
//
// It is a READ. Requiring the header would make "what is my current setting"
// fail for a client that correctly omits it on reads.
func TestReadingTheStateNeedsNoKey(t *testing.T) {
	r := &fakeRestrictions{result: app.RestrictionResult{Since: since}}

	res, err := service(t, r, user(caller)).GetProcessingRestriction(context.Background(),
		connect.NewRequest(&compliancev1.GetProcessingRestrictionRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Msg.GetRestricted() {
		t.Error("a restricted subject reads as unrestricted")
	}
	if len(r.stated) != 1 || r.stated[0] != caller {
		t.Errorf("read the state of %v", r.stated)
	}
}

// AN UNRESTRICTED SUBJECT READS AS UNRESTRICTED, WITH NO INSTANT.
func TestAnUnrestrictedSubjectReadsAsSuch(t *testing.T) {
	r := &fakeRestrictions{}

	res, err := service(t, r, user(caller)).GetProcessingRestriction(context.Background(),
		connect.NewRequest(&compliancev1.GetProcessingRestrictionRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if res.Msg.GetRestricted() {
		t.Error("an unrestricted subject reads as restricted")
	}
	if res.Msg.GetRestrictedSince() != nil {
		t.Error("an unrestricted subject carries an instant")
	}
}

// EVERY MUTATION NEEDS AN IDEMPOTENCY KEY.
func TestTheMutationsNeedAnIdempotencyKey(t *testing.T) {
	r := &fakeRestrictions{}
	s := service(t, r, user(caller))
	ctx := context.Background()

	if _, err := s.RestrictProcessing(ctx,
		withKey(&compliancev1.RestrictProcessingRequest{}, "")); err == nil {
		t.Error("restricting with no Idempotency-Key was served")
	}
	if _, err := s.LiftProcessingRestriction(ctx,
		withKey(&compliancev1.LiftProcessingRestrictionRequest{}, "")); err == nil {
		t.Error("lifting with no Idempotency-Key was served")
	}
	if len(r.restricted)+len(r.lifted) != 0 {
		t.Error("the use case ran for a request the header check should have refused")
	}
}

// AN UNAUTHENTICATED CALLER IS REFUSED, AND NOTHING RUNS.
//
// Reaching a handler with no principal means the authn gate did not run.
// Continuing would act on an empty subject.
func TestAnUnauthenticatedCallerIsRefused(t *testing.T) {
	r := &fakeRestrictions{}
	// A principal with NO subject is what the authn gate leaves when nothing
	// authenticated.
	s := service(t, r, authz.Principal{})

	if _, err := s.RestrictProcessing(context.Background(),
		withKey(&compliancev1.RestrictProcessingRequest{}, "key-1")); err == nil {
		t.Error("an unauthenticated restriction was served")
	}
	if _, err := s.GetProcessingRestriction(context.Background(),
		connect.NewRequest(&compliancev1.GetProcessingRestrictionRequest{})); err == nil {
		t.Error("an unauthenticated read was served")
	}
	if len(r.restricted)+len(r.stated) != 0 {
		t.Error("the use case ran for an unauthenticated caller")
	}
}

// AN API KEY CANNOT EXERCISE A PERSON'S RIGHTS.
//
// A KindAPIKey principal carries the KEY's identifier, not a person's pseudonym.
// Acting on it would halt the mail of whatever account that string happened to
// name, and there is no delegation convention in this system to make it mean
// anything else.
func TestAnAPIKeyCannotRestrictProcessing(t *testing.T) {
	r := &fakeRestrictions{}
	apiKey := authz.Principal{Kind: authz.KindAPIKey, ID: "key_1"}

	if _, err := service(t, r, apiKey).RestrictProcessing(context.Background(),
		withKey(&compliancev1.RestrictProcessingRequest{}, "key-1")); err == nil {
		t.Fatal("an API key exercised a data subject's Article 18 right")
	}
	if len(r.restricted) != 0 {
		t.Error("the use case ran for an API key")
	}
}

// A FAILING USE CASE IS REPORTED.
func TestAFailingRestrictionIsReported(t *testing.T) {
	r := &fakeRestrictions{err: errors.New("kurrentdb: unavailable")}

	if _, err := service(t, r, user(caller)).RestrictProcessing(context.Background(),
		withKey(&compliancev1.RestrictProcessingRequest{}, "key-1")); err == nil {
		t.Fatal("a failed restriction reported success; the person believes processing " +
			"has stopped and it has not")
	}
}

// AN INCOMPLETE WIRING IS REFUSED.
func TestTheComplianceServiceRefusesAnIncompleteWiring(t *testing.T) {
	if _, err := complianceapi.New(complianceapi.Deps{
		Exports: &fakeExports{},
	}); err == nil {
		t.Error("a service with no restriction use case was accepted")
	}
	if _, err := complianceapi.New(complianceapi.Deps{
		Restrictions: &fakeRestrictions{},
	}); err == nil {
		t.Error("a service with no export use case was accepted; a person cannot obtain a " +
			"copy of their own data")
	}
}

// THE EXPORT ACTS ON THE AUTHENTICATED CALLER.
//
// compliance.md §3 calls this the most dangerous endpoint in the product: it
// exports everything known about a person, on demand, in a convenient bundle. A
// request that could name a subject would be exactly the exfiltration API that
// description warns about — so the schema has no field for one and the handler
// reads the principal.
func TestTheExportActsOnTheAuthenticatedCaller(t *testing.T) {
	exports := &fakeExports{exportID: "export_01ARZ3NDEKTSV4RRFFQ69G5FAV"}
	svc, err := complianceapi.New(complianceapi.Deps{
		Restrictions: &fakeRestrictions{}, Exports: exports,
		ExportViews: &fakeExportViews{},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := pipeline(t, svc, user(caller))

	res, err := client.ExportMyData(context.Background(),
		withKey(&compliancev1.ExportMyDataRequest{}, "k-export"))
	if err != nil {
		t.Fatal(err)
	}
	if len(exports.asked) != 1 || exports.asked[0].SubjectID != caller {
		t.Fatalf("exported for %v, want the authenticated caller %q", exports.asked, caller)
	}
	if exports.asked[0].IdempotencyKey != "k-export" {
		t.Errorf("the idempotency key reached the app layer as %q; the export ID is "+
			"DERIVED from it, so losing it starts a second workflow on every retry",
			exports.asked[0].IdempotencyKey)
	}
	if res.Msg.GetExportId() != "export_01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Errorf("returned export id %q", res.Msg.GetExportId())
	}
	// PENDING, always, and never a link: the bundle does not exist yet.
	if res.Msg.GetStatus() != compliancev1.DataExportStatus_DATA_EXPORT_STATUS_PENDING {
		t.Errorf("a freshly accepted request reports status %v", res.Msg.GetStatus())
	}
}

// A FAILING EXPORT DOES NOT LEAK THE STORE'S OWN ERROR.
//
// An object-store failure names a bucket, a key and an endpoint. None of that
// belongs in a response to a browser.
func TestAFailingExportDoesNotLeakTheStoreError(t *testing.T) {
	const leak = "NoSuchBucket: chronos-prod-eu at s3.internal:8333"
	exports := &fakeExports{err: errs.Internalf("producing the export").Wrap(errors.New(leak))}
	svc, err := complianceapi.New(complianceapi.Deps{
		Restrictions: &fakeRestrictions{}, Exports: exports,
		ExportViews: &fakeExportViews{},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := pipeline(t, svc, user(caller))

	_, err = client.ExportMyData(context.Background(),
		withKey(&compliancev1.ExportMyDataRequest{}, "k-fail"))
	if err == nil {
		t.Fatal("a failing export reported success")
	}
	if strings.Contains(err.Error(), "chronos-prod-eu") ||
		strings.Contains(err.Error(), "s3.internal") {
		t.Errorf("the response carries the store's own text: %q", err)
	}
}
