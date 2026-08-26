package api_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	compliancev1 "github.com/chronos/chronos-go/gen/proto/chronos/compliance/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/compliance/v1/compliancev1connect"
	complianceapi "github.com/chronos/chronos-go/internal/modules/compliance/api"
	"github.com/chronos/chronos-go/internal/modules/compliance/app"
	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
)

// These drive Articles 16 and 21 through the REAL gate pipeline, for
// service_test.go's reason: `interceptor.PrincipalFrom` reads a context key
// whose type is unexported precisely so no other package can forge a caller, and
// a test that called the handler directly would prove nothing about where the
// subject comes from — which is the single most important property of every
// endpoint on this service.

// --------------------------------------------------------------------------
// Fakes
// --------------------------------------------------------------------------

// fakeRectifications records what reached the Article 16 use case.
type fakeRectifications struct {
	asked  []app.RectifyCommand
	result app.RectifyResult
	err    error
}

func (f *fakeRectifications) Rectify(
	_ context.Context, cmd app.RectifyCommand,
) (app.RectifyResult, error) {
	f.asked = append(f.asked, cmd)
	if f.err != nil {
		return app.RectifyResult{}, f.err
	}
	if len(f.result.Fields) == 0 {
		return app.RectifyResult{
			Fields:      []string{"display_name"},
			CorrectedAt: time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC),
		}, nil
	}
	return f.result, nil
}

// fakeObjections records what reached the Article 21 use case.
type fakeObjections struct {
	objected  []app.ObjectionCommand
	withdrawn []app.ObjectionCommand
	listed    []string
	standing  []app.StandingObjection
	err       error
}

func (f *fakeObjections) Object(
	_ context.Context, cmd app.ObjectionCommand,
) (app.ObjectionResult, error) {
	f.objected = append(f.objected, cmd)
	if f.err != nil {
		return app.ObjectionResult{}, f.err
	}
	return app.ObjectionResult{Changed: true, Since: objectedAt}, nil
}

func (f *fakeObjections) Withdraw(
	_ context.Context, cmd app.ObjectionCommand,
) (app.ObjectionResult, error) {
	f.withdrawn = append(f.withdrawn, cmd)
	if f.err != nil {
		return app.ObjectionResult{}, f.err
	}
	return app.ObjectionResult{Changed: true}, nil
}

func (f *fakeObjections) List(
	_ context.Context, subjectID string,
) ([]app.StandingObjection, error) {
	f.listed = append(f.listed, subjectID)
	return f.standing, f.err
}

var objectedAt = time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC)

// rightsService wires the two new use cases behind the real pipeline.
func rightsService(
	t *testing.T, r *fakeRectifications, o *fakeObjections,
) compliancev1connect.ComplianceServiceClient {
	t.Helper()
	svc, err := complianceapi.New(complianceapi.Deps{
		Restrictions:   &fakeRestrictions{},
		Exports:        &fakeExports{},
		ExportViews:    &fakeExportViews{},
		Rectifications: r,
		Objections:     o,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return pipeline(t, svc, user(caller))
}

// --------------------------------------------------------------------------
// Article 16
// --------------------------------------------------------------------------

// THE CORRECTION ACTS ON THE AUTHENTICATED CALLER AND NOBODY ELSE.
//
// This is the property the whole service is shaped around, and rectification is
// where getting it wrong is most damaging: an endpoint that could name a subject
// would let one person decide what is true about another, recorded in the log as
// that person's own exercise of a statutory right.
//
// The schema has no subject field, so the only way this could break is a handler
// reading one from somewhere else. Asserting the command's SubjectID is what
// catches that.
func TestRectificationActsOnTheAuthenticatedCaller(t *testing.T) {
	rect := &fakeRectifications{}
	name := "Sam Corrected"

	if _, err := rightsService(t, rect, &fakeObjections{}).RectifyMyData(
		context.Background(),
		withKey(&compliancev1.RectifyMyDataRequest{DisplayName: &name}, "k-rect"),
	); err != nil {
		t.Fatalf("rectifying: %v", err)
	}

	if len(rect.asked) != 1 {
		t.Fatalf("the use case was called %d times, want 1", len(rect.asked))
	}
	got := rect.asked[0]
	if got.SubjectID != caller {
		t.Errorf("corrected the data of %q, want the authenticated caller %q",
			got.SubjectID, caller)
	}
	if got.ActorID != caller {
		t.Errorf("the actor is %q; the record of who exercised the right must be the "+
			"person who did", got.ActorID)
	}
	if got.IdempotencyKey != "k-rect" {
		t.Errorf("the idempotency key reached the app layer as %q; it is forwarded "+
			"unchanged to profile, so losing it writes the vault twice on a retry",
			got.IdempotencyKey)
	}
}

// AN OMITTED FIELD STAYS OMITTED, ALL THE WAY DOWN.
//
// "leave my timezone alone" and "empty my timezone" are different requests. If
// this layer flattened a nil pointer into an empty string, a person correcting
// their display name would silently ask for their locale and timezone to be
// cleared — and the settings screen that renders one field would wipe the other
// three.
func TestRectificationForwardsOnlyTheFieldsNamed(t *testing.T) {
	rect := &fakeRectifications{}
	zone := "Europe/Berlin"

	if _, err := rightsService(t, rect, &fakeObjections{}).RectifyMyData(
		context.Background(),
		withKey(&compliancev1.RectifyMyDataRequest{Timezone: &zone}, "k-tz"),
	); err != nil {
		t.Fatalf("rectifying: %v", err)
	}

	got := rect.asked[0]
	if got.Timezone == nil || *got.Timezone != zone {
		t.Fatalf("the timezone reached the app layer as %v, want %q", got.Timezone, zone)
	}
	if got.DisplayName != nil {
		t.Errorf("a display name of %q was sent for a request that did not mention one; "+
			"the correction would overwrite a field nobody asked it to touch",
			*got.DisplayName)
	}
	if got.Locale != nil {
		t.Errorf("a locale of %q was sent for a request that did not mention one",
			*got.Locale)
	}
}

// THE RESPONSE NAMES FIELDS AND NEVER VALUES.
//
// A response echoing the corrected name would put personal data into proxy logs,
// client caches and support screenshots — for no gain, because the caller sent
// it. This asserts the shape rather than trusting the comment.
func TestTheRectificationResponseCarriesNoValues(t *testing.T) {
	const secret = "Sam The Corrected Person"
	name := secret
	rect := &fakeRectifications{result: app.RectifyResult{
		Fields: []string{"display_name"}, CorrectedAt: objectedAt,
	}}

	res, err := rightsService(t, rect, &fakeObjections{}).RectifyMyData(
		context.Background(),
		withKey(&compliancev1.RectifyMyDataRequest{DisplayName: &name}, "k-echo"),
	)
	if err != nil {
		t.Fatalf("rectifying: %v", err)
	}
	for _, f := range res.Msg.GetCorrectedFields() {
		if strings.Contains(f, secret) {
			t.Fatalf("the response echoes the corrected value %q; it belongs in the vault "+
				"and nowhere a proxy logs", f)
		}
	}
	if len(res.Msg.GetCorrectedFields()) != 1 ||
		res.Msg.GetCorrectedFields()[0] != "display_name" {
		t.Errorf("the response names %v, want the field names it corrected",
			res.Msg.GetCorrectedFields())
	}
	if !res.Msg.GetCorrectedAt().AsTime().Equal(objectedAt) {
		t.Errorf("corrected_at is %v", res.Msg.GetCorrectedAt().AsTime())
	}
}

// A FAILING CORRECTION DOES NOT LEAK THE OWNING MODULE'S INTERNALS.
func TestAFailingRectificationDoesNotLeakInternals(t *testing.T) {
	const leak = "pgx: relation \"profile_view\" does not exist at pg.internal:5432"
	rect := &fakeRectifications{
		err: errs.Internalf("storing profile details").Wrap(errors.New(leak)),
	}
	name := "Sam"

	_, err := rightsService(t, rect, &fakeObjections{}).RectifyMyData(
		context.Background(),
		withKey(&compliancev1.RectifyMyDataRequest{DisplayName: &name}, "k-leak"),
	)
	if err == nil {
		t.Fatal("a failing correction reported success; the person believes their record " +
			"was corrected and it was not")
	}
	if strings.Contains(err.Error(), "pg.internal") ||
		strings.Contains(err.Error(), "profile_view") {
		t.Errorf("the response carries the store's own text: %q", err)
	}
}

// --------------------------------------------------------------------------
// Article 21
// --------------------------------------------------------------------------

// AN OBJECTION ACTS ON THE AUTHENTICATED CALLER, AND NAMES A REAL PURPOSE.
func TestObjectingActsOnTheAuthenticatedCaller(t *testing.T) {
	obj := &fakeObjections{}

	res, err := rightsService(t, &fakeRectifications{}, obj).ObjectToProcessing(
		context.Background(),
		withKey(&compliancev1.ObjectToProcessingRequest{
			Purpose: compliancev1.ProcessingPurpose_PROCESSING_PURPOSE_ACTIVITY_NOTIFICATIONS,
		}, "k-obj"),
	)
	if err != nil {
		t.Fatalf("objecting: %v", err)
	}

	if len(obj.objected) != 1 {
		t.Fatalf("the use case was called %d times, want 1", len(obj.objected))
	}
	got := obj.objected[0]
	if got.SubjectID != caller || got.ActorID != caller {
		t.Errorf("objected for subject %q / actor %q, want the caller %q both times",
			got.SubjectID, got.ActorID, caller)
	}
	if got.Purpose != domain.PurposeActivityNotifications {
		t.Errorf("the purpose reached the app layer as %q, want %q; a mismapped purpose "+
			"records an instruction against processing nobody is doing, and leaves the "+
			"processing they meant to stop running",
			got.Purpose, domain.PurposeActivityNotifications)
	}
	if !res.Msg.GetObjectedSince().AsTime().Equal(objectedAt) {
		t.Errorf("objected_since is %v", res.Msg.GetObjectedSince().AsTime())
	}
}

// AN UNSPECIFIED PURPOSE IS REFUSED, NOT DEFAULTED.
//
// The enum's zero value is what a client sends when it forgot the field. Mapping
// it to any real purpose would record an instruction the person did not give;
// mapping it to none and succeeding would report that processing stopped when
// nothing did. Both are worse than an error, so protovalidate refuses it at the
// boundary and the handler refuses it again for any other caller of the use case.
func TestObjectingToNothingIsRefused(t *testing.T) {
	obj := &fakeObjections{}

	_, err := rightsService(t, &fakeRectifications{}, obj).ObjectToProcessing(
		context.Background(),
		withKey(&compliancev1.ObjectToProcessingRequest{}, "k-none"),
	)
	if err == nil {
		t.Fatal("an objection naming no purpose was accepted; the person is told " +
			"processing stopped and none did")
	}
	if len(obj.objected) != 0 {
		t.Errorf("it reached the use case anyway, as %v", obj.objected)
	}
}

// WITHDRAWING IS SCOPED TO ONE PURPOSE.
//
// The failure this guards is the one the composite primary key also guards: a
// withdrawal that released every objection the person holds. Here it would
// happen by the handler dropping the purpose on the way through.
func TestWithdrawingNamesThePurpose(t *testing.T) {
	obj := &fakeObjections{}

	if _, err := rightsService(t, &fakeRectifications{}, obj).WithdrawProcessingObjection(
		context.Background(),
		withKey(&compliancev1.WithdrawProcessingObjectionRequest{
			Purpose: compliancev1.ProcessingPurpose_PROCESSING_PURPOSE_PRODUCT_UPDATES,
		}, "k-wd"),
	); err != nil {
		t.Fatalf("withdrawing: %v", err)
	}

	if len(obj.withdrawn) != 1 {
		t.Fatalf("the use case was called %d times, want 1", len(obj.withdrawn))
	}
	if obj.withdrawn[0].Purpose != domain.PurposeProductUpdates {
		t.Errorf("withdrew %q, want %q; releasing the wrong objection resumes processing "+
			"the person is still objecting to",
			obj.withdrawn[0].Purpose, domain.PurposeProductUpdates)
	}
}

// THE LIST IS THE CALLER'S OWN, AND RENDERS EVERY STANDING OBJECTION.
//
// An objection missing from this list is one the person cannot withdraw — the
// list is the only place the control exists — so a purpose this build no longer
// recognises must still appear, as UNSPECIFIED rather than as nothing.
func TestListingObjectionsRendersEvenAnUnknownPurpose(t *testing.T) {
	obj := &fakeObjections{standing: []app.StandingObjection{
		{Purpose: domain.PurposeActivityNotifications, Since: objectedAt},
		{Purpose: domain.Purpose("a_purpose_this_build_retired"), Since: objectedAt},
	}}

	res, err := rightsService(t, &fakeRectifications{}, obj).ListProcessingObjections(
		context.Background(), withKey(&compliancev1.ListProcessingObjectionsRequest{}, ""))
	if err != nil {
		t.Fatalf("listing: %v", err)
	}

	if len(obj.listed) != 1 || obj.listed[0] != caller {
		t.Fatalf("listed for %v, want the authenticated caller %q", obj.listed, caller)
	}
	if n := len(res.Msg.GetObjections()); n != 2 {
		t.Fatalf("the response carries %d objections and the subject holds 2; an "+
			"objection the list omits is one they cannot withdraw, because this list is "+
			"the only place the control exists", n)
	}
	if got := res.Msg.GetObjections()[0].GetPurpose(); got !=
		compliancev1.ProcessingPurpose_PROCESSING_PURPOSE_ACTIVITY_NOTIFICATIONS {
		t.Errorf("the known purpose rendered as %v", got)
	}
	if got := res.Msg.GetObjections()[1].GetPurpose(); got !=
		compliancev1.ProcessingPurpose_PROCESSING_PURPOSE_UNSPECIFIED {
		t.Errorf("the retired purpose rendered as %v, want UNSPECIFIED — dropping it "+
			"would hide an instruction that is still being enforced", got)
	}
}
