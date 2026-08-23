// Package api serves the data subject's own rights.
package api

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	compliancev1 "github.com/chronos/chronos-go/gen/proto/chronos/compliance/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/compliance/v1/compliancev1connect"
	"github.com/chronos/chronos-go/internal/modules/compliance/app"
	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/errs"
	srvconnect "github.com/chronos/chronos-go/internal/server/connect"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

// Restrictions is compliance's Article 18 use case, narrowed to what this layer
// calls.
type Restrictions interface {
	Restrict(ctx context.Context, cmd app.RestrictionCommand) (app.RestrictionResult, error)
	Lift(ctx context.Context, cmd app.RestrictionCommand) (app.RestrictionResult, error)
	State(ctx context.Context, subjectID string) (app.RestrictionResult, error)
}

// Exports produces a data subject's portability bundle.
// Exports is the request half: it records that somebody asked and returns the
// id they poll with. It does NOT build the bundle — a workflow does — so this
// port cannot read a vault, list an object or mint a URL.
type Exports interface {
	Request(ctx context.Context, cmd app.RequestExportCommand) (string, error)
}

// ExportViews is the read half, and it is a SEPARATE port for the reason the
// two halves are separate use cases: this one mints download URLs for the most
// concentrated personal data the system holds, and the one that accepts the
// request has no business being able to.
type ExportViews interface {
	Get(ctx context.Context, exportID, subjectID string) (app.ExportView, error)
	List(ctx context.Context, subjectID string, limit int) ([]app.ExportView, error)
}

// Service serves ComplianceService.
type Service struct {
	compliancev1connect.UnimplementedComplianceServiceHandler

	restrictions Restrictions
	views        ExportViews
	exports      Exports
}

// Deps is what Service needs.
type Deps struct {
	Restrictions Restrictions
	Exports      Exports
	ExportViews  ExportViews
}

func New(d Deps) (*Service, error) {
	switch {
	case d.Restrictions == nil:
		return nil, fmt.Errorf("compliance: a restriction use case is required; without one " +
			"every Article 18 method answers 'unimplemented' and a person can only halt " +
			"processing by asking an operator to edit a table")
	case d.Exports == nil:
		return nil, fmt.Errorf("compliance: an export use case is required; without one a " +
			"person cannot obtain a copy of their own data, which is Article 15 and 20")
	case d.ExportViews == nil:
		return nil, fmt.Errorf("compliance: an export reader is required; without one a " +
			"person can ASK for their data and can never find out whether it is ready, " +
			"which answers Article 15 with a request nobody can collect")
	}
	return &Service{
		restrictions: d.Restrictions, exports: d.Exports, views: d.ExportViews,
	}, nil
}

// ExportMyData records that the caller asked for a copy of their data.
//
// # It no longer produces one, and the response no longer carries a link
//
// Building the bundle is a workflow (compliance.md §5), so at the moment this
// responds there is nothing to link to. What comes back is the request's ID, and
// GetDataExport is polled with it — which is also what makes the flow honest
// about a long job: a response that had to wait for the bundle would hold a
// connection open for as long as somebody's data takes to gather, and would lose
// it entirely if the process restarted mid-way.
//
// The subject is the authenticated caller and nothing else. compliance.md §3
// calls this the most dangerous endpoint in the product — it exports everything
// known about a person, on demand, in a convenient bundle — and a request that
// could name a subject would be exactly the exfiltration API that description
// warns about.
func (s *Service) ExportMyData(
	ctx context.Context, req *connect.Request[compliancev1.ExportMyDataRequest],
) (*connect.Response[compliancev1.ExportMyDataResponse], error) {
	subject, key, err := s.command(ctx, req.Header())
	if err != nil {
		return nil, fail(err)
	}
	exportID, err := s.exports.Request(ctx, app.RequestExportCommand{
		SubjectID: subject, IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&compliancev1.ExportMyDataResponse{
		ExportId: exportID,
		// Always pending here. Returned rather than assumed so a client that
		// polls immediately reads one shape of answer everywhere.
		Status: compliancev1.DataExportStatus_DATA_EXPORT_STATUS_PENDING,
	}), nil
}

// GetDataExport reports where one request has got to, and mints its links.
//
// The export id is matched against the AUTHENTICATED caller, so an id belonging
// to somebody else answers exactly as an unknown one. That check is in the app
// layer's reader rather than here, because it is a property of the query and not
// of the transport — and putting it here would let a second caller of the same
// use case acquire the unscoped version.
func (s *Service) GetDataExport(
	ctx context.Context, req *connect.Request[compliancev1.GetDataExportRequest],
) (*connect.Response[compliancev1.GetDataExportResponse], error) {
	subject, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	view, err := s.views.Get(ctx, req.Msg.GetExportId(), subject)
	if err != nil {
		return nil, fail(err)
	}

	out := &compliancev1.GetDataExportResponse{
		Status:        exportStatus(view.Status),
		ManifestUrl:   view.ManifestURL,
		FailureReason: view.FailureReason,
		RequestedAt:   timestamppb.New(view.RequestedAt.UTC()),
		Files:         make([]*compliancev1.ExportedFile, 0, len(view.Objects)),
	}
	if !view.SettledAt.IsZero() {
		out.SettledAt = timestamppb.New(view.SettledAt.UTC())
	}
	if !view.ExpiresAt.IsZero() {
		out.ExpiresAt = timestamppb.New(view.ExpiresAt.UTC())
	}
	for _, o := range view.Objects {
		out.Files = append(out.Files, &compliancev1.ExportedFile{
			Key: o.Key, SizeBytes: o.Size, DownloadUrl: o.URL,
		})
	}
	return connect.NewResponse(out), nil
}

// ListDataExports returns the caller's own request history, newest first.
//
// No links, deliberately. Minting one per file of every past export would turn a
// list screen into a bulk issuance of bearer capabilities for everything the
// person has ever exported.
func (s *Service) ListDataExports(
	ctx context.Context, req *connect.Request[compliancev1.ListDataExportsRequest],
) (*connect.Response[compliancev1.ListDataExportsResponse], error) {
	subject, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	views, err := s.views.List(ctx, subject, int(req.Msg.GetLimit()))
	if err != nil {
		return nil, fail(err)
	}

	out := &compliancev1.ListDataExportsResponse{
		Exports: make([]*compliancev1.DataExportSummary, 0, len(views)),
	}
	for _, v := range views {
		summary := &compliancev1.DataExportSummary{
			ExportId:      v.ExportID,
			Status:        exportStatus(v.Status),
			FailureReason: v.FailureReason,
			RequestedAt:   timestamppb.New(v.RequestedAt.UTC()),
		}
		if !v.SettledAt.IsZero() {
			summary.SettledAt = timestamppb.New(v.SettledAt.UTC())
		}
		out.Exports = append(out.Exports, summary)
	}
	return connect.NewResponse(out), nil
}

// exportStatus maps the domain's state onto the wire enum.
//
// An UNKNOWN state maps to UNSPECIFIED rather than to any of the three real
// answers. The alternative — defaulting to PENDING — would tell somebody their
// export is still building for a state this build cannot interpret, which is the
// one answer that makes them wait rather than act.
func exportStatus(s domain.ExportState) compliancev1.DataExportStatus {
	switch s {
	case domain.ExportStatePending:
		return compliancev1.DataExportStatus_DATA_EXPORT_STATUS_PENDING
	case domain.ExportStateReady:
		return compliancev1.DataExportStatus_DATA_EXPORT_STATUS_READY
	case domain.ExportStateFailed:
		return compliancev1.DataExportStatus_DATA_EXPORT_STATUS_FAILED
	default:
		return compliancev1.DataExportStatus_DATA_EXPORT_STATUS_UNSPECIFIED
	}
}

// RestrictProcessing halts processing of the caller's own data.
func (s *Service) RestrictProcessing(
	ctx context.Context, req *connect.Request[compliancev1.RestrictProcessingRequest],
) (*connect.Response[compliancev1.RestrictProcessingResponse], error) {
	subject, key, err := s.command(ctx, req.Header())
	if err != nil {
		return nil, fail(err)
	}
	result, err := s.restrictions.Restrict(ctx, app.RestrictionCommand{
		SubjectID: subject, ActorID: subject, IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&compliancev1.RestrictProcessingResponse{
		Changed:         result.Changed,
		RestrictedSince: timestamp(result),
	}), nil
}

// LiftProcessingRestriction resumes processing of the caller's own data.
func (s *Service) LiftProcessingRestriction(
	ctx context.Context, req *connect.Request[compliancev1.LiftProcessingRestrictionRequest],
) (*connect.Response[compliancev1.LiftProcessingRestrictionResponse], error) {
	subject, key, err := s.command(ctx, req.Header())
	if err != nil {
		return nil, fail(err)
	}
	result, err := s.restrictions.Lift(ctx, app.RestrictionCommand{
		SubjectID: subject, ActorID: subject, IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&compliancev1.LiftProcessingRestrictionResponse{
		Changed: result.Changed,
	}), nil
}

// GetProcessingRestriction reports the caller's own restriction state.
func (s *Service) GetProcessingRestriction(
	ctx context.Context, _ *connect.Request[compliancev1.GetProcessingRestrictionRequest],
) (*connect.Response[compliancev1.GetProcessingRestrictionResponse], error) {
	subject, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	result, err := s.restrictions.State(ctx, subject)
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&compliancev1.GetProcessingRestrictionResponse{
		Restricted:      !result.Since.IsZero(),
		RestrictedSince: timestamp(result),
	}), nil
}

// command reads the two things every mutating method here needs.
//
// The subject comes from the CONTEXT and is used as BOTH the subject and the
// actor. There is no field for either in the schema and there must not be: a
// request that could name a subject is a request to exercise somebody else's
// rights.
func (s *Service) command(
	ctx context.Context, header interceptor.Header,
) (subject, key string, err error) {
	subject, err = callerSubject(ctx)
	if err != nil {
		return "", "", err
	}
	key = header.Get(interceptor.IdempotencyHeader)
	if key == "" {
		return "", "", errs.ValidationFailedf(
			"%s is required on every mutating request", interceptor.IdempotencyHeader)
	}
	return subject, key, nil
}

// timestamp renders the instant, or nil when there is none.
func timestamp(r app.RestrictionResult) *timestamppb.Timestamp {
	if r.Since.IsZero() {
		return nil
	}
	return timestamppb.New(r.Since.UTC())
}

// callerSubject reads the authenticated caller's pseudonym from the context.
//
// The context, never the request: `interceptor.PrincipalFrom` reads a value only
// the authn gate can write, so a subject obtained here cannot have been chosen
// by whoever sent the request.
//
// A KindAPIKey or KindServiceAccount principal carries the KEY's identifier
// rather than a person's pseudonym, and is refused. These are a data subject's
// own rights: exercising them on behalf of a person is a decision with no
// delegation convention in this system yet, and inventing one silently at an
// endpoint that halts somebody's mail is the wrong place to start.
func callerSubject(ctx context.Context) (string, error) {
	principal, ok := interceptor.PrincipalFrom(ctx)
	if !ok || principal.Subject.Kind != authz.KindUser || principal.Subject.ID == "" {
		return "", errs.Unauthenticatedf("this request has not authenticated")
	}
	return principal.Subject.ID, nil
}

// fail hands the error to the transport mapping the rest of the server uses.
func fail(err error) error { return srvconnect.Error(err) }
