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

// Service serves ComplianceService.
type Service struct {
	compliancev1connect.UnimplementedComplianceServiceHandler

	restrictions Restrictions
}

// Deps is what Service needs.
type Deps struct {
	Restrictions Restrictions
}

func New(d Deps) (*Service, error) {
	if d.Restrictions == nil {
		return nil, fmt.Errorf("compliance: a restriction use case is required; without one " +
			"every Article 18 method answers 'unimplemented' and a person can only halt " +
			"processing by asking an operator to edit a table")
	}
	return &Service{restrictions: d.Restrictions}, nil
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
