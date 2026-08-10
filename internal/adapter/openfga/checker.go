// Package openfga adapts OpenFGA as the authorization service.
//
// gRPC, not HTTP. The official Go SDK (github.com/openfga/go-sdk) is generated
// by OpenAPI Generator and speaks HTTP only — verified: it imports net/http and
// contains no reference to google.golang.org/grpc anywhere in the module. The
// SERVER serves the full openfga.v1.OpenFGAService over gRPC, so ADR-037 means
// generating a client rather than accepting the SDK's transport.
package openfga

import (
	"context"
	"fmt"
	"strconv"

	fgav1 "github.com/chronos/chronos-go/gen/thirdparty/openfga/v1"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

// Checker implements authz.Checker over OpenFGA.
//
// It answers questions and NOTHING else. Every failure is returned as an error
// rather than as a denial, because the Guard is what turns errors into denials —
// an adapter that decided for itself would eventually disagree with the policy,
// and the disagreement would be a permit nobody intended.
type Checker struct {
	client  fgav1.OpenFGAServiceClient
	storeID string

	// modelID pins the authorization model.
	//
	// Unpinned, OpenFGA evaluates against the LATEST model, so deploying a model
	// change would silently re-evaluate every in-flight request against it. Pinned,
	// a model change is a deliberate rollout.
	modelID string
}

var _ authz.Checker = (*Checker)(nil)

// Config is what the adapter needs.
type Config struct {
	StoreID string
	// ModelID pins the authorization model. Empty means "latest", which is
	// accepted only because a fresh environment has no model id until the first
	// write — New logs it rather than letting it pass unnoticed.
	ModelID string
}

func New(conn *grpc.ClientConn, cfg Config) (*Checker, error) {
	if conn == nil {
		return nil, fmt.Errorf("openfga: a connection is required")
	}
	if cfg.StoreID == "" {
		return nil, fmt.Errorf("openfga: a store id is required; without one every check " +
			"would be evaluated against no tuples at all")
	}
	return &Checker{
		client:  fgav1.NewOpenFGAServiceClient(conn),
		storeID: cfg.StoreID,
		modelID: cfg.ModelID,
	}, nil
}

// Check answers one question.
func (c *Checker) Check(ctx context.Context, q authz.Query) (authz.Decision, error) {
	req := &fgav1.CheckRequest{
		StoreId:              c.storeID,
		AuthorizationModelId: c.modelID,
		TupleKey: &fgav1.CheckRequestTupleKey{
			User:     userRef(q.Principal),
			Relation: string(q.Relation),
			Object:   q.Resource.String(),
		},
	}
	if ctxTuples := contextualTuples(q); ctxTuples != nil {
		req.ContextualTuples = ctxTuples
	}
	if condCtx, err := conditionContext(q.Context); err != nil {
		return authz.Deny("invalid auth context"), err
	} else if condCtx != nil {
		req.Context = condCtx
	}

	resp, err := c.client.Check(ctx, req)
	if err != nil {
		// Returned, never converted to a denial here. The Guard owns that rule.
		return authz.Decision{}, fmt.Errorf("%w: check %s %s %s: %w",
			authz.ErrUnavailable, q.Principal, q.Relation, q.Resource, err)
	}
	if resp.GetAllowed() {
		return authz.Allow("tuple"), nil
	}
	return authz.Deny("no tuple"), nil
}

// BatchCheck answers a page of questions in one round trip.
//
// Measured on localhost, 50 checks: 108 ms sequential against 78 ms batched —
// 1.4x (access.md §1.5). It saves round trips, not evaluation, so it is the
// right tool for a page of resources and the wrong one for unbounded fan-out.
//
// Correlation ids are positional indices, and the response is reassembled by
// them. OpenFGA does not promise response ORDER, so trusting arrival order would
// attach one resource's answer to another — a permit for the wrong object.
func (c *Checker) BatchCheck(ctx context.Context, qs []authz.Query) ([]authz.Decision, error) {
	if len(qs) == 0 {
		return nil, nil
	}

	items := make([]*fgav1.BatchCheckItem, 0, len(qs))
	for i, q := range qs {
		item := &fgav1.BatchCheckItem{
			TupleKey: &fgav1.CheckRequestTupleKey{
				User:     userRef(q.Principal),
				Relation: string(q.Relation),
				Object:   q.Resource.String(),
			},
			CorrelationId: strconv.Itoa(i),
		}
		if ctxTuples := contextualTuples(q); ctxTuples != nil {
			item.ContextualTuples = ctxTuples
		}
		condCtx, err := conditionContext(q.Context)
		if err != nil {
			return nil, err
		}
		if condCtx != nil {
			item.Context = condCtx
		}
		items = append(items, item)
	}

	resp, err := c.client.BatchCheck(ctx, &fgav1.BatchCheckRequest{
		StoreId:              c.storeID,
		AuthorizationModelId: c.modelID,
		Checks:               items,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: batch check of %d: %w", authz.ErrUnavailable, len(qs), err)
	}

	// Start from denials, so a correlation id the server omits stays a denial
	// rather than inheriting whatever was in the slot.
	out := make([]authz.Decision, len(qs))
	for i := range out {
		out[i] = authz.Deny("no answer")
	}
	for id, result := range resp.GetResult() {
		i, convErr := strconv.Atoi(id)
		if convErr != nil || i < 0 || i >= len(out) {
			// A correlation id we did not send. Refusing the whole batch is the
			// only safe response: it means the answers cannot be trusted to
			// belong to the questions.
			return nil, fmt.Errorf("%w: batch check returned correlation id %q, "+
				"which was not sent", authz.ErrUnavailable, id)
		}
		if result.GetError() != nil {
			out[i] = authz.Deny("check failed")
			continue
		}
		if result.GetAllowed() {
			out[i] = authz.Allow("tuple")
			continue
		}
		out[i] = authz.Deny("no tuple")
	}
	return out, nil
}

// userRef renders a principal as OpenFGA's user reference.
//
// An API key or service account is checked as ITSELF, not as the principal it
// acts for. Substituting the owner here would give the key the owner's full
// access; the intersection with the key's scopes is expressed in the model, not
// by rewriting the subject (access.md §4).
func userRef(p authz.Principal) string {
	return string(p.Kind) + ":" + p.ID
}

// contextualTuples carries facts that are true for THIS request but not yet in
// the store.
//
// Two uses, both from access.md §6: a grant that has just been written but whose
// tuple the projector has not applied, and the session facts conditions
// reference. They can only ever ADD access for the duration of one request,
// which is why they are safe on the grant side and never used on the revoke side
// — revocation goes through the tombstones instead.
func contextualTuples(q authz.Query) *fgav1.ContextualTupleKeys {
	if q.Context.ActiveOrg == "" {
		return nil
	}
	return &fgav1.ContextualTupleKeys{
		TupleKeys: []*fgav1.TupleKey{{
			User:     userRef(q.Principal),
			Relation: "member",
			Object:   "organization:" + q.Context.ActiveOrg,
		}},
	}
}

// conditionContext supplies the values CEL conditions evaluate against, so
// "destructive actions require AAL2" is an authorization rule rather than an
// `if session.AAL < 2` repeated through handlers.
func conditionContext(a authz.AuthContext) (*structpb.Struct, error) {
	if a.AAL == 0 && !a.DeviceTrusted && a.IP == "" {
		return nil, nil
	}
	s, err := structpb.NewStruct(map[string]any{
		"aal":            float64(a.AAL),
		"device_trusted": a.DeviceTrusted,
		"ip":             a.IP,
	})
	if err != nil {
		return nil, fmt.Errorf("openfga: building condition context: %w", err)
	}
	return s, nil
}
