package interceptor

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/chronos/chronos-go/internal/platform/cqrs"
	"github.com/chronos/chronos-go/internal/platform/errs"
	srvconnect "github.com/chronos/chronos-go/internal/server/connect"
	"github.com/chronos/chronos-go/internal/server/policy"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// IdempotencyHeader is the client-generated key every mutating RPC must carry.
const IdempotencyHeader = "Idempotency-Key"

// Idempotency is gate 5 (CONVENTIONS §6).
//
// It wraps the handler rather than running before it, because the gate is not a
// check — it is an execution strategy. "Has this key been used?" answered before
// the handler is a race; the claim and the execution have to be the same
// operation, which is what cqrs.Once provides.
//
// The response codec is deliberately NOT injectable. It was, briefly: two
// function fields documented as a seam a test could substitute to exercise a
// replay without a real proto message. They were unexported, with no setter and
// no export_test.go, so nothing could ever substitute them. A comment promising
// an affordance that does not exist is worse than no comment — a reader trusts
// the replay path has a cheap test hook and stops looking for the real one.
//
// The replay path is driven end to end through the real pipeline instead, which
// is the better test anyway: it exercises the actual dynamicpb decode against
// the actual method descriptor, which a substituted codec would have skipped.
type Idempotency struct {
	once *cqrs.Once
}

// NewIdempotency builds gate 5.
func NewIdempotency(once *cqrs.Once) (*Idempotency, error) {
	if once == nil {
		return nil, fmt.Errorf("interceptor: an idempotency gate needs a cqrs.Once; without " +
			"one every mutation is ungated and a double-click executes it twice")
	}
	return &Idempotency{once: once}, nil
}

// Do runs the handler at most once for this key.
//
// A READ passes straight through. Requiring a key on reads would make every list
// endpoint carry one for no benefit, and storing a read's response is retained
// data with no purpose (ADR-002).
func (i *Idempotency) Do(
	ctx context.Context, p policy.Policy, req connect.AnyRequest,
	next func(context.Context) (connect.AnyResponse, error),
) (connect.AnyResponse, error) {
	if !p.Mutating() {
		return next(ctx)
	}

	key := req.Header().Get(IdempotencyHeader)
	if key == "" {
		// Refused, not defaulted. Generating a key server-side would make every
		// retry look like a new request — the exact failure the header exists to
		// prevent, with the added insult of looking like it was handled.
		//
		// Deliberately redundant, and the redundancy was MEASURED rather than
		// assumed. Deleting this block leaves two more layers that also refuse:
		// cqrs.Scope.Validate, called by scopeFrom below, and the same Validate
		// called again at the top of cqrs.Once.Do. With this block removed the
		// handler still does not run — so the safety property survives — but what
		// the CLIENT is told degrades at every layer:
		//
		//	this block      InvalidArgument "Idempotency-Key is required on every mutating request"
		//	scopeFrom       InvalidArgument "cqrs: invalid: no idempotency key; every mutating RPC requires one"
		//	cqrs.Once.Do    Unknown         same text, having never passed through errs at all
		//
		// Only the first names the header the client has to set, and only the
		// first keeps an internal package name off the wire. The layers below are
		// the backstop for a caller that reaches cqrs by another route; this one
		// exists so the HTTP client gets an answer it can act on.
		return nil, srvconnect.Error(errs.ValidationFailedf(
			"%s is required on every mutating request", IdempotencyHeader))
	}

	scope, err := scopeFrom(ctx, p, key)
	if err != nil {
		return nil, srvconnect.Error(errs.ValidationFailedf("%s", err))
	}

	// Every event this request writes inherits the chain from here. Attached
	// after the key is known and before the handler runs, because the key IS the
	// command's identity and the log cannot be amended once written.
	ctx = withCausation(ctx, key)

	body, err := marshalRequest(req)
	if err != nil {
		return nil, srvconnect.Error(errs.Internalf("cannot fingerprint the request").Wrap(err))
	}

	var response connect.AnyResponse
	stored, err := i.once.Do(ctx, scope, body, func(ctx context.Context) ([]byte, error) {
		resp, herr := next(ctx)
		if herr != nil {
			return nil, herr
		}
		response = resp
		return marshalResponse(resp)
	})

	switch {
	case errors.Is(err, cqrs.ErrKeyReused):
		// CONFLICT names the client's bug precisely. Returning the stored
		// response instead would tell them their request succeeded when a
		// different one is what ran.
		return nil, srvconnect.Error(errs.Conflictf(
			"this %s was already used for a different request", IdempotencyHeader))
	case errors.Is(err, cqrs.ErrInFlight):
		return nil, srvconnect.Error(errs.Conflictf(
			"an identical request is still in progress; retry with the same %s",
			IdempotencyHeader))
	case errors.Is(err, cqrs.ErrStoreUnavailable):
		// The gate could not be applied, so the mutation did NOT run. Reporting
		// success here, or running it anyway, both defeat the gate exactly when
		// clients are retrying hardest.
		return nil, srvconnect.Error(errs.Internalf("idempotency is unavailable").Wrap(err))
	case err != nil:
		// The handler's own error. It is already a domain error and has already
		// been through the disclosure ladder.
		return nil, err
	}

	if response != nil {
		// This caller executed. Return the live response rather than the
		// deserialized one — identical content, but no round trip through the
		// codec on the common path.
		return response, nil
	}
	// A replay: somebody else executed, and this is their stored answer.
	return unmarshalResponse(req, stored)
}

// scopeFrom builds the idempotency scope for this request.
//
// The principal comes from the CONTEXT, never from a header. A client-supplied
// principal would let one tenant scope their key to another's, which is the
// cross-tenant read the scope exists to prevent.
func scopeFrom(ctx context.Context, p policy.Policy, key string) (cqrs.Scope, error) {
	principal, ok := PrincipalFrom(ctx)
	if !ok {
		return cqrs.Scope{}, errors.New("no authenticated principal")
	}
	s := cqrs.Scope{
		Principal: principal.Subject.String(),
		Operation: p.Method,
		Key:       cqrs.Key(key),
	}
	return s, s.Validate()
}

// marshalRequest produces the bytes the fingerprint is taken over.
//
// Deterministic marshalling, because protobuf's default is explicitly NOT
// deterministic: map field ordering varies between calls, so the same request
// would fingerprint differently on a retry and a genuine replay would be
// reported as a reused key.
func marshalRequest(req connect.AnyRequest) ([]byte, error) {
	m, ok := req.Any().(proto.Message)
	if !ok {
		return nil, fmt.Errorf("request is a %T, not a proto message", req.Any())
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(m)
}

func marshalResponse(resp connect.AnyResponse) ([]byte, error) {
	m, ok := resp.Any().(proto.Message)
	if !ok {
		return nil, fmt.Errorf("response is a %T, not a proto message", resp.Any())
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return nil, err
	}
	if b == nil {
		// A nil slice is how the store spells "no response recorded". Returning
		// one here would record a COMPLETED claim with an absent response, and
		// the client's retry — taking the replay path — would be told the
		// mutation stored nothing, after it had already run.
		//
		// Reachable, and measured rather than assumed. proto.Marshal returns a
		// non-nil zero-length slice for every real message, empty or not:
		//
		//	&systemv1.GetStatusResponse{}  b == nil: false, len 0
		//	&emptypb.Empty{}               b == nil: false, len 0
		//	dynamicpb.NewMessage(Empty)    b == nil: false, len 0
		//	(*emptypb.Empty)(nil)          b == nil: TRUE,  len 0
		//
		// The last row is the one that matters: a TYPED NIL marshals to a nil
		// slice with a NIL error, so nothing upstream reports a problem. A
		// service layer returning (nil, nil) into connect.NewResponse is an
		// everyday Go mistake, not a contrived one — which is why this is
		// normalization rather than defence against the impossible.
		b = []byte{}
	}
	return b, nil
}

// unmarshalResponse rebuilds a stored response.
//
// The response TYPE comes from the request's own spec — Connect sets
// Spec.Schema to the protoreflect.MethodDescriptor for protobuf RPCs — so a
// replay decodes into exactly the type this method returns. Storing the type
// name beside the bytes would be the other option and a worse one: it makes the
// stored record self-describing, so a record written by an older schema decodes
// happily into a type that has since changed meaning.
//
// Decoding against the CURRENT descriptor means a schema change that would
// misinterpret the bytes fails loudly here instead.
func unmarshalResponse(req connect.AnyRequest, stored []byte) (connect.AnyResponse, error) {
	if stored == nil {
		// nil, not len == 0. An empty message marshals to ZERO BYTES and is a
		// perfectly ordinary response — a Delete that returns google.protobuf.Empty
		// is the common case, not an edge one. Rejecting on length would refuse
		// every retry of such a method, which is the opposite of what the gate is
		// for. Only a nil slice means the store had nothing.
		return nil, fmt.Errorf("a completed idempotency record stored no response at all")
	}
	md, ok := req.Spec().Schema.(protoreflect.MethodDescriptor)
	if !ok {
		return nil, fmt.Errorf("request spec carries a %T, not a method descriptor, so the "+
			"response type is unknown", req.Spec().Schema)
	}
	// dynamicpb, not the generated Go type, and not by choice.
	//
	// connect.AnyResponse is sealed — it carries an unexported internalOnly()
	// method — so the only way to build one is connect.NewResponse[T], whose T
	// must be known at COMPILE time. An interceptor sees every method, so it
	// never is. Go cannot instantiate a generic function reflectively, which
	// rules out looking the concrete type up in protoregistry and calling
	// NewResponse on it.
	//
	// A *dynamicpb.Message is a concrete type that satisfies proto.Message, so
	// T = dynamicpb.Message compiles, and it marshals to exactly the same bytes
	// as the generated type would: the descriptor is the same, and the wire
	// format is defined by the descriptor.
	//
	// The tempting-looking alternative, connect.NewResponse(&msg) with msg a
	// proto.Message, is a pointer to the INTERFACE — *proto.Message does not
	// implement proto.Message, so the codec fails at marshal time, on the replay
	// path only, long after the code looked right.
	msg := dynamicpb.NewMessage(md.Output())
	if err := proto.Unmarshal(stored, msg); err != nil {
		return nil, fmt.Errorf("stored response does not decode as %s: %w",
			md.Output().FullName(), err)
	}
	return connect.NewResponse(msg), nil
}
