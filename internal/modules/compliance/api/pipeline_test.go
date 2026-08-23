package api_test

import (
	"context"
	"sync"
	"time"

	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/cqrs"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

// The gate pipeline's collaborators, stubbed.
//
// They are here rather than inline because the POINT of running the real
// pipeline is that a handler receives its principal the way production leaves it
// — from a context key no test package can write. Everything else the gates need
// is scaffolding, and scaffolding that permits everything is correct here: what
// these tests assert is what the HANDLER does with a caller, not what the gates
// do with a policy, which internal/server/interceptor covers.

type stubAuthenticator struct {
	principal interceptor.Principal
	err       error
}

func (s stubAuthenticator) Authenticate(
	_ context.Context, _ interceptor.Header,
) (interceptor.Principal, error) {
	return s.principal, s.err
}

type stubOrgResolver struct{}

func (stubOrgResolver) Resolve(
	ctx context.Context, _ interceptor.Principal, _ interceptor.Header,
) (context.Context, error) {
	return ctx, nil
}

type allowChecker struct{}

func (allowChecker) Check(_ context.Context, _ authz.Query) (authz.Decision, error) {
	return authz.Allow("test"), nil
}

func (allowChecker) BatchCheck(_ context.Context, qs []authz.Query) ([]authz.Decision, error) {
	out := make([]authz.Decision, len(qs))
	for i := range out {
		out[i] = authz.Allow("test")
	}
	return out, nil
}

type stubSubscriptions struct{}

func (stubSubscriptions) Permit(_ context.Context, _ optionsv1.OperationClass) error { return nil }

// memStore is an in-memory cqrs.Store, enough to make gate 5 real.
type memStore struct {
	mu      sync.Mutex
	records map[string]cqrs.Record
}

func newMemStore() *memStore { return &memStore{records: map[string]cqrs.Record{}} }

func (m *memStore) Claim(
	_ context.Context, s cqrs.Scope, fp [32]byte, _ time.Duration,
) (cqrs.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.records[s.String()]; ok {
		return r, nil
	}
	m.records[s.String()] = cqrs.Record{State: cqrs.StateRunning, Fingerprint: fp}
	return cqrs.Record{State: cqrs.StateNew, Fingerprint: fp}, nil
}

func (m *memStore) Complete(_ context.Context, s cqrs.Scope, response []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.records[s.String()]
	r.State = cqrs.StateDone
	r.Response = response
	m.records[s.String()] = r
	return nil
}

func (m *memStore) Release(_ context.Context, s cqrs.Scope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, s.String())
	return nil
}
