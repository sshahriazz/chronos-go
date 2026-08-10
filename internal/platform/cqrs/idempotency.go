package cqrs

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Idempotency errors. Separate values because a caller must be able to tell
// "you sent the same key with a different body" (a client bug, CONFLICT) from
// "we could not tell" (an infrastructure fault).
var (
	// ErrKeyReused is the same key with a DIFFERENT body.
	ErrKeyReused = errors.New("cqrs: idempotency key reused with a different request")

	// ErrInFlight is a duplicate that arrived while the first is still running
	// and could not be waited for.
	ErrInFlight = errors.New("cqrs: an identical request is already in flight")

	// ErrStoreUnavailable means the idempotency record could not be read or
	// written.
	ErrStoreUnavailable = errors.New("cqrs: idempotency store unavailable")
)

// KeyTTL is how long a record is kept (CONVENTIONS §6).
//
// It bounds how long a replay is possible, not how long the effect lasts. A day
// covers a client retrying through an outage; longer would keep responses — which
// can contain personal data — well past any use.
const KeyTTL = 24 * time.Hour

// Key is the client-generated `Idempotency-Key` header.
type Key string

// Scope is what a key is unique WITHIN: (principal, operation, key).
//
// The principal is not decoration. Without it, one tenant sending another's key
// is handed that request's stored response — a cross-tenant read through a
// header, reachable by anyone who can guess a ULID. The operation is there for
// the milder version of the same mistake: the same key on two different RPCs.
type Scope struct {
	Principal string
	Operation string
	Key       Key
}

func (s Scope) String() string {
	return s.Principal + "|" + s.Operation + "|" + string(s.Key)
}

// Validate rejects a scope that must never reach the store.
func (s Scope) Validate() error {
	switch {
	case s.Principal == "":
		return fmt.Errorf("%w: an idempotency scope has no principal; one tenant's key would "+
			"replay another's response", ErrInvalid)
	case s.Operation == "":
		return fmt.Errorf("%w: an idempotency scope has no operation", ErrInvalid)
	case s.Key == "":
		return fmt.Errorf("%w: no idempotency key; every mutating RPC requires one", ErrInvalid)
	}
	// '|' separates the parts of the stored key. A value carrying one could
	// address a different scope than the caller named — the same class of bug as
	// a reserved character in an authorization reference.
	if strings.ContainsAny(s.Principal, "|") || strings.ContainsAny(s.Operation, "|") ||
		strings.ContainsAny(string(s.Key), "|") {
		return fmt.Errorf("%w: an idempotency scope contains the reserved separator '|'",
			ErrInvalid)
	}
	return nil
}

// Fingerprint hashes a request body.
//
// Stored alongside the response so a replay can be told apart from a reused key.
// SHA-256 rather than something cheaper because a collision here does not fail —
// it returns a DIFFERENT request's response as if it were this one's.
func Fingerprint(body []byte) [32]byte { return sha256.Sum256(body) }

// State is what the store found for a scope.
type State int

const (
	// StateNew: nothing recorded. The caller holds the claim and must execute.
	StateNew State = iota

	// StateDone: a completed response is stored.
	StateDone

	// StateRunning: another request holds the claim and has not finished.
	StateRunning
)

// Record is a stored idempotency entry.
type Record struct {
	State State

	// Fingerprint of the body the FIRST request carried.
	Fingerprint [32]byte

	// Response is the stored reply, present only when State is StateDone.
	Response []byte
}

// Store persists idempotency records. Implemented in adapter/postgres.
//
// Claim must be atomic: two concurrent requests with the same scope must not
// both receive StateNew, or a double-click executes twice — which is the entire
// thing this gate exists to prevent.
type Store interface {
	// Claim records an intent to execute and reports what was already there.
	// Exactly one concurrent caller may receive StateNew.
	Claim(ctx context.Context, s Scope, fp [32]byte, ttl time.Duration) (Record, error)

	// Complete stores the response against a claim this caller holds.
	Complete(ctx context.Context, s Scope, response []byte) error

	// Release drops a claim whose execution failed, so a retry can run.
	Release(ctx context.Context, s Scope) error
}

// Once runs a mutation at most once per scope.
//
// The order is the design:
//
//  1. Validate the scope. A missing principal is refused before anything is
//     stored.
//  2. Claim. Atomic, so concurrent duplicates cannot both proceed.
//  3. If a record exists and the body MATCHES, return the stored response
//     without executing.
//  4. If a record exists and the body DIFFERS, refuse. Never return the stored
//     response — that is somebody else's answer to a different question.
//  5. Execute, then record the response.
//  6. On failure, RELEASE the claim so a retry can run. A failed attempt that
//     kept its claim would make a transient error permanent for a day.
type Once struct {
	store Store
	ttl   time.Duration

	// wait is how a duplicate that arrives mid-execution is handled. Zero means
	// do not wait — report ErrInFlight and let the client retry.
	wait  time.Duration
	sleep func(context.Context, time.Duration) bool
}

// OnceDeps is what a Once needs.
type OnceDeps struct {
	// Store is required. An optional one would mean a deployment could lose the
	// gate silently, and a double-click executing twice looks exactly like a
	// client sending two requests.
	Store Store

	// TTL bounds a stored record. Zero takes KeyTTL.
	TTL time.Duration

	// Wait is how long to wait for an in-flight duplicate to finish before
	// giving up. Zero does not wait.
	Wait time.Duration

	// Sleep is injectable so a test can exercise the wait without spending it.
	// It reports false when the context ended.
	Sleep func(context.Context, time.Duration) bool
}

// MaxTTL caps how long a response may be replayable. A record kept longer is a
// response — possibly carrying personal data — retained past any use for it.
const MaxTTL = 7 * 24 * time.Hour

func NewOnce(d OnceDeps) (*Once, error) {
	if d.Store == nil {
		return nil, fmt.Errorf("cqrs: an idempotency Store is required; without one a " +
			"double-click executes twice and looks identical to two requests")
	}
	if d.TTL <= 0 {
		d.TTL = KeyTTL
	}
	if d.TTL > MaxTTL {
		return nil, fmt.Errorf("cqrs: an idempotency TTL of %s exceeds the %s cap", d.TTL, MaxTTL)
	}
	if d.Wait < 0 {
		return nil, fmt.Errorf("%w: a negative in-flight wait", ErrInvalid)
	}
	if d.Sleep == nil {
		d.Sleep = sleep
	}
	return &Once{store: d.Store, ttl: d.TTL, wait: d.Wait, sleep: d.Sleep}, nil
}

// pollInterval is how often an in-flight duplicate re-checks. Short, because the
// request it is waiting on is a single mutation, not a workflow.
const pollInterval = 25 * time.Millisecond

// Do executes fn at most once for this scope and body.
//
// fn returns the response to store. It is called only when this caller holds the
// claim; a replay never reaches it.
func (o *Once) Do(
	ctx context.Context, s Scope, body []byte, fn func(context.Context) ([]byte, error),
) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	fp := Fingerprint(body)

	deadline := time.Time{}
	for {
		rec, err := o.store.Claim(ctx, s, fp, o.ttl)
		if err != nil {
			// NOT executed. Running anyway would defeat the gate exactly when it
			// is most needed — a store that is struggling is a store under the
			// retry storm the gate exists for.
			return nil, fmt.Errorf("%w: claiming %s: %w", ErrStoreUnavailable, s, err)
		}

		switch rec.State {
		case StateNew:
			return o.execute(ctx, s, fn)

		case StateDone:
			if rec.Fingerprint != fp {
				// The stored response is NOT returned. Handing back an answer to
				// a different question is worse than refusing: the client
				// believes its request succeeded.
				return nil, fmt.Errorf("%w: %s", ErrKeyReused, s)
			}
			return rec.Response, nil

		case StateRunning:
			if rec.Fingerprint != fp {
				return nil, fmt.Errorf("%w: %s", ErrKeyReused, s)
			}
			if o.wait == 0 {
				return nil, fmt.Errorf("%w: %s", ErrInFlight, s)
			}
			if deadline.IsZero() {
				// Set from the FIRST observation, so the wait bounds the whole
				// duplicate rather than resetting on every poll.
				deadline = time.Now().Add(o.wait)
			}
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("%w: %s", ErrInFlight, s)
			}
			if !o.sleep(ctx, pollInterval) {
				return nil, ctx.Err()
			}

		default:
			return nil, fmt.Errorf("%w: unknown idempotency state %d", ErrInvalid, rec.State)
		}
	}
}

// execute runs the handler and records its response.
func (o *Once) execute(
	ctx context.Context, s Scope, fn func(context.Context) ([]byte, error),
) ([]byte, error) {
	resp, err := fn(ctx)
	if err != nil {
		// Release, so a retry can run. Keeping the claim would turn a transient
		// failure into a permanent one for the whole TTL, and the client's
		// retries — with the same key, correctly — would all be refused.
		//
		// WithoutCancel: the request context may already be cancelled, which is
		// often exactly why fn failed, and the release still has to happen.
		if rerr := o.store.Release(context.WithoutCancel(ctx), s); rerr != nil {
			return nil, errors.Join(err, fmt.Errorf("%w: releasing %s: %w",
				ErrStoreUnavailable, s, rerr))
		}
		return nil, err
	}
	if cerr := o.store.Complete(ctx, s, resp); cerr != nil {
		// The effect ALREADY happened. Reporting a failure here would make the
		// client retry a mutation that succeeded, and the claim it would hit is
		// still marked running — so the response is returned and the failure to
		// record it is the error the caller sees alongside it.
		return resp, fmt.Errorf("%w: recording the response for %s: %w",
			ErrStoreUnavailable, s, cerr)
	}
	return resp, nil
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
