// Package api_test drives profile's handlers through a REAL Connect server: a
// real HTTP listener, the real enforcement pipeline (ADR-021), the real
// protovalidate interceptor, and the generated client.
//
// # Why not call the handler methods directly
//
// Because the property most worth testing here is unreachable that way. A
// principal can ONLY be put into a context by `interceptor.withPrincipal`, which
// is unexported and called by the authn gate alone — deliberately, so a handler
// cannot forge one. A test that called `s.GetProfile(ctx, req)` would therefore
// be testing the "no principal" branch forever, and the self-scoping this whole
// service depends on would never execute.
//
// So the pipeline runs. What is substituted is only the two things a unit test
// has no business starting: the authenticator (a stub that returns whichever
// principal the case wants) and the use cases (in-memory fakes). Everything
// between them is production code.
package api_test

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	validatepb "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"connectrpc.com/connect"
	validate "connectrpc.com/validate"
	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	profilev1 "github.com/chronos/chronos-go/gen/proto/chronos/profile/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/profile/v1/profilev1connect"
	profileapi "github.com/chronos/chronos-go/internal/modules/profile/api"
	"github.com/chronos/chronos-go/internal/modules/profile/app"
	"github.com/chronos/chronos-go/internal/modules/profile/domain"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/cqrs"
	srvconnect "github.com/chronos/chronos-go/internal/server/connect"
	"github.com/chronos/chronos-go/internal/server/interceptor"
	"github.com/chronos/chronos-go/internal/server/policy"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	alice = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	bob   = "subj_01BX5ZZKBKACTAV9WEVGEMMVRZ"
)

// ---------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------

// stubAuthn is the ONE production component this test replaces, and it is
// replaced because starting a real session store is not what these cases are
// about. It answers with whatever principal the case installed.
type stubAuthn struct {
	mu        sync.Mutex
	principal interceptor.Principal
	err       error
}

func (s *stubAuthn) Authenticate(context.Context, interceptor.Header) (interceptor.Principal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return interceptor.Principal{}, s.err
	}
	return s.principal, nil
}

func (s *stubAuthn) as(subjectID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = nil
	s.principal = interceptor.Principal{
		Subject: authz.Principal{Kind: authz.KindUser, ID: subjectID},
		AAL:     optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1,
	}
}

func (s *stubAuthn) asKind(kind authz.PrincipalKind, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = nil
	s.principal = interceptor.Principal{
		Subject: authz.Principal{Kind: kind, ID: id},
		AAL:     optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1,
	}
}

func (s *stubAuthn) anonymous() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = errors.New("no session")
}

// memoryOnce is an in-memory idempotency store. Gate 5 refuses every mutation
// when it is absent, so a test of a mutating RPC has to supply one.
type memoryOnce struct {
	mu      sync.Mutex
	records map[string]cqrs.Record
}

func newMemoryOnce() *memoryOnce { return &memoryOnce{records: map[string]cqrs.Record{}} }

func (m *memoryOnce) key(s cqrs.Scope) string { return s.String() }

func (m *memoryOnce) Claim(
	_ context.Context, s cqrs.Scope, fp [32]byte, _ time.Duration,
) (cqrs.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rec, ok := m.records[m.key(s)]; ok {
		return rec, nil
	}
	rec := cqrs.Record{State: cqrs.StateNew, Fingerprint: fp}
	m.records[m.key(s)] = cqrs.Record{State: cqrs.StateRunning, Fingerprint: fp}
	return rec, nil
}

func (m *memoryOnce) Complete(_ context.Context, s cqrs.Scope, response []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec := m.records[m.key(s)]
	rec.State = cqrs.StateDone
	rec.Response = response
	m.records[m.key(s)] = rec
	return nil
}

func (m *memoryOnce) Release(_ context.Context, s cqrs.Scope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, m.key(s))
	return nil
}

// fakeQueries, fakeUpdates and fakeAvatars record what the handler asked for.
// Every one of them stores the SUBJECT it was called with, because "which
// person did the handler act on" is the question these tests exist to answer.

type fakeQueries struct {
	mu      sync.Mutex
	calls   []string
	profile app.Profile
	err     error
}

func (f *fakeQueries) Get(_ context.Context, subjectID string) (app.Profile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, subjectID)
	if f.err != nil {
		return app.Profile{}, f.err
	}
	p := f.profile
	p.SubjectID = subjectID
	return p, nil
}

type fakeUpdates struct {
	mu    sync.Mutex
	calls []app.UpdateCommand
	err   error
}

func (f *fakeUpdates) Update(_ context.Context, cmd app.UpdateCommand) (app.Profile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, cmd)
	if f.err != nil {
		return app.Profile{}, f.err
	}
	return app.Profile{SubjectID: cmd.SubjectID}, nil
}

func (f *fakeUpdates) last() app.UpdateCommand {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

type fakeAvatars struct {
	mu    sync.Mutex
	calls []app.UploadGrantCommand
	err   error
}

func (f *fakeAvatars) Grant(
	_ context.Context, cmd app.UploadGrantCommand,
) (app.UploadGrant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, cmd)
	if f.err != nil {
		return app.UploadGrant{}, f.err
	}
	return app.UploadGrant{
		URL:       "https://objects.example/bucket",
		Fields:    []app.GrantField{{Key: "key", Value: "v"}},
		ObjectKey: domain.AvatarPrefix(cmd.SubjectID) + "/aaaaaaaaaaaaaaaaaaaaaaaaaa",
		Expires:   time.Date(2026, 8, 21, 10, 10, 0, 0, time.UTC),
		MaxBytes:  cmd.SizeBytes,
	}, nil
}

type server struct {
	client  profilev1connect.ProfileServiceClient
	authn   *stubAuthn
	queries *fakeQueries
	updates *fakeUpdates
	avatars *fakeAvatars
}

// newServer starts the real pipeline over fake use cases.
func newServer(t *testing.T) *server {
	t.Helper()

	s := &server{
		authn:   &stubAuthn{},
		queries: &fakeQueries{},
		updates: &fakeUpdates{},
		avatars: &fakeAvatars{},
	}
	s.authn.as(alice)

	svc, err := profileapi.New(profileapi.Deps{
		Queries: s.queries, Updates: s.updates, Avatars: s.avatars,
	})
	if err != nil {
		t.Fatalf("profileapi.New: %v", err)
	}

	// THE REAL POLICY SET, loaded from the compiled descriptor — the same call
	// cmd/api makes. A method with no annotation fails here, which is exactly
	// how ADR-021's "declare or do not boot" rule shows up in a test.
	policies, err := policy.Load(profilev1connect.ProfileServiceName)
	if err != nil {
		t.Fatalf("policy.Load: %v", err)
	}

	once, err := cqrs.NewOnce(cqrs.OnceDeps{Store: newMemoryOnce()})
	if err != nil {
		t.Fatalf("cqrs.NewOnce: %v", err)
	}
	idem, err := interceptor.NewIdempotency(once)
	if err != nil {
		t.Fatalf("interceptor.NewIdempotency: %v", err)
	}

	gates, err := interceptor.NewGates(interceptor.Deps{
		Policies: policies,
		Authn:    s.authn,
		// Org, Authz, Subscriptions and Entitlements are nil, exactly as cmd/api
		// leaves them today. Every method in this service is self-scoped and
		// declares none of them, so a method that started needing one would be
		// REFUSED here rather than silently ungated — which is the assertion
		// TestEveryMethodIsSelfScoped makes explicit.
		Idempotency: idem,
	})
	if err != nil {
		t.Fatalf("interceptor.NewGates: %v", err)
	}

	// The gates go FIRST, which makes them outermost — the ADR-021 order cmd/api
	// uses. Validation ahead of authentication would answer an unauthenticated
	// caller with a field-level description of a request they were never
	// entitled to make.
	opts := []connect.HandlerOption{
		connect.WithInterceptors(gates, validate.NewInterceptor()),
	}
	opts = append(opts, srvconnect.JSONOptions()...)

	_, handler := profilev1connect.NewProfileServiceHandler(svc, opts...)
	httpsrv := httptest.NewServer(handler)
	t.Cleanup(httpsrv.Close)

	s.client = profilev1connect.NewProfileServiceClient(httpsrv.Client(), httpsrv.URL)
	return s
}

// withKey attaches the idempotency header every mutating RPC needs.
func withKey[T any](req *connect.Request[T], key string) *connect.Request[T] {
	req.Header().Set(interceptor.IdempotencyHeader, key)
	return req
}

// ---------------------------------------------------------------------------
// Self-scoping
// ---------------------------------------------------------------------------

// TestEveryRPCActsOnTheAuthenticatedCallerAndNobodyElse is the central property
// of this service.
//
// The subject the use case receives must be the one the AUTHENTICATOR produced.
// Nothing else can influence it, because no request message has a field for it —
// which is the schema's job, asserted separately below.
func TestEveryRPCActsOnTheAuthenticatedCallerAndNobodyElse(t *testing.T) {
	t.Parallel()

	s := newServer(t)
	ctx := context.Background()

	for _, who := range []string{alice, bob} {
		s.authn.as(who)

		if _, err := s.client.GetProfile(ctx,
			connect.NewRequest(&profilev1.GetProfileRequest{})); err != nil {
			t.Fatalf("GetProfile as %s: %v", who, err)
		}
		got := s.queries.calls[len(s.queries.calls)-1]
		if got != who {
			t.Fatalf("GetProfile read the profile of %q while %q was authenticated", got, who)
		}

		if _, err := s.client.UpdateProfile(ctx, withKey(
			connect.NewRequest(&profilev1.UpdateProfileRequest{
				DisplayName: ptr("Ada"),
			}), "key-"+who)); err != nil {
			t.Fatalf("UpdateProfile as %s: %v", who, err)
		}
		if got := s.updates.last().SubjectID; got != who {
			t.Fatalf("UpdateProfile changed the profile of %q while %q was authenticated",
				got, who)
		}

		if _, err := s.client.CreateAvatarUpload(ctx, withKey(
			connect.NewRequest(&profilev1.CreateAvatarUploadRequest{
				ContentType: "image/png", SizeBytes: 1024,
			}), "avatar-"+who)); err != nil {
			t.Fatalf("CreateAvatarUpload as %s: %v", who, err)
		}
		last := s.avatars.calls[len(s.avatars.calls)-1]
		if last.SubjectID != who {
			t.Fatalf("CreateAvatarUpload minted a grant for %q while %q was authenticated",
				last.SubjectID, who)
		}
	}
}

// TestNoRequestMessageCanNameASubject is the schema half of the same property,
// checked against the DESCRIPTOR rather than by reading the .proto.
//
// A field added later called `subject_id`, `user_id` or `account_id` would give
// a caller somewhere to put a person who is not them, and the handler's own
// discipline would be the only thing standing in the way. This makes it fail at
// the schema instead.
func TestNoRequestMessageCanNameASubject(t *testing.T) {
	t.Parallel()

	forbidden := []string{"subject_id", "user_id", "account_id", "principal_id", "email"}
	svc := profilev1.File_chronos_profile_v1_profile_proto.Services().ByName("ProfileService")
	if svc == nil {
		t.Fatal("ProfileService is not in the descriptor")
	}

	for i := range svc.Methods().Len() {
		m := svc.Methods().Get(i)
		fields := m.Input().Fields()
		for j := range fields.Len() {
			name := string(fields.Get(j).Name())
			for _, bad := range forbidden {
				if name == bad {
					t.Fatalf("%s.%s carries a %q field. Every RPC in this service acts on "+
						"the CALLER, whose pseudonym comes from the session; a field naming "+
						"somebody else turns UpdateProfile into a way to rename a colleague",
						m.Name(), m.Input().Name(), name)
				}
			}
		}
	}
}

func TestUnauthenticatedRequestsAreRefused(t *testing.T) {
	t.Parallel()

	s := newServer(t)
	s.authn.anonymous()

	_, err := s.client.GetProfile(context.Background(),
		connect.NewRequest(&profilev1.GetProfileRequest{}))
	if err == nil {
		t.Fatal("an unauthenticated caller read a profile")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated", got)
	}
	if len(s.queries.calls) != 0 {
		t.Fatal("the handler ran for an unauthenticated caller")
	}
}

// TestAMachineCredentialCannotActAsAPerson — an API key's principal carries the
// KEY's identifier, not a person's pseudonym, so reading it as a subject would
// let a machine credential rename whatever account that string happened to
// name.
func TestAMachineCredentialCannotActAsAPerson(t *testing.T) {
	t.Parallel()

	for _, kind := range []authz.PrincipalKind{authz.KindAPIKey, authz.KindServiceAccount} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			t.Parallel()
			s := newServer(t)
			s.authn.asKind(kind, "key_01ARZ3NDEKTSV4RRFFQ69G5FAV")

			_, err := s.client.UpdateProfile(context.Background(), withKey(
				connect.NewRequest(&profilev1.UpdateProfileRequest{DisplayName: ptr("Ada")}),
				"k1"))
			if err == nil {
				t.Fatal("a machine credential changed a person's profile")
			}
			if len(s.updates.calls) != 0 {
				t.Fatal("the handler ran for a machine credential")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The sparse mapping
// ---------------------------------------------------------------------------

// TestSparsenessSurvivesTheWire is the end-to-end version of the sparse
// contract, and the one that catches the easiest mistake in this layer: reading
// an optional field with GetXxx(), which returns "" for an absent field and
// collapses "leave it alone" into "empty it".
func TestSparsenessSurvivesTheWire(t *testing.T) {
	t.Parallel()

	s := newServer(t)
	ctx := context.Background()

	if _, err := s.client.UpdateProfile(ctx, withKey(
		connect.NewRequest(&profilev1.UpdateProfileRequest{
			Timezone: ptr("Europe/Berlin"),
		}), "k1")); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}

	cmd := s.updates.last()
	if cmd.Timezone == nil || *cmd.Timezone != "Europe/Berlin" {
		t.Fatalf("Timezone = %v, want Europe/Berlin", cmd.Timezone)
	}
	for _, f := range []struct {
		name string
		got  *string
	}{
		{"DisplayName", cmd.DisplayName}, {"Locale", cmd.Locale},
		{"AvatarObjectKey", cmd.AvatarObjectKey},
	} {
		if f.got != nil {
			t.Fatalf("%s = %q, want nil. The caller did not send it, and a non-nil "+
				"pointer here is an instruction to change it — which for the avatar "+
				"means removing it", f.name, *f.got)
		}
	}
}

// TestClearingTheAvatarIsDistinguishableFromNotMentioningIt is the other half,
// over real HTTP: an explicitly-sent empty string must arrive as a non-nil
// pointer to "".
func TestClearingTheAvatarIsDistinguishableFromNotMentioningIt(t *testing.T) {
	t.Parallel()

	s := newServer(t)
	if _, err := s.client.UpdateProfile(context.Background(), withKey(
		connect.NewRequest(&profilev1.UpdateProfileRequest{
			AvatarObjectKey: ptr(""),
		}), "k1")); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}

	cmd := s.updates.last()
	if cmd.AvatarObjectKey == nil {
		t.Fatal("an explicitly-empty avatar key arrived as nil, so 'remove my avatar' " +
			"is indistinguishable from 'leave it alone' by the time it reaches the app layer")
	}
	if *cmd.AvatarObjectKey != "" {
		t.Fatalf("AvatarObjectKey = %q, want the empty string", *cmd.AvatarObjectKey)
	}
}

// ---------------------------------------------------------------------------
// Declarative enforcement
// ---------------------------------------------------------------------------

// TestEveryMethodIsSelfScoped reads the policy the SERVER enforces with, not
// the .proto text.
//
// It is what stops a later method being added with an org relation, an
// entitlement or a resource-id field — each of which would need a gate this
// binary leaves nil, and would therefore be refused at runtime rather than at
// review.
func TestEveryMethodIsSelfScoped(t *testing.T) {
	t.Parallel()

	policies, err := policy.Load(profilev1connect.ProfileServiceName)
	if err != nil {
		t.Fatalf("policy.Load: %v", err)
	}
	methods := policies.Methods()
	if len(methods) != 3 {
		t.Fatalf("the service declares %d methods, want 3", len(methods))
	}
	selfScoped := policies.SelfScoped()
	if len(selfScoped) != len(methods) {
		t.Fatalf("%d of %d methods are self-scoped; every one must be, because a "+
			"profile is a person's own and there is no administrative method here",
			len(selfScoped), len(methods))
	}
}

// TestMutationsRequireAnIdempotencyKey — gate 5 refuses a mutation without one
// rather than minting a substitute.
func TestMutationsRequireAnIdempotencyKey(t *testing.T) {
	t.Parallel()

	s := newServer(t)
	_, err := s.client.UpdateProfile(context.Background(),
		connect.NewRequest(&profilev1.UpdateProfileRequest{DisplayName: ptr("Ada")}))
	if err == nil {
		t.Fatal("a mutation without an idempotency key was executed")
	}
	if len(s.updates.calls) != 0 {
		t.Fatal("the handler ran for a request gate 5 should have refused")
	}
}

// TestValidationRunsBeforeTheHandler is the assertion that the rules in the
// .proto are enforcement rather than documentation. Without the interceptor,
// every one of them is a comment.
func TestValidationRunsBeforeTheHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		call func(context.Context, profilev1connect.ProfileServiceClient) error
		why  string
	}{
		{
			name: "an empty display name",
			why: "it is not how a name is removed, and the schema saying so is what " +
				"makes the app layer's refusal a second line rather than the only one",
			call: func(ctx context.Context, c profilev1connect.ProfileServiceClient) error {
				_, err := c.UpdateProfile(ctx, withKey(connect.NewRequest(
					&profilev1.UpdateProfileRequest{DisplayName: ptr("")}), "k"))
				return err
			},
		},
		{
			name: "a display name with leading whitespace",
			why:  "it renders as a gap and sorts the person to the top of every list",
			call: func(ctx context.Context, c profilev1connect.ProfileServiceClient) error {
				_, err := c.UpdateProfile(ctx, withKey(connect.NewRequest(
					&profilev1.UpdateProfileRequest{DisplayName: ptr(" Ada")}), "k"))
				return err
			},
		},
		{
			name: "a locale that is not a tag",
			why:  "a value nothing renders from makes the field free text",
			call: func(ctx context.Context, c profilev1connect.ProfileServiceClient) error {
				_, err := c.UpdateProfile(ctx, withKey(connect.NewRequest(
					&profilev1.UpdateProfileRequest{Locale: ptr("english")}), "k"))
				return err
			},
		},
		{
			name: "a timezone offset rather than a zone",
			why:  "an offset is wrong for half of every year in most of the world",
			call: func(ctx context.Context, c profilev1connect.ProfileServiceClient) error {
				_, err := c.UpdateProfile(ctx, withKey(connect.NewRequest(
					&profilev1.UpdateProfileRequest{Timezone: ptr("+01:00")}), "k"))
				return err
			},
		},
		{
			name: "an avatar key with a path traversal",
			why:  "the key is concatenated into a URL path",
			call: func(ctx context.Context, c profilev1connect.ProfileServiceClient) error {
				_, err := c.UpdateProfile(ctx, withKey(connect.NewRequest(
					&profilev1.UpdateProfileRequest{
						AvatarObjectKey: ptr("avatar/../../etc/passwd"),
					}), "k"))
				return err
			},
		},
		{
			name: "an svg avatar upload",
			why:  "SVG executes script from an origin the session cookie is scoped to",
			call: func(ctx context.Context, c profilev1connect.ProfileServiceClient) error {
				_, err := c.CreateAvatarUpload(ctx, withKey(connect.NewRequest(
					&profilev1.CreateAvatarUploadRequest{
						ContentType: "image/svg+xml", SizeBytes: 10,
					}), "k"))
				return err
			},
		},
		{
			name: "an avatar upload over the ceiling",
			why:  "the declared size is what the signed policy pins",
			call: func(ctx context.Context, c profilev1connect.ProfileServiceClient) error {
				_, err := c.CreateAvatarUpload(ctx, withKey(connect.NewRequest(
					&profilev1.CreateAvatarUploadRequest{
						ContentType: "image/png", SizeBytes: domain.MaxAvatarBytes + 1,
					}), "k"))
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := newServer(t)
			err := tt.call(context.Background(), s.client)
			if err == nil {
				t.Fatalf("the request was accepted, want InvalidArgument (%s)", tt.why)
			}
			if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
				t.Fatalf("code = %v, want InvalidArgument", got)
			}
			// The second assertion is what catches a rule that "fails" for an
			// unrelated reason: a handler that itself errored would also produce
			// a non-nil error.
			if len(s.updates.calls) != 0 || len(s.avatars.calls) != 0 {
				t.Fatal("the request reached the handler")
			}
		})
	}
}

// TestSchemaAndDomainAgreeOnAvatarTypes stops the allowlist drifting between the
// two places it appears.
//
// The schema decides what a client may ASK for; the domain decides what this
// system will ever sign a policy for or record. A type in one and not the other
// is either an upload the schema permits and the server refuses, or — the
// dangerous direction — one the domain would accept and the schema never
// mentions.
func TestSchemaAndDomainAgreeOnAvatarTypes(t *testing.T) {
	t.Parallel()

	msg := profilev1.File_chronos_profile_v1_profile_proto.
		Messages().ByName("CreateAvatarUploadRequest")
	if msg == nil {
		t.Fatal("CreateAvatarUploadRequest is not in the descriptor")
	}
	field := msg.Fields().ByName("content_type")
	if field == nil {
		t.Fatal("content_type is not on CreateAvatarUploadRequest")
	}

	// Read from the compiled protovalidate rules, so this reflects what the
	// interceptor enforces rather than what the file appears to say.
	rules := protovalidateRuleValues(t, field)
	want := domain.AllowedAvatarTypes()
	if len(rules) != len(want) {
		t.Fatalf("the schema allows %v and the domain allows %v", rules, want)
	}
	for i := range want {
		if rules[i] != want[i] {
			t.Fatalf("the schema allows %v and the domain allows %v", rules, want)
		}
	}
}

func ptr[T any](v T) *T { return &v }

// protovalidateRuleValues reads the `in:` list off a field's COMPILED
// protovalidate rules.
//
// From the descriptor rather than from the .proto text, for the reason
// checkopenapi gives about reading options: the extension's value is what the
// interceptor enforces, and a regex over the file could be defeated by any
// syntax it did not anticipate — reporting "no rule", which is the
// safe-looking answer and therefore the dangerous one.
func protovalidateRuleValues(t *testing.T, field protoreflect.FieldDescriptor) []string {
	t.Helper()

	rules, ok := proto.GetExtension(field.Options(), validatepb.E_Field).(*validatepb.FieldRules)
	if !ok || rules == nil {
		t.Fatalf("%s carries no protovalidate rules, so the schema constrains nothing",
			field.FullName())
	}
	in := rules.GetString().GetIn()
	if len(in) == 0 {
		t.Fatalf("%s has no `in` list", field.FullName())
	}
	return in
}
