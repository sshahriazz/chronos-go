package policy_test

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	operatorv1 "github.com/chronos/chronos-go/gen/proto/chronos/operator/v1"
	"github.com/chronos/chronos-go/internal/operator/domain"
	"github.com/chronos/chronos-go/internal/operator/policy"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	// Registers google/protobuf/empty.proto in the global files, which the
	// synthetic descriptors below import.
	_ "google.golang.org/protobuf/types/known/emptypb"
)

// TestTheRealServiceLoads is the conformance gate.
//
// It is the test that fails when somebody adds an RPC to OperatorService and
// forgets its policy — which is the whole reason the loader exists. Everything
// below it tests the loader's own rules; this one tests the schema we ship.
func TestTheRealServiceLoads(t *testing.T) {
	cat, err := policy.LoadByName("chronos.operator.v1.OperatorService")
	if err != nil {
		t.Fatalf("the shipped OperatorService does not load: %v", err)
	}
	if len(cat) == 0 {
		t.Fatal("loaded an empty catalogue, which would mean no method was inspected at all")
	}
}

// TestEveryAuthenticatedMethodRecordsAnAuditAction is operator.md §5, asserted
// on the shipped schema rather than on a synthetic one.
//
// "Every operator RPC, including reads, produces an audit event. A new endpoint
// without one fails the suite." This is that suite entry.
func TestEveryAuthenticatedMethodRecordsAnAuditAction(t *testing.T) {
	cat, err := policy.LoadByName("chronos.operator.v1.OperatorService")
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	for name, p := range cat {
		// The sign-in ceremony is exempt: it reads no tenant data, and the
		// completion step records the sign-in. See the loader's own comment.
		if p.Access == policy.AccessUnauthenticated || p.Access == policy.AccessSSOOnly {
			continue
		}
		if p.Audit == operatorv1.AuditAction_AUDIT_ACTION_UNSPECIFIED {
			t.Errorf("%s is authenticated and records nothing", name)
		}
	}
}

// TestOnlyTheWebAuthnPairIsReachableWithAPendingSession is the two-stage
// session's whole value, asserted.
//
// An sso_only session has passed ONE factor. If a third method ever becomes
// reachable from it, the intermediate state stops being "the step that ends
// this state" and becomes a partially-authorized session — which is the design
// operator.md §3 rejects.
func TestOnlyTheWebAuthnPairIsReachableWithAPendingSession(t *testing.T) {
	cat, err := policy.LoadByName("chronos.operator.v1.OperatorService")
	if err != nil {
		t.Fatalf("loading: %v", err)
	}

	want := map[string]bool{
		"/chronos.operator.v1.OperatorService/BeginWebAuthn":  true,
		"/chronos.operator.v1.OperatorService/FinishWebAuthn": true,
	}
	got := map[string]bool{}
	for name, p := range cat {
		if p.Access == policy.AccessSSOOnly {
			got[name] = true
		}
	}
	for name := range want {
		if !got[name] {
			t.Errorf("%s should be reachable with a pending session and is not", name)
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("%s is reachable with a session that has passed only ONE factor", name)
		}
	}
}

// TestOnlyTheOIDCCeremonyIsUnauthenticated is the same argument for the other
// exemption.
func TestOnlyTheOIDCCeremonyIsUnauthenticated(t *testing.T) {
	cat, err := policy.LoadByName("chronos.operator.v1.OperatorService")
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	want := map[string]bool{
		"/chronos.operator.v1.OperatorService/BeginSignIn":    true,
		"/chronos.operator.v1.OperatorService/CompleteSignIn": true,
	}
	for name, p := range cat {
		if p.Access != policy.AccessUnauthenticated {
			continue
		}
		if !want[name] {
			t.Errorf("%s is reachable with no session at all", name)
		}
		delete(want, name)
	}
	for name := range want {
		t.Errorf("%s should be unauthenticated and is not", name)
	}
}

// TestAnIncoherentDeclarationIsRefused walks every way a declaration can be
// wrong.
//
// Each case is built as a synthetic descriptor rather than by editing the
// checked-in schema, because a test that works by deleting an annotation only
// runs once — putting the annotation back is what the next commit does.
func TestAnIncoherentDeclarationIsRefused(t *testing.T) {
	cases := []struct {
		name string
		opts func() *descriptorpb.MethodOptions
		// want is a fragment of the message the loader must produce, so a
		// refusal for the WRONG reason fails too.
		want string
	}{
		{
			name: "nothing declared at all",
			opts: func() *descriptorpb.MethodOptions { return &descriptorpb.MethodOptions{} },
			want: "declares no audit action",
		},
		{
			name: "a capability with no audit action",
			opts: func() *descriptorpb.MethodOptions {
				o := &descriptorpb.MethodOptions{}
				proto.SetExtension(o, operatorv1.E_Capability, string(domain.CapViewCustomers))
				return o
			},
			want: "declares no audit action",
		},
		{
			name: "an audit action with no capability",
			opts: func() *descriptorpb.MethodOptions {
				o := &descriptorpb.MethodOptions{}
				proto.SetExtension(o, operatorv1.E_Audit,
					operatorv1.AuditAction_AUDIT_ACTION_VIEWED_CUSTOMER)
				return o
			},
			want: "declares no capability",
		},
		{
			name: "a capability the role table has never heard of",
			opts: func() *descriptorpb.MethodOptions {
				o := &descriptorpb.MethodOptions{}
				proto.SetExtension(o, operatorv1.E_Capability, "read_everything")
				proto.SetExtension(o, operatorv1.E_Audit,
					operatorv1.AuditAction_AUDIT_ACTION_VIEWED_CUSTOMER)
				return o
			},
			want: "which no role in internal/operator/domain holds",
		},
		{
			name: "unauthenticated AND sso_only",
			opts: func() *descriptorpb.MethodOptions {
				o := &descriptorpb.MethodOptions{}
				proto.SetExtension(o, operatorv1.E_Unauthenticated, true)
				proto.SetExtension(o, operatorv1.E_SsoOnly, true)
				return o
			},
			want: "declares both unauthenticated and sso_only",
		},
		{
			name: "unauthenticated with a capability",
			opts: func() *descriptorpb.MethodOptions {
				o := &descriptorpb.MethodOptions{}
				proto.SetExtension(o, operatorv1.E_Unauthenticated, true)
				proto.SetExtension(o, operatorv1.E_Capability, string(domain.CapViewCustomers))
				return o
			},
			want: "capability AND unauthenticated",
		},
		{
			name: "sso_only with a capability it could never evaluate",
			opts: func() *descriptorpb.MethodOptions {
				o := &descriptorpb.MethodOptions{}
				proto.SetExtension(o, operatorv1.E_SsoOnly, true)
				proto.SetExtension(o, operatorv1.E_Capability, string(domain.CapViewCustomers))
				proto.SetExtension(o, operatorv1.E_Audit,
					operatorv1.AuditAction_AUDIT_ACTION_SIGNED_IN)
				return o
			},
			want: "capability AND sso_only",
		},
		{
			name: "unauthenticated but recording an audit entry for nobody",
			opts: func() *descriptorpb.MethodOptions {
				o := &descriptorpb.MethodOptions{}
				proto.SetExtension(o, operatorv1.E_Unauthenticated, true)
				proto.SetExtension(o, operatorv1.E_Audit,
					operatorv1.AuditAction_AUDIT_ACTION_VIEWED_CUSTOMER)
				return o
			},
			want: "unauthenticated and declares an audit action",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			full := registerSynthetic(t, "synthetic.operator", "Method", tc.opts())
			_, err := policy.LoadByName(full)
			if err == nil {
				t.Fatal("the loader accepted a declaration it must refuse")
			}
			if !errors.Is(err, policy.ErrUnannotated) {
				t.Errorf("want ErrUnannotated, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refused for the wrong reason:\n got %v\nwant a message containing %q",
					err, tc.want)
			}
		})
	}
}

// TestAValidDeclarationLoads is the counterpart: the refusals above must not be
// so broad that a correct method is caught too.
func TestAValidDeclarationLoads(t *testing.T) {
	o := &descriptorpb.MethodOptions{}
	proto.SetExtension(o, operatorv1.E_Capability, string(domain.CapViewCustomers))
	proto.SetExtension(o, operatorv1.E_Audit, operatorv1.AuditAction_AUDIT_ACTION_VIEWED_CUSTOMER)

	full := registerSynthetic(t, "synthetic.operator", "Method", o)
	cat, err := policy.LoadByName(full)
	if err != nil {
		t.Fatalf("a correct declaration was refused: %v", err)
	}
	for _, p := range cat {
		if p.Access != policy.AccessCapability {
			t.Errorf("want AccessCapability, got %v", p.Access)
		}
		if p.Capability != domain.CapViewCustomers {
			t.Errorf("want %q, got %q", domain.CapViewCustomers, p.Capability)
		}
	}
}

// TestTheZeroPolicyIsTheRestrictiveOne guards the choice of iota ordering.
//
// A Policy that failed to load, or one somebody constructed by mistake, must
// require a capability rather than be unauthenticated. Swapping the constants
// would compile, pass every other test here, and silently open every endpoint
// whose policy lookup missed.
func TestTheZeroPolicyIsTheRestrictiveOne(t *testing.T) {
	var zero policy.Policy
	if zero.Access != policy.AccessCapability {
		t.Fatalf("the zero Access is %v, not AccessCapability — a failed lookup would be unauthenticated",
			zero.Access)
	}
	if zero.Capability != "" {
		t.Fatal("the zero Capability is non-empty")
	}
	// And an empty capability is one no role holds, so the check that reads it
	// denies rather than passes.
	for _, role := range domain.Roles() {
		if domain.Permits(role, zero.Capability) {
			t.Fatalf("role %q holds the empty capability", role)
		}
	}
}

// --------------------------------------------------------------------------
// Synthetic descriptors
// --------------------------------------------------------------------------

// syntheticSeq makes every registered descriptor unique within the process,
// which is what lets this package survive `go test -count=2`. Registration is
// global and permanent, so a shared name makes the second run PANIC in the
// protobuf registry rather than re-run the test.
var syntheticSeq atomic.Uint64

func registerSynthetic(
	t *testing.T, pkg, method string, opts *descriptorpb.MethodOptions,
) protoreflect.FullName {
	t.Helper()

	pkg = fmt.Sprintf("%s.r%d", pkg, syntheticSeq.Add(1))
	file := pkg + "/" + method + ".proto"

	empty := "google.protobuf.Empty"
	svcName := "SyntheticService"
	fd := &descriptorpb.FileDescriptorProto{
		Name:       ptr(file),
		Package:    ptr(pkg),
		Syntax:     ptr("proto3"),
		Dependency: []string{"google/protobuf/empty.proto"},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: ptr(svcName),
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name:       ptr(method),
				InputType:  ptr("." + empty),
				OutputType: ptr("." + empty),
				Options:    opts,
			}},
		}},
	}

	fdesc, err := protodesc.NewFile(fd, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("building synthetic descriptor: %v", err)
	}
	if err := protoregistry.GlobalFiles.RegisterFile(fdesc); err != nil {
		t.Fatalf("registering synthetic descriptor: %v", err)
	}
	return protoreflect.FullName(pkg + "." + svcName)
}

func ptr[T any](v T) *T { return &v }
