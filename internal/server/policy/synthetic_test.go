package policy_test

import (
	"testing"

	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	// Registers google/protobuf/empty.proto in the global files, which the
	// synthetic descriptors below import. Without it protodesc.NewFile fails to
	// resolve the dependency — nothing else in this binary pulls it in.
	_ "google.golang.org/protobuf/types/known/emptypb"
)

// registerSynthetic builds a one-method service at runtime and registers it, so
// a policy failure can be tested without breaking a real .proto.
//
// The alternative — deleting an annotation from a checked-in schema to watch the
// test fail — is a test that only runs once, because putting the annotation back
// is what the next commit does.
func registerSynthetic(
	t *testing.T, pkg, method string, opts *descriptorpb.MethodOptions,
) protoreflect.FullName {
	t.Helper()

	// Each call gets its own file name. Registration is global and permanent for
	// the process, so a shared name makes the second call fail with a duplicate
	// rather than testing what it meant to.
	file := pkg + "/" + method + ".proto"

	empty := "google.protobuf.Empty"
	svcName := "SyntheticService"
	fd := &descriptorpb.FileDescriptorProto{
		Name:       proto.String(file),
		Package:    proto.String(pkg),
		Syntax:     proto.String("proto3"),
		Dependency: []string{"google/protobuf/empty.proto"},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String(svcName),
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name:       proto.String(method),
				InputType:  proto.String("." + empty),
				OutputType: proto.String("." + empty),
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

// annotated builds MethodOptions carrying a full, valid policy — the baseline
// the incoherent-combination tests mutate one field at a time.
func annotated() *descriptorpb.MethodOptions {
	o := &descriptorpb.MethodOptions{}
	proto.SetExtension(o, optionsv1.E_Authz, &optionsv1.Authz{
		Relation:     "admin",
		ResourceType: "organization",
	})
	proto.SetExtension(o, optionsv1.E_Operation, optionsv1.OperationClass_OPERATION_CLASS_WRITE)
	return o
}
