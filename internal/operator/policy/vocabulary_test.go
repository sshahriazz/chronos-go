package policy_test

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	operatorv1 "github.com/chronos/chronos-go/gen/proto/chronos/operator/v1"
	"github.com/chronos/chronos-go/internal/operator/domain"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	// buf.validate's extensions, so the field constraints are readable through
	// protoreflect. Nothing else in this package pulls them in.
	_ "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
)

// The role vocabulary's third leg.
//
// Four roles, three artefacts: Go constants, a protovalidate `pattern` on the
// two request fields that carry a role, and a CHECK constraint. The Go ↔ SQL
// pair is asserted in internal/operator/adapter/postgres; this is Go ↔ proto.
//
// # Why the pattern matters rather than being belt-and-braces
//
// CONVENTIONS §7 makes the published bound and the refused request one number.
// A pattern that admits a role the capability table does not know publishes a
// role we do not have — and protovalidate would ACCEPT it, so the request
// reaches the handler and is refused there instead, with a different code and
// a different message from the one the schema promised.

// rolePattern extracts the alternation out of a `^(a|b|c)$` pattern.
var rolePattern = regexp.MustCompile(`^\^\(([a-z_|]+)\)\$$`)

// TestTheRoleFieldPatternMatchesTheDomain walks every field in the operator
// schema whose pattern looks like a role alternation, and holds it to
// domain.Roles().
//
// It DISCOVERS the fields rather than naming them, which is the point: naming
// them would make this test as complete as whoever last remembered to add one,
// and a third role-carrying field added later is exactly the case it must
// catch.
func TestTheRoleFieldPatternMatchesTheDomain(t *testing.T) {
	want := make([]string, 0, len(domain.Roles()))
	for _, r := range domain.Roles() {
		want = append(want, string(r))
	}
	sort.Strings(want)
	joined := strings.Join(want, "|")

	checked := 0
	forEachOperatorField(t, func(path string, fd protoreflect.FieldDescriptor) {
		pattern := stringPattern(fd)
		m := rolePattern.FindStringSubmatch(pattern)
		if m == nil {
			return
		}

		got := strings.Split(m[1], "|")
		sort.Strings(got)
		if strings.Join(got, "|") != joined {
			t.Errorf("%s publishes the roles %v and the domain knows %v.\n\n"+
				"CONVENTIONS §7: the published bound and the refused request are one "+
				"number. A pattern admitting a role the capability table does not know "+
				"means protovalidate accepts it and the handler refuses it — with a "+
				"different code and a different message from the one the schema promised.",
				path, got, want)
		}
		checked++
	})

	if checked == 0 {
		t.Fatal("no field in the operator schema carries a role pattern.\n\n" +
			"Either the fields lost their patterns — in which case an arbitrary string " +
			"now reaches the handler — or this test's regexp no longer matches how they " +
			"are written, and it is asserting nothing.")
	}
}

// TestEveryCapabilityInTheSchemaIsOneTheRoleTableKnows is the same argument for
// the OTHER string the proto carries.
//
// The policy loader already refuses an unknown capability at startup, so this
// is not the enforcement — it is the test that fails in CI rather than in
// production, on a build somebody would otherwise deploy and watch refuse to
// start.
func TestEveryCapabilityInTheSchemaIsOneTheRoleTableKnows(t *testing.T) {
	sd := operatorService(t)

	methods := sd.Methods()
	for i := range methods.Len() {
		md := methods.Get(i)

		raw, _ := proto.GetExtension(md.Options(), operatorv1.E_Capability).(string)
		capability := domain.Capability(strings.TrimSpace(raw))
		if capability == "" {
			continue
		}
		if !domain.KnownCapability(capability) {
			t.Errorf("%s declares the capability %q, which no role holds", md.Name(), capability)
		}
	}
}

// --------------------------------------------------------------------------
// Reflection helpers
// --------------------------------------------------------------------------

func operatorService(t *testing.T) protoreflect.ServiceDescriptor {
	t.Helper()
	d, err := protoregistry.GlobalFiles.FindDescriptorByName("chronos.operator.v1.OperatorService")
	if err != nil {
		t.Fatalf("resolving the operator service: %v", err)
	}
	sd, ok := d.(protoreflect.ServiceDescriptor)
	if !ok {
		t.Fatal("chronos.operator.v1.OperatorService is not a service")
	}
	return sd
}

// forEachOperatorField visits every field of every message in the operator
// package.
func forEachOperatorField(t *testing.T, fn func(path string, fd protoreflect.FieldDescriptor)) {
	t.Helper()

	protoregistry.GlobalFiles.RangeFiles(func(file protoreflect.FileDescriptor) bool {
		if file.Package() != "chronos.operator.v1" {
			return true
		}
		messages := file.Messages()
		for i := range messages.Len() {
			msg := messages.Get(i)
			fields := msg.Fields()
			for j := range fields.Len() {
				fd := fields.Get(j)
				fn(string(msg.Name())+"."+string(fd.Name()), fd)
			}
		}
		return true
	})
}

// stringPattern reads a field's protovalidate `pattern`, or "" when it has
// none.
//
// It goes through the OPTIONS as protobuf holds them rather than through the
// generated Go structs, so a field added to the schema is visible here without
// anything being regenerated into this test.
func stringPattern(fd protoreflect.FieldDescriptor) string {
	opts := fd.Options()
	if opts == nil {
		return ""
	}

	var pattern string
	proto.RangeExtensions(opts, func(xt protoreflect.ExtensionType, v any) bool {
		if xt.TypeDescriptor().FullName() != "buf.validate.field" {
			return true
		}
		m, ok := v.(protoreflect.ProtoMessage)
		if !ok {
			return true
		}
		rules := m.ProtoReflect()
		rules.Range(func(fd protoreflect.FieldDescriptor, val protoreflect.Value) bool {
			if fd.Name() != "string" {
				return true
			}
			str := val.Message()
			str.Range(func(sfd protoreflect.FieldDescriptor, sval protoreflect.Value) bool {
				if sfd.Name() == "pattern" {
					pattern = sval.String()
					return false
				}
				return true
			})
			return false
		})
		return false
	})
	return pattern
}
