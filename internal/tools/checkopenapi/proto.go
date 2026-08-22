package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	// Imported for their side effect: a generated package registers its file
	// descriptors with protoregistry.GlobalFiles at init, and that registry is
	// what routes() walks. Anything not imported here is invisible to the
	// check — which is why crossCheckAgainstSources exists and fails when the
	// .proto sources on disk describe an RPC the registry does not carry.
	_ "github.com/chronos/chronos-go/gen/proto/chronos/billing/v1"
	_ "github.com/chronos/chronos-go/gen/proto/chronos/errors/v1"
	_ "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	_ "github.com/chronos/chronos-go/gen/proto/chronos/notification/v1"
	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	_ "github.com/chronos/chronos-go/gen/proto/chronos/organization/v1"
	_ "github.com/chronos/chronos-go/gen/proto/chronos/profile/v1"
	_ "github.com/chronos/chronos-go/gen/proto/chronos/system/v1"
	_ "github.com/chronos/chronos-go/gen/proto/chronos/workspace/v1"
)

// protoPackagePrefix limits the registry walk to this repository's own schema.
// The registry also carries google.protobuf, gnostic and protovalidate, none of
// which this document publishes.
const protoPackagePrefix = "chronos."

// rpc is what the compiled descriptor says about one method, for the two rules
// that compare the published document against the schema the server enforces.
//
// Both fields are read from the descriptor rather than from the .proto text or
// from the document, so each is the value the interceptors themselves act on:
// internal/server/interceptor/authn reads `public`, and
// internal/server/interceptor/idempotency requires its header of exactly the
// methods `policy.Policy.Mutating` returns true for.
type rpc struct {
	// public is (chronos.options.v1.public).
	public bool

	// mutating mirrors policy.Policy.Mutating: the operation classes that write.
	// A mutating method requires an `Idempotency-Key` header at runtime, so a
	// published operation that does not document one describes a call every
	// client will get a VALIDATION_FAILED from on its first attempt.
	mutating bool
}

// routes is every RPC this repository declares, keyed by the path a Connect
// client calls: /<package>.<Service>/<Method>.
//
// The value is what the COMPILED descriptor says about the method, read from the
// descriptor rather than matched out of the .proto text. That matters:
// the option's value is what the authentication interceptor enforces at runtime
// (internal/server/policy reads the same extension off the same descriptor), so
// this check compares the published document against the enforced fact rather
// than against a second reading of the same file. A regex could be defeated by
// any syntax it did not anticipate — a block comment, an option set on the
// service, a line break in the wrong place — and would report "not public",
// which is the SAFE-looking answer and therefore the dangerous one.
func routes() map[string]rpc {
	out := map[string]rpc{}
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if !strings.HasPrefix(string(fd.Package()), protoPackagePrefix) {
			return true
		}
		services := fd.Services()
		for i := range services.Len() {
			svc := services.Get(i)
			methods := svc.Methods()
			for j := range methods.Len() {
				m := methods.Get(j)
				public, _ := proto.GetExtension(m.Options(), optionsv1.E_Public).(bool)
				class, _ := proto.GetExtension(m.Options(), optionsv1.E_Operation).(optionsv1.OperationClass)
				out["/"+string(svc.FullName())+"/"+string(m.Name())] = rpc{
					public:   public,
					mutating: mutatingClass(class),
				}
			}
		}
		return true
	})
	return out
}

// mutatingClass is policy.Policy.Mutating, restated over the raw enum.
//
// Restated rather than imported: internal/server/policy builds a Policy from a
// descriptor and carries the gates with it, and pulling the server's policy
// package into a build-time documentation tool would make this gate depend on
// the runtime it is meant to audit. The list is short, and the two must be
// changed together — a new mutating operation class that is added there and not
// here makes this check quietly weaker, which is why it is spelled out rather
// than defaulted.
func mutatingClass(c optionsv1.OperationClass) bool {
	switch c {
	case optionsv1.OperationClass_OPERATION_CLASS_WRITE,
		optionsv1.OperationClass_OPERATION_CLASS_GROW,
		optionsv1.OperationClass_OPERATION_CLASS_BILLING_MANAGE:
		return true
	default:
		return false
	}
}

var (
	packageRE = regexp.MustCompile(`(?m)^package\s+([\w.]+)\s*;`)
	serviceRE = regexp.MustCompile(`(?m)^service\s+(\w+)\s*\{`)
	rpcRE     = regexp.MustCompile(`\brpc\s+(\w+)\s*\(`)
)

// crossCheckAgainstSources is the guard on routes()'s one weakness.
//
// routes() sees only what some package in this binary's import graph registered.
// A new proto package that nobody blank-imports above would be skipped in
// SILENCE — every rule would still pass, over a smaller set, and the endpoint
// nobody checked would be the new one. That is precisely the failure mode this
// whole file exists to prevent, so it is not left to a convention.
//
// The .proto sources on disk are therefore read as a LOWER BOUND on what must
// exist. The text scan is deliberately crude: it never decides whether an RPC is
// public, only that the RPC exists, and a crude scan that over-reports produces a
// loud failure rather than a quiet pass.
func crossCheckAgainstSources(dir string, known map[string]rpc) (found int, problems []string) {
	var files []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".proto") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return 0, []string{fmt.Sprintf("cannot read the .proto sources under %s: %v", dir, err)}
	}
	sort.Strings(files)

	var missing []string
	for _, path := range files {
		src, err := os.ReadFile(path) // #nosec G304 -- a build-time tool reading this repo's own sources
		if err != nil {
			problems = append(problems, fmt.Sprintf("cannot read %s: %v", path, err))
			continue
		}
		text := string(src)
		pkg := packageRE.FindStringSubmatch(text)
		if pkg == nil {
			continue
		}
		for _, svc := range serviceRE.FindAllStringSubmatchIndex(text, -1) {
			name := text[svc[2]:svc[3]]
			body := serviceBody(text, svc[1])
			for _, match := range rpcRE.FindAllStringSubmatch(body, -1) {
				found++
				route := "/" + pkg[1] + "." + name + "/" + match[1]
				if _, ok := known[route]; !ok {
					missing = append(missing, route)
				}
			}
		}
	}
	sort.Strings(missing)
	for _, route := range missing {
		problems = append(problems, fmt.Sprintf(
			"%s is declared in the .proto sources but is absent from the descriptor registry — "+
				"add a blank import for its generated package in internal/tools/checkopenapi/proto.go, "+
				"otherwise this check silently skips it", route))
	}
	return found, problems
}

// serviceBody returns the text from a service's opening brace to the closing
// brace in column zero, matching how these files are formatted.
func serviceBody(text string, from int) string {
	if end := strings.Index(text[from:], "\n}"); end != -1 {
		return text[from : from+end]
	}
	return text[from:]
}
