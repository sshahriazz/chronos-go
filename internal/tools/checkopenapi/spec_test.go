package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const (
	specPath = "../../../docs/api/chronos-openapi.yaml"
	protoDir = "../../../proto/chronos"
)

// A route that is `public = true` and one that is not. Both are asserted to
// still have those properties in TestRoutesReadsTheDeclaredOption, so a test
// below that depends on one cannot quietly start testing nothing.
const (
	publicRoute    = "/chronos.identity.v1.IdentityService/ResendEmailVerification"
	protectedRoute = "/chronos.identity.v1.IdentityService/ListSessions"
)

func loadSpec(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("reading the published spec: %v", err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("parsing the published spec: %v", err)
	}
	return spec
}

// TestValidateAcceptsThePublishedSpec is the positive half. Without it, every
// negative case below could be passing for the wrong reason.
func TestValidateAcceptsThePublishedSpec(t *testing.T) {
	t.Parallel()

	r := &reporter{out: io.Discard}
	validate(r, loadSpec(t), routes())
	if len(r.problems) != 0 {
		t.Errorf("the committed spec does not satisfy its own checker:\n  %s",
			strings.Join(r.problems, "\n  "))
	}
}

// TestValidateRejects is the negative half: every rule this tool enforces,
// broken on purpose, one at a time.
//
// A checker nobody has seen fail is a checker nobody knows works. Each case
// mutates a fresh copy of the REAL document, so a rule that stops firing —
// because the spec changed shape, or because a refactor dropped the check —
// fails here rather than passing silently in CI forever.
func TestValidateRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		corrupt func(spec map[string]any, declared map[string]bool)
		want    string
	}{
		{
			// The regression this whole tool exists to catch.
			name: "paths is empty",
			corrupt: func(spec map[string]any, _ map[string]bool) {
				spec["paths"] = map[string]any{}
			},
			want: "paths is NOT empty (0 documented)",
		},
		{
			name: "paths is absent entirely",
			corrupt: func(spec map[string]any, _ map[string]bool) {
				delete(spec, "paths")
			},
			want: "paths is NOT empty (0 documented)",
		},
		{
			name: "two operations share one operationId",
			corrupt: func(spec map[string]any, _ map[string]bool) {
				ids := allOperations(spec)
				op(ids[0]).(map[string]any)["operationId"] =
					op(ids[1]).(map[string]any)["operationId"]
			},
			want: "is already used by",
		},
		{
			name: "an operation has no operationId",
			corrupt: func(spec map[string]any, _ map[string]bool) {
				delete(op(allOperations(spec)[0]).(map[string]any), "operationId")
			},
			want: "no operationId (generated clients need it)",
		},
		{
			name: "an operation documents no responses",
			corrupt: func(spec map[string]any, _ map[string]bool) {
				delete(op(allOperations(spec)[0]).(map[string]any), "responses")
			},
			want: "no responses documented",
		},
		{
			name: "an operation has neither summary nor description",
			corrupt: func(spec map[string]any, _ map[string]bool) {
				o := op(allOperations(spec)[0]).(map[string]any)
				delete(o, "summary")
				delete(o, "description")
			},
			want: "no summary or description",
		},
		{
			// The real bug this cross-check was written for: an RPC declared
			// public in the proto, published as requiring a bearer token.
			name: "a public RPC is published as requiring a bearer token",
			corrupt: func(spec map[string]any, _ map[string]bool) {
				post(spec, publicRoute)["security"] = []any{
					map[string]any{"bearerAuth": []any{}},
				}
			},
			want: "declares public = true but publishes security",
		},
		{
			name: "a public RPC publishes no security override at all",
			corrupt: func(spec map[string]any, _ map[string]bool) {
				delete(post(spec, publicRoute), "security")
			},
			want: "declares public = true but publishes security",
		},
		{
			// The other direction, which is the quieter one: an authenticated
			// RPC documented as needing nothing.
			name: "a protected RPC is published as open",
			corrupt: func(spec map[string]any, _ map[string]bool) {
				post(spec, protectedRoute)["security"] = []any{map[string]any{}}
			},
			want: "is NOT public but overrides the document security default",
		},
		{
			name: "a public RPC is missing from the document",
			corrupt: func(spec map[string]any, _ map[string]bool) {
				delete(mapOf(spec["paths"]), publicRoute)
			},
			want: "public RPC is absent from the document",
		},
		{
			name: "a $ref points at nothing",
			corrupt: func(spec map[string]any, _ map[string]bool) {
				op(allOperations(spec)[0]).(map[string]any)["requestBody"] =
					map[string]any{"$ref": "#/components/schemas/NoSuchSchema"}
			},
			want: "$refs resolve",
		},
		{
			name: "a published schema is reachable from nothing",
			corrupt: func(spec map[string]any, _ map[string]bool) {
				schemas := mapOf(mapOf(spec["components"])["schemas"])
				schemas["chronos.options.v1.Authz"] = map[string]any{"type": "object"}
			},
			want: "published but referenced by nothing",
		},
		{
			// The exemption must not outlive the thing it exempts, or it becomes
			// a permanent hole in the reachability rule.
			name: "the exempted schema is no longer published",
			corrupt: func(spec map[string]any, _ map[string]bool) {
				delete(mapOf(mapOf(spec["components"])["schemas"]),
					"chronos.errors.v1.ErrorDetail")
			},
			want: "drop the exemption",
		},
		{
			name: "no RPC was discovered at all",
			corrupt: func(_ map[string]any, declared map[string]bool) {
				for k := range declared {
					delete(declared, k)
				}
			},
			want: "the .proto descriptors were read (0 RPCs found)",
		},
		{
			name: "the document does not declare OpenAPI 3",
			corrupt: func(spec map[string]any, _ map[string]bool) {
				spec["openapi"] = "2.0"
			},
			want: "declares OpenAPI 3.x",
		},
		{
			name: "info.title is missing",
			corrupt: func(spec map[string]any, _ map[string]bool) {
				delete(mapOf(spec["info"]), "title")
			},
			want: "info.title is set",
		},
		{
			name: "info.version is missing",
			corrupt: func(spec map[string]any, _ map[string]bool) {
				delete(mapOf(spec["info"]), "version")
			},
			want: "info.version is set",
		},
		{
			name: "info.description is a placeholder",
			corrupt: func(spec map[string]any, _ map[string]bool) {
				mapOf(spec["info"])["description"] = "TODO"
			},
			want: "info.description is substantive",
		},
		{
			name: "no servers are declared",
			corrupt: func(spec map[string]any, _ map[string]bool) {
				delete(spec, "servers")
			},
			want: "servers are declared",
		},
		{
			name: "externalDocs is missing",
			corrupt: func(spec map[string]any, _ map[string]bool) {
				delete(spec, "externalDocs")
			},
			want: "externalDocs links the error catalogue",
		},
		{
			name: "no security scheme is documented",
			corrupt: func(spec map[string]any, _ map[string]bool) {
				delete(mapOf(spec["components"]), "securitySchemes")
			},
			want: "security schemes are documented",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			spec := clone(loadSpec(t)).(map[string]any)
			declared := routes()
			tt.corrupt(spec, declared)

			r := &reporter{out: io.Discard}
			validate(r, spec, declared)

			if !containsSubstring(r.problems, tt.want) {
				t.Errorf("breaking %q produced no problem mentioning %q; got:\n  %s",
					tt.name, tt.want, strings.Join(r.problems, "\n  "))
			}
		})
	}
}

// TestReportNarratesEvenOnSuccess pins the property the Python predecessor
// lacked: a gate must say that it ran. Silence on success is indistinguishable
// from not running.
func TestReportNarratesEvenOnSuccess(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	r := &reporter{out: &out}
	validate(r, loadSpec(t), routes())

	got := out.String()
	for _, want := range []string{"paths is NOT empty", "every operationId is unique", "$refs resolve"} {
		if !strings.Contains(got, want) {
			t.Errorf("the report never mentions %q:\n%s", want, got)
		}
	}
}

// --- helpers ----------------------------------------------------------------

// allOperations returns every (path item, verb) pair in a stable order.
func allOperations(spec map[string]any) []operationRef {
	paths := mapOf(spec["paths"])
	var out []operationRef
	for _, path := range sortedKeys(paths) {
		item := mapOf(paths[path])
		for _, verb := range sortedKeys(item) {
			if verbs[verb] {
				out = append(out, operationRef{item, verb})
			}
		}
	}
	return out
}

type operationRef struct {
	item map[string]any
	verb string
}

func op(r operationRef) any { return r.item[r.verb] }

// post returns one path's POST operation, for the security cases.
func post(spec map[string]any, path string) map[string]any {
	return mapOf(mapOf(mapOf(spec["paths"])[path])["post"])
}

func containsSubstring(list []string, want string) bool {
	for _, s := range list {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}

// clone deep-copies a decoded YAML document so one test case's mutation cannot
// reach another's.
func clone(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = clone(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = clone(val)
		}
		return out
	default:
		return v
	}
}
