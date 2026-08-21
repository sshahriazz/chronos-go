package main

import (
	"io"
	"strings"
	"testing"
)

// TestBoundsRejects is the negative half of the hardening rules: each one broken
// on purpose, on a fresh copy of the REAL document.
//
// The positive half is TestValidateAcceptsThePublishedSpec, which runs every
// rule in this file over the committed spec. Both halves are needed and the
// negative one is the load-bearing half — a rule that has never been seen to
// fire is a rule nobody knows is connected. Two security checks in this
// repository passed unconditionally for their whole lives, which is what this
// shape of test exists to prevent.
func TestBoundsRejects(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		corrupt func(spec map[string]any)
		want    string
	}{
		{
			name: "a server offers cleartext",
			corrupt: func(spec map[string]any) {
				spec["servers"] = append(sliceOf(spec["servers"]),
					map[string]any{"url": "http://api.chronos.example"})
			},
			want: "carries the session bearer token in the clear",
		},
		{
			name: "a request string loses its maxLength",
			corrupt: func(spec map[string]any) {
				delete(schema(spec, "chronos.identity.v1.RegisterRequest", "email"), "maxLength")
			},
			want: "is a string with no maxLength",
		},
		{
			name: "a request string loses its pattern",
			corrupt: func(spec map[string]any) {
				delete(schema(spec, "chronos.identity.v1.RegisterRequest", "email"), "pattern")
			},
			want: "is a string with no pattern",
		},
		{
			name: "a response array loses its maxItems",
			corrupt: func(spec map[string]any) {
				delete(schema(spec, "chronos.identity.v1.ListSessionsResponse", "sessions"), "maxItems")
			},
			want: "is an array with no maxItems",
		},
		{
			name: "a numeric field loses its ceiling",
			corrupt: func(spec map[string]any) {
				s := schema(spec, "chronos.identity.v1.RevokeAllSessionsResponse", "revoked")
				delete(s, "maximum")
				delete(s, "exclusiveMaximum")
			},
			want: "is numeric with no maximum",
		},
		{
			name: "a numeric field loses its floor",
			corrupt: func(spec map[string]any) {
				s := schema(spec, "chronos.identity.v1.RevokeAllSessionsResponse", "revoked")
				delete(s, "minimum")
				delete(s, "exclusiveMinimum")
			},
			want: "is numeric with no minimum",
		},
		{
			// The finding an external audit caught and this gate did not: a
			// gnostic `maximum` is a double, and 2^63-1 came back out of the
			// generator as 9223372036854776000 — a ceiling no int64 can reach.
			name: "a ceiling is too big for the type it bounds",
			corrupt: func(spec map[string]any) {
				numberBranch(spec, "chronos.notification.v1.GetUnreadCountResponse",
					"unread")["maximum"] = 9223372036854776000.0
			},
			want: "outside the range of int64",
		},
		{
			name: "a bound is fractional on an integer field",
			corrupt: func(spec map[string]any) {
				numberBranch(spec, "chronos.notification.v1.GetUnreadCountResponse",
					"unread")["maximum"] = 10.5
			},
			want: "which is fractional; int64 holds integers",
		},
		{
			name: "an identifier pattern is not the one ids implements",
			corrupt: func(spec map[string]any) {
				schema(spec, "chronos.identity.v1.Session",
					"sessionId")["pattern"] = "^sess_[0-9ABCDEFGHJKMNPQRSTVWXYZ]{26}$"
			},
			want: "but ids.PatternFor(\"sess\") is",
		},
		{
			name: "an identifier is bounded at the wrong length",
			corrupt: func(spec map[string]any) {
				schema(spec, "chronos.identity.v1.Session", "sessionId")["maxLength"] = 64
			},
			want: "but every sess_ identifier is exactly 31 characters",
		},
		{
			name: "an identifier uses a prefix ids does not register",
			corrupt: func(spec map[string]any) {
				s := schema(spec, "chronos.identity.v1.Session", "sessionId")
				s["pattern"] = "^widget_[0-7][0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{25}$"
			},
			want: "which internal/platform/ids does not register",
		},
		{
			name: "a message reopens itself to unknown fields",
			corrupt: func(spec map[string]any) {
				components(spec)["chronos.identity.v1.RegisterRequest"].(map[string]any)["additionalProperties"] = true
			},
			want: "accepts additional properties",
		},
		{
			name: "a message stops closing itself at all",
			corrupt: func(spec map[string]any) {
				delete(components(spec)["chronos.identity.v1.RegisterRequest"].(map[string]any),
					"additionalProperties")
			},
			want: "does not close additionalProperties",
		},
		{
			name: "an annotation is written beside a $ref",
			corrupt: func(spec map[string]any) {
				s := schema(spec, "chronos.identity.v1.Session", "assuranceLevel")
				// Undo the allOf hoist: put the reference back inline beside the
				// annotations, which is what the generator emits.
				inner := mapOf(sliceOf(s["allOf"])[0])
				delete(s, "allOf")
				s["$ref"] = inner["$ref"]
			},
			want: "sit alongside $ref",
		},
		{
			name: "an enum arrives without a type",
			corrupt: func(spec map[string]any) {
				delete(components(spec)["encoding"].(map[string]any), "type")
			},
			want: "declares an enum with no type",
		},
		{
			name: "a const keeps a redundant enum beside it",
			corrupt: func(spec map[string]any) {
				s := components(spec)["connect-protocol-version"].(map[string]any)
				s["enum"] = []any{1}
			},
			want: "declares both const and enum",
		},
		{
			name: "a parameter loses its worked example",
			corrupt: func(spec map[string]any) {
				for _, p := range sliceOf(post(spec, protectedRoute)["parameters"]) {
					param := mapOf(p)
					delete(param, "example")
					delete(param, "examples")
					delete(mapOf(param["schema"]), "example")
					delete(mapOf(param["schema"]), "examples")
				}
			},
			want: "has no example",
		},
		{
			name: "a request body loses its worked example",
			corrupt: func(spec map[string]any) {
				media := mapOf(mapOf(mapOf(post(spec, protectedRoute)["requestBody"])["content"])["application/json"])
				delete(media, "example")
				delete(media, "examples")
			},
			want: "request body (application/json) has no example",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			spec := clone(loadSpec(t)).(map[string]any)
			tt.corrupt(spec)

			r := &reporter{out: io.Discard}
			checkBounds(r, spec)

			if !containsSubstring(r.problems, tt.want) {
				t.Errorf("breaking %q produced no problem mentioning %q; got:\n  %s",
					tt.name, tt.want, strings.Join(r.problems, "\n  "))
			}
		})
	}
}

// TestAMapIsNotClosed pins the one object the closure rule must leave alone.
//
// A protobuf `map<string, string>` renders as an object whose
// `additionalProperties` IS the value schema — that is what a map MEANS on the
// wire, and writing `false` over it would publish a type that can hold no
// entries. chronos.errors.v1.ErrorDetail.metadata is the live example.
func TestAMapIsNotClosed(t *testing.T) {
	t.Parallel()

	metadata := schema(loadSpec(t), "chronos.errors.v1.ErrorDetail", "metadata")
	if _, isSchema := metadata["additionalProperties"].(map[string]any); !isSchema {
		t.Fatalf("metadata.additionalProperties is %T, not a value schema — the map was closed "+
			"and can now hold nothing", metadata["additionalProperties"])
	}

	r := &reporter{out: io.Discard}
	for _, s := range collectSchemas(loadSpec(t)) {
		if !strings.HasSuffix(s.where, "ErrorDetail/properties/metadata") {
			continue
		}
		r.problems = append(r.problems, boundsProblems(s)...)
	}
	if containsSubstring(r.problems, "additionalProperties") {
		t.Errorf("the closure rule fired on a protobuf map:\n  %s", strings.Join(r.problems, "\n  "))
	}
}

// TestAStaleExemptionIsReported checks the reachability exemption in the
// direction nobody remembers to check.
//
// `intentionallyUnreferenced` is empty today, which means the two-way check has
// nothing to fire on — and a check with nothing to fire on is a check nobody
// knows still works. So the map is injected here instead: an entry naming a
// schema the document does not publish must be reported as stale, because a
// stale exemption is a permanent hole in the rule it exempts from.
func TestAStaleExemptionIsReported(t *testing.T) {
	t.Parallel()

	spec := loadSpec(t)
	r := &reporter{out: io.Discard}
	checkSchemaReachability(r, mapOf(spec["components"]), collectRefs(spec),
		map[string]bool{"chronos.errors.v1.SchemaThatWasDeletedYearsAgo": true})

	if !containsSubstring(r.problems, "drop the exemption") {
		t.Errorf("an exemption naming an unpublished schema was not reported:\n  %s",
			strings.Join(r.problems, "\n  "))
	}
}

// TestCollectSchemasReachesInsideAnOperation asserts the walk does not stop at
// components.
//
// A parameter's schema is written inline under a path, and an earlier version of
// this walk only descended from components.schemas — so every Connect query
// parameter went unchecked while the report said 500-odd schemas were fine.
func TestCollectSchemasReachesInsideAnOperation(t *testing.T) {
	t.Parallel()

	var fromPaths int
	for _, s := range collectSchemas(loadSpec(t)) {
		if strings.HasPrefix(s.where, "#/paths/") {
			fromPaths++
		}
	}
	if fromPaths == 0 {
		t.Error("the schema walk reached nothing under paths; parameters and bodies are unchecked")
	}
}

// --- helpers ----------------------------------------------------------------

func components(spec map[string]any) map[string]any {
	return mapOf(mapOf(spec["components"])["schemas"])
}

// schema returns one property of one published message.
func schema(spec map[string]any, message, property string) map[string]any {
	return mapOf(mapOf(mapOf(components(spec)[message])["properties"])[property])
}

// numberBranch returns the integer half of a 64-bit field.
//
// protobuf-JSON lets a 64-bit integer travel as a number or as a decimal string,
// and fixopenapi splits that into a `oneOf` so each spelling carries the bounds
// that apply to it. The numeric bounds therefore live one level down.
func numberBranch(spec map[string]any, message, property string) map[string]any {
	s := schema(spec, message, property)
	for _, branch := range sliceOf(s["oneOf"]) {
		m := mapOf(branch)
		if str(m["type"]) == "integer" {
			return m
		}
	}
	return s
}
