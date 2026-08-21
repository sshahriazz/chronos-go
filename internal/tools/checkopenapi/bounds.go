package main

// Bounds: the rules that make the published document describe a CLOSED surface.
//
// Everything in this file states one property — every value a client may send or
// receive is bounded, typed, and exemplified — and every rule here has a
// counterpart in the .proto that is enforced at runtime by protovalidate. That
// pairing is the point. A `maxLength` in this document is not documentation of a
// limit, it is the same limit the interceptor refuses at, generated from the same
// `(buf.validate.field)` rule, so the document cannot promise a bound the server
// does not hold.
//
// # Why a gate rather than a linter run by hand
//
// An external audit (the 42Crunch OpenAPI extension) scored this document at 255
// findings, of which roughly 150 were "string has no maxLength", "array has no
// maxItems", "integer has no maximum". Each one is a field somewhere accepting
// arbitrary input, and each one was invisible because nothing in `make check`
// looked. An unbounded `repeated` in a response is worse than untidy: it is a
// promise that a page can be any size, which is exactly what a client's own
// memory budget is written against.
//
// The findings were fixable, but a one-time fix decays — the NEXT RPC reproduces
// every one of them. So the rules live here, run in `make check`, and fail the
// build. See docs/CONVENTIONS.md §7.2 for the authoring workflow they enforce.
//
// # This gate never inspects the fixer's work for the fixer
//
// internal/tools/fixopenapi normalises structure the protobuf sources cannot
// express (`additionalProperties`, `$ref` siblings, the Connect protocol's own
// query parameters). It is FORBIDDEN from inventing a bound on a chronos.* field,
// and this gate is what makes that stick: a field missing `maxLength` fails here
// whether or not the fixer ran, so the only place to satisfy it is the .proto.

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	// The identifier grammar and the idempotency-key bound this gate compares
	// against. Imported deliberately: the point of both rules is that there is ONE
	// implementation, and a copy maintained here would be the next one to drift.
	"github.com/chronos/chronos-go/internal/platform/cqrs"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// schemaAt is one schema node and the JSON pointer that reaches it. The pointer
// is the whole diagnostic value of this gate — "a string has no maxLength" is
// useless, "#/components/schemas/chronos.identity.v1.RegisterRequest/properties/email
// has no maxLength" names the proto field to edit.
type schemaAt struct {
	where  string
	schema map[string]any
}

// checkBounds runs every hardening rule over every schema the document reaches.
func checkBounds(r *reporter, spec map[string]any) {
	checkServersEncrypted(r, spec)

	schemas := collectSchemas(spec)
	r.check(len(schemas) > 0, fmt.Sprintf("schema nodes were found to check (%d)", len(schemas)))

	var problems []string
	for _, s := range schemas {
		problems = append(problems, boundsProblems(s)...)
	}
	sort.Strings(problems)
	r.problems = append(r.problems, problems...)

	msg := fmt.Sprintf("every value in the document is bounded and typed (%d schemas)", len(schemas))
	if len(problems) > 0 {
		msg += fmt.Sprintf(" — %d unbounded", len(problems))
	}
	r.check(len(problems) == 0, msg)

	checkIdentifierGrammar(r, schemas)
	checkIdempotencyKeyBound(r, spec)
	checkExamples(r, spec)
}

// checkIdempotencyKeyBound ties the published ceiling on `Idempotency-Key` to
// the constant that enforces it.
//
// The header is not a protobuf field — it is declared on the operation as a
// gnostic parameter — so nothing generates its bound from anything, and it is the
// one number in this document typed out beside the rule rather than derived from
// it. `cqrs.Key.Validate` refuses a longer key at runtime; this asserts the
// document says the same number.
//
// It matters more than a typo would suggest: the key becomes a causation id in an
// append-only log, so a document promising a ceiling the server does not hold is a
// promise about what can be written permanently.
func checkIdempotencyKeyBound(r *reporter, spec map[string]any) {
	schema := mapOf(mapOf(mapOf(spec["components"])["schemas"])["idempotency-key"])
	if schema == nil {
		r.check(false, "the idempotency-key schema is published — proto/openapi.base.yaml "+
			"declares it and every mutation references it")
		return
	}
	got, ok := asFloat(schema["maxLength"])
	r.check(ok && int(got) == cqrs.MaxKeyLen, fmt.Sprintf(
		"the published Idempotency-Key ceiling is cqrs.MaxKeyLen (%d, document says %v)",
		cqrs.MaxKeyLen, schema["maxLength"]))
}

// identifierPattern recognises a published pattern that is describing a prefixed
// ULID: an anchored pattern whose first token is a lower-case word followed by
// '_'. Nothing else in this document begins that way — a media type starts with
// `image/`, a handle with a character class, a URI with its scheme.
var identifierPattern = regexp.MustCompile(`^\^([a-z][a-z0-9]*)_`)

// checkIdentifierGrammar holds every published identifier to the one grammar
// internal/platform/ids implements.
//
// # Why a gate and not a convention
//
// An identifier's pattern cannot be shared between the .proto files: protobuf has
// no constant an option value can reference, so `max_len` and `pattern` are
// literals, typed out per field, ~30 times. That is a copy of a security-relevant
// rule per field, and copies drift.
//
// They had already drifted before anyone looked, in both directions at once. The
// literals were UPPERCASE-ONLY while `ulid.ParseStrict` accepts lowercase, so the
// validation interceptor refused identifiers the handler would have parsed — a
// rule stricter than the handler, refusing valid input at the boundary with no
// test anywhere noticing. And they admitted any Crockford character in the
// LEADING position, which ParseStrict rejects as a timestamp overflow, so the
// published document described identifiers that cannot exist.
//
// Neither is the kind of mistake review catches: both patterns look right.
//
// So the literal stays, and this compares it against `ids.PatternFor`, which is
// the same function `ids.Parse` is tested against
// (TestThePatternAgreesWithParse). A field that types its own gets a diff naming
// the exact string to paste.
func checkIdentifierGrammar(r *reporter, schemas []schemaAt) {
	known := map[string]string{} // prefix -> the ids.Kind that registers it
	for name, prefix := range ids.Registry() {
		known[prefix] = name
	}

	var problems []string
	checked := 0
	for _, s := range schemas {
		pattern := str(s.schema["pattern"])
		if pattern == "" {
			continue
		}
		// An optional identifier admits the empty string first. Both halves are
		// checked together, so a field cannot claim to be optional and then
		// publish a different grammar for the non-empty case.
		body, optional := strings.CutPrefix(pattern, "^$|")

		m := identifierPattern.FindStringSubmatch(body)
		if m == nil {
			continue
		}
		prefix := m[1]
		if _, isKnown := known[prefix]; !isKnown {
			problems = append(problems, fmt.Sprintf(
				"%s: publishes identifiers prefixed %q, which internal/platform/ids does not "+
					"register — add the Kind there, or the boundary is validating a shape "+
					"nothing can parse", s.where, prefix))
			continue
		}
		checked++

		want := ids.PatternFor(prefix)
		if optional {
			want = ids.OptionalPatternFor(prefix)
		}
		if pattern != want {
			problems = append(problems, fmt.Sprintf(
				"%s: publishes\n      %s\n    but ids.PatternFor(%q) is\n      %s\n    "+
					"— paste that one; the two are separate implementations of one grammar",
				s.where, pattern, prefix, want))
		}

		if maxLen, ok := asFloat(s.schema["maxLength"]); !ok || int(maxLen) != ids.RenderedLen(prefix) {
			problems = append(problems, fmt.Sprintf(
				"%s: publishes maxLength %v, but every %s_ identifier is exactly %d characters",
				s.where, s.schema["maxLength"], prefix, ids.RenderedLen(prefix)))
		}
	}

	sort.Strings(problems)
	r.problems = append(r.problems, problems...)

	msg := fmt.Sprintf("every published identifier uses the ids grammar (%d checked)", checked)
	if len(problems) > 0 {
		msg += fmt.Sprintf(" — %d disagree", len(problems))
	}
	r.check(len(problems) == 0, msg)
	r.check(checked > 0, "identifiers were found to check — a run that finds none proves nothing")
}

// checkServersEncrypted refuses a cleartext server URL.
//
// This document's only credential is a bearer token, and a bearer token is a
// password: whoever holds it is the session. `http://localhost:8090` sat at the
// top of `servers` for the convenience of the local docs UI, which made the
// published document say that the first and default way to call this API is over
// a channel that carries that token in the clear. The docs UI now injects its own
// local server at serve time (cmd/apidocs), so the convenience survived and the
// published artefact stopped advertising cleartext.
func checkServersEncrypted(r *reporter, spec map[string]any) {
	var cleartext []string
	for _, entry := range sliceOf(spec["servers"]) {
		url := str(mapOf(entry)["url"])
		if strings.HasPrefix(strings.ToLower(url), "http://") {
			cleartext = append(cleartext, url)
		}
	}
	msg := "every declared server is https"
	if len(cleartext) > 0 {
		msg += fmt.Sprintf(" — cleartext: %v", cleartext)
	}
	r.check(len(cleartext) == 0, msg)
	for _, url := range cleartext {
		r.note("servers: %s carries the session bearer token in the clear", url)
	}
}

// boundsProblems returns every rule one schema node violates.
func boundsProblems(s schemaAt) []string {
	m, where := s.schema, s.where
	var out []string
	note := func(format string, args ...any) {
		out = append(out, where+": "+fmt.Sprintf(format, args...))
	}

	// A $ref with siblings. In OpenAPI 3.1 the siblings are legal and are
	// annotations, but they are silently DISCARDED by a large share of client
	// generators and validators, which resolve the reference and return its
	// target. `not: {enum: [CHANNEL_UNSPECIFIED]}` written beside a $ref reads as
	// a constraint and is enforced by nothing. fixopenapi hoists these into
	// `allOf`, where every consumer honours them.
	if _, hasRef := m["$ref"]; hasRef && len(m) > 1 {
		note("keys %v sit alongside $ref, where consumers may drop them", siblingKeys(m))
	}

	types := typesOf(m)
	_, hasEnum := m["enum"]
	_, hasConst := m["const"]

	if hasEnum && len(types) == 0 {
		note("declares an enum with no type, so the JSON type of its values is undefined")
	}
	if hasConst && hasEnum {
		note("declares both const and enum; const alone already fixes the value")
	}

	for _, t := range types {
		switch t {
		case "string":
			// An enum or a const IS the bound: the value set is finite and
			// enumerated, which is stricter than any pattern.
			if hasEnum || hasConst {
				continue
			}
			if _, ok := m["maxLength"]; !ok {
				note("is a string with no maxLength")
			}
			if _, ok := m["pattern"]; !ok {
				note("is a string with no pattern")
			}
		case "array":
			if _, ok := m["maxItems"]; !ok {
				note("is an array with no maxItems")
			}
		case "integer", "number":
			if hasEnum || hasConst {
				continue
			}
			// `exclusiveMinimum` counts. protovalidate's `gt` maps to it rather
			// than to `minimum`, and "greater than 0" bounds a field exactly as
			// well as "at least 1" — demanding the other spelling would push
			// somebody towards writing a weaker rule to satisfy a checker.
			if !hasAny(m, "minimum", "exclusiveMinimum") {
				note("is numeric with no minimum")
			}
			if !hasAny(m, "maximum", "exclusiveMaximum") {
				note("is numeric with no maximum")
			}
			format := str(m["format"])
			if format == "" {
				note("is numeric with no format, so its precision is unstated")
			}
			for _, key := range []string{"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"} {
				if v, ok := m[key]; ok {
					if why := boundFitsFormat(v, format); why != "" {
						note("%s %s", key, why)
					}
				}
			}
		case "object":
			// A protobuf `map<k, v>` renders as an object whose
			// additionalProperties IS the value schema. That is a bounded shape
			// already and must not be closed.
			if _, isMap := m["additionalProperties"].(map[string]any); isMap {
				continue
			}
			if _, hasProps := m["properties"]; !hasProps {
				continue
			}
			switch ap := m["additionalProperties"].(type) {
			case bool:
				if ap {
					note("is an object that accepts additional properties")
				}
			case nil:
				note("is an object that does not close additionalProperties")
			}
		}
	}
	return out
}

// checkExamples requires a worked sample everywhere a caller writes a value.
//
// A parameter or request body with no example is a field a client author has to
// guess at, and the guesses land in production. Every one of these comes from the
// .proto — `(gnostic.openapi.v3.property) = {example: ...}` on the field — except
// the Connect protocol's own query parameters, which the generator synthesises
// and fixopenapi supplies from a closed table.
func checkExamples(r *reporter, spec map[string]any) {
	var missing []string
	for _, path := range sortedKeys(mapOf(spec["paths"])) {
		item := mapOf(mapOf(spec["paths"])[path])
		for _, verb := range sortedKeys(item) {
			if !verbs[verb] {
				continue
			}
			op := mapOf(item[verb])
			where := strings.ToUpper(verb) + " " + path

			for _, p := range sliceOf(op["parameters"]) {
				param := mapOf(p)
				if !hasExample(spec, param) && !hasExample(spec, mapOf(param["schema"])) {
					missing = append(missing, fmt.Sprintf(
						"%s: parameter %q has no example", where, str(param["name"])))
				}
			}
			for _, ct := range sortedKeys(mapOf(mapOf(op["requestBody"])["content"])) {
				media := mapOf(mapOf(mapOf(op["requestBody"])["content"])[ct])
				if !hasExample(spec, media) {
					missing = append(missing, fmt.Sprintf(
						"%s: request body (%s) has no example", where, ct))
				}
			}
		}
	}
	sort.Strings(missing)
	r.problems = append(r.problems, missing...)

	msg := "every parameter and request body carries a worked example"
	if len(missing) > 0 {
		msg += fmt.Sprintf(" — %d without one", len(missing))
	}
	r.check(len(missing) == 0, msg)
}

// integerFormats is the range each integer `format` can hold, with the ceiling
// stated EXCLUSIVELY.
//
// Exclusive because a JSON number is a double, and the inclusive ceilings do not
// all survive being one. `float64(math.MaxInt64)` is 2^63 — it rounds UP, past
// the value it is supposed to represent — so a check written as `f > maxInt64`
// can never fail: the too-big value and the limit it is compared against are the
// same double. That is not a hypothetical. It is how the published document came
// to carry `maximum: 9223372036854776000` while every gate here was green, and
// the first version of this very rule failed to catch it for exactly this reason.
//
// Stated as "must be strictly below 2^63" instead, the arithmetic is exact and
// the check works. It also says something true about the field: no `maximum` a
// double can carry is a usable ceiling for an int64, so an int64 field wanting a
// published ceiling needs a smaller, real one.
var integerFormats = map[string]struct{ min, maxExclusive float64 }{
	"int32":  {-2147483648, 2147483648},
	"int64":  {-9223372036854775808, 9223372036854775808},
	"uint32": {0, 4294967296},
	"uint64": {0, 18446744073709551616},
}

// boundFitsFormat reports why a numeric bound does not fit its declared format,
// or "" when it does.
//
// This rule exists because of a bound this repository published: an int64 field
// was given `maximum: 9223372036854775807` through a gnostic annotation, whose
// `maximum` is a DOUBLE. 2^63-1 has no exact double, so it came back out of the
// generator as 9223372036854776000 — larger than any int64, and a number no
// value can ever reach. Every other gate here was green; the finding came from an
// external audit, which is the situation this file exists to stop happening
// twice.
//
// The lesson generalises past that one field: a bound outside its type is either
// vacuous (nothing can violate it) or impossible (nothing can satisfy it), and
// both are worse than no bound, because both read as protection.
func boundFitsFormat(v any, format string) string {
	limits, known := integerFormats[format]
	if !known {
		return ""
	}
	f, ok := asFloat(v)
	if !ok {
		return fmt.Sprintf("is %v, which is not a number", v)
	}
	if f != math.Trunc(f) {
		return fmt.Sprintf("is %v, which is fractional; %s holds integers", v, format)
	}
	if f < limits.min || f >= limits.maxExclusive {
		return fmt.Sprintf("is %v, which is outside the range of %s — a bound no value can "+
			"reach is not a bound", v, format)
	}
	return ""
}

func asFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case float64:
		return t, true
	default:
		return 0, false
	}
}

func hasAny(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		if _, ok := m[k]; ok {
			return true
		}
	}
	return false
}

// hasExample follows a `$ref` before answering.
//
// The `Idempotency-Key` parameter's schema is a reference to
// `#/components/schemas/idempotency-key`, where the example lives — described
// once for all thirteen mutations that carry it. A check that looked only at the
// reference node would report thirteen missing examples and push somebody towards
// pasting the example thirteen times to satisfy it.
func hasExample(spec, m map[string]any) bool {
	if m == nil {
		return false
	}
	if hasAny(m, "example", "examples") {
		return true
	}
	if ref := str(m["$ref"]); ref != "" {
		var node any = spec
		for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			node = mapOf(node)[strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")]
		}
		return hasAny(mapOf(node), "example", "examples")
	}
	return false
}

// collectSchemas reaches every schema node a client can encounter.
//
// It descends from the three places a schema is REACHABLE rather than walking the
// document blindly: a blind walk cannot tell `properties.items` — a field named
// "items" — from the `items` keyword, and would check prose as if it were a
// schema.
func collectSchemas(spec map[string]any) []schemaAt {
	var out []schemaAt
	seen := map[string]bool{}

	var descend func(node any, where string)
	descend = func(node any, where string) {
		m := mapOf(node)
		if m == nil || seen[where] {
			return
		}
		seen[where] = true
		out = append(out, schemaAt{where: where, schema: m})

		for _, k := range sortedKeys(mapOf(m["properties"])) {
			descend(mapOf(m["properties"])[k], where+"/properties/"+k)
		}
		descend(m["items"], where+"/items")
		descend(m["not"], where+"/not")
		descend(m["additionalProperties"], where+"/additionalProperties")
		for _, key := range []string{"allOf", "anyOf", "oneOf", "prefixItems"} {
			for i, sub := range sliceOf(m[key]) {
				descend(sub, fmt.Sprintf("%s/%s/%d", where, key, i))
			}
		}
	}

	components := mapOf(spec["components"])
	for _, name := range sortedKeys(mapOf(components["schemas"])) {
		descend(mapOf(components["schemas"])[name], "#/components/schemas/"+pointerEscape(name))
	}

	for _, path := range sortedKeys(mapOf(spec["paths"])) {
		item := mapOf(mapOf(spec["paths"])[path])
		for _, verb := range sortedKeys(item) {
			if !verbs[verb] {
				continue
			}
			op := mapOf(item[verb])
			base := "#/paths/" + pointerEscape(path) + "/" + verb

			for i, p := range sliceOf(op["parameters"]) {
				descend(mapOf(mapOf(p)["schema"]), fmt.Sprintf("%s/parameters/%d/schema", base, i))
			}
			descendContent(descend, mapOf(op["requestBody"])["content"], base+"/requestBody")
			for _, code := range sortedKeys(mapOf(op["responses"])) {
				descendContent(descend, mapOf(mapOf(op["responses"])[code])["content"],
					base+"/responses/"+code)
			}
		}
	}
	return out
}

func descendContent(descend func(any, string), content any, where string) {
	c := mapOf(content)
	for _, ct := range sortedKeys(c) {
		descend(mapOf(c[ct])["schema"], where+"/content/"+pointerEscape(ct)+"/schema")
	}
}

// typesOf reads `type`, which OpenAPI 3.1 allows to be a single name or a list —
// protobuf's int64 arrives as `[string, integer]`, because protobuf-JSON accepts
// both spellings of a 64-bit number.
func typesOf(m map[string]any) []string {
	switch t := m["type"].(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, v := range t {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func siblingKeys(m map[string]any) []string {
	out := make([]string, 0, len(m)-1)
	for k := range m {
		if k != "$ref" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
