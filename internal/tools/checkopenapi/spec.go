package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// verbs are the operation keys a path item may carry. Anything else under a path
// (`parameters`, `summary`, an extension) is not an operation.
var verbs = map[string]bool{
	"get": true, "post": true, "put": true, "patch": true, "delete": true,
}

// intentionallyUnreferenced names schemas published on purpose with nothing
// pointing at them. It is EMPTY, and the empty map is the interesting part.
//
// It used to hold chronos.errors.v1.ErrorDetail. That schema is injected by
// internal/tools/gendocs, and it reaches a client inside `connect.error.details`
// — whose item schema the generator synthesised from the Connect protocol as a
// free-form object, because the protocol cannot know what a given server puts
// there. So the document's most important type was published with no `$ref`
// anywhere, and this exemption is what let that pass.
//
// It no longer needs to. gendocs now overrides `connect.error_details.Any` too,
// naming ErrorDetail as the decoded `debug` payload — which is simply true: every
// error this server raises is built in one function, and it attaches exactly that
// one detail type. The reference exists, so the exemption does not.
//
// The exemption is checked in both directions: a name listed here that is not
// published at all is a stale exemption, and a stale exemption is a hole.
var intentionallyUnreferenced = map[string]bool{}

// reporter accumulates problems while narrating what it checked.
//
// Narration matters for a gate: a checker that prints nothing on success is
// indistinguishable from a checker that did not run, and "did not run" is the
// failure this tool traces back to.
type reporter struct {
	out      io.Writer
	color    bool
	problems []string
}

func (r *reporter) check(ok bool, msg string) bool {
	if ok {
		_, _ = fmt.Fprintf(r.out, "  %s    %s\n", r.paint(green, "OK"), msg)
		return true
	}
	_, _ = fmt.Fprintf(r.out, "  %s  %s\n", r.paint(red, "FAIL"), msg)
	r.problems = append(r.problems, msg)
	return false
}

// note records a problem that has no OK counterpart — a per-operation fault,
// where one line per passing operation would bury the failures.
func (r *reporter) note(format string, args ...any) {
	r.problems = append(r.problems, fmt.Sprintf(format, args...))
}

const (
	green = "\033[32m"
	red   = "\033[31m"
)

func (r *reporter) paint(code, s string) string {
	if !r.color {
		return s
	}
	return code + s + "\033[0m"
}

// validate runs every published-contract rule and returns the problems found.
//
// spec is the decoded document; declared is every RPC the .proto sources declare
// mapped to its `(chronos.options.v1.public)` option.
func validate(r *reporter, spec map[string]any, declared map[string]rpc) {
	_, _ = fmt.Fprint(r.out, "openapi spec validation\n\n")

	r.check(strings.HasPrefix(str(spec["openapi"]), "3."), "declares OpenAPI 3.x")

	info := mapOf(spec["info"])
	r.check(str(info["title"]) != "", "info.title is set")
	r.check(str(info["version"]) != "", "info.version is set")
	r.check(len(str(info["description"])) > 200,
		"info.description is substantive, not a placeholder")
	r.check(len(sliceOf(spec["servers"])) > 0, "servers are declared")
	r.check(spec["externalDocs"] != nil, "externalDocs links the error catalogue")

	components := mapOf(spec["components"])
	r.check(len(mapOf(components["securitySchemes"])) > 0, "security schemes are documented")

	paths := mapOf(spec["paths"])
	// The regression this file exists to catch: a generator misconfiguration
	// once produced `paths: {}` — structurally valid, completely useless, and
	// silent. A published API document that is quietly empty is worse than none,
	// because consumers trust it.
	r.check(len(paths) > 0, fmt.Sprintf("paths is NOT empty (%d documented)", len(paths)))

	ops, seen := checkOperations(r, paths)
	r.check(ops > 0, fmt.Sprintf("operations are documented (%d)", ops))
	r.check(len(seen) == ops, fmt.Sprintf("every operationId is unique (%d of %d)", len(seen), ops))

	checkSecurityAgreement(r, paths, declared, ops)
	checkIdempotencyAgreement(r, paths, declared)

	refs := collectRefs(spec)
	checkRefsResolve(r, spec, refs)
	checkSchemaReachability(r, components, refs, intentionallyUnreferenced)
	checkBounds(r, spec)
}

// checkOperations walks every operation once, enforcing the three properties a
// generated client cannot work without.
func checkOperations(r *reporter, paths map[string]any) (ops int, seen map[string]string) {
	seen = map[string]string{}
	for _, path := range sortedKeys(paths) {
		item := mapOf(paths[path])
		for _, verb := range sortedKeys(item) {
			if !verbs[verb] {
				continue
			}
			op := mapOf(item[verb])
			ops++
			where := strings.ToUpper(verb) + " " + path

			switch id := str(op["operationId"]); {
			case id == "":
				r.note("%s: no operationId (generated clients need it)", where)
			case seen[id] != "":
				// operationId must be unique document-wide. A method exposed as
				// both GET and POST is the case that breaks it: one shared id
				// makes every generated client emit two methods with one name.
				r.note("%s: operationId %q is already used by %s", where, id, seen[id])
			default:
				seen[id] = where
			}

			if len(mapOf(op["responses"])) == 0 {
				r.note("%s: no responses documented", where)
			}
			// Descriptions come from proto comments; an empty one means the
			// COMMENTS lint was bypassed or the generator dropped it.
			if str(op["summary"]) == "" && str(op["description"]) == "" {
				r.note("%s: no summary or description — is the RPC documented?", where)
			}
		}
	}
	return ops, seen
}

// checkSecurityAgreement compares the published document against the schema it
// is generated from.
//
// The OpenAPI generator reads gnostic annotations and knows nothing of
// chronos.options.v1, so an RPC's `public` option and its published `security`
// are two statements of one fact — and the SECOND one is what clients read while
// the FIRST is what the authentication interceptor enforces. When the paths were
// hand-written the two had already diverged: ResendEmailVerification is
// `public = true` and was published as requiring a bearer token. That is a
// documented lie about an authentication boundary.
func checkSecurityAgreement(r *reporter, paths map[string]any, declared map[string]rpc, ops int) {
	r.check(len(declared) > 0,
		fmt.Sprintf("the .proto descriptors were read (%d RPCs found)", len(declared)))

	var mismatched []string
	for _, path := range sortedKeys(paths) {
		item := mapOf(paths[path])
		for _, verb := range sortedKeys(item) {
			if !verbs[verb] {
				continue
			}
			op := mapOf(item[verb])
			sec := op["security"]
			where := strings.ToUpper(verb) + " " + path

			if declared[path].public {
				// An empty requirement overrides the document default. `[]`
				// cannot be produced from a proto annotation (an empty repeated
				// field is indistinguishable from an unset one), so `[{}]` —
				// "satisfiable with nothing" — is the form used, and it is what
				// is checked for.
				if !isOpenRequirement(sec) {
					mismatched = append(mismatched, fmt.Sprintf(
						"%s: declares public = true but publishes security %v", where, sec))
				}
			} else if sec != nil {
				mismatched = append(mismatched, fmt.Sprintf(
					"%s: is NOT public but overrides the document security default with %v",
					where, sec))
			}
		}
	}
	r.problems = append(r.problems, mismatched...)
	r.check(len(mismatched) == 0, fmt.Sprintf(
		"published security matches (chronos.options.v1.public) on all %d operations", ops))

	var missing []string
	for route, meta := range declared {
		if meta.public && paths[route] == nil {
			missing = append(missing, route)
		}
	}
	sort.Strings(missing)
	msg := "every public RPC appears in the document"
	if len(missing) > 0 {
		msg += fmt.Sprintf(" — missing: %v", missing)
	}
	r.check(len(missing) == 0, msg)
	for _, route := range missing {
		r.note("%s: public RPC is absent from the document", route)
	}
}

// checkIdempotencyAgreement compares the published document against the header
// the server actually demands.
//
// internal/server/interceptor/idempotency refuses EVERY mutating request that
// arrives without an `Idempotency-Key`, and it decides which requests those are
// from `(chronos.options.v1.operation)` — the same option this check reads. So
// the header is not advice: an operation the document does not mention it on is
// an operation whose every first call fails, and the client author has nothing
// in the published contract to tell them why.
//
// It was already wrong when this check was written. IdentityService declared the
// parameter on all seven of its mutations; NotificationService and ProfileService
// declared it on none of theirs, so six published operations documented a call
// the server refuses. That is the same class of defect as the security drift
// above — the document and the interceptor disagreeing about a request's
// requirements — and it is caught the same way.
// The rule is UNCONDITIONAL, and the earlier version of this check asserted the
// opposite. It carved out public methods on the reasoning that a public method
// "returns from internal/server/interceptor/gates before idempotency is reached
// — there is no principal to scope a key to". The FIRST half of that is exactly
// right: gates.go really does return at `if p.Public { return next(ctx, req) }`
// before Idempotency.Do, so the interceptor never enforces the header on a
// public method.
//
// The conclusion drawn from it is what was wrong. Enforcement moves rather than
// disappearing: identity/api/service.go's idempotencyKey() reads the same header
// and refuses with the same message, so the requirement survives the bypass.
// What the check compared the document against was one enforcement point, not
// the behaviour, and the document has to describe the behaviour.
//
// So the carve-out inverted the gate for the seven public mutations — Register,
// VerifyEmail, ResendEmailVerification, RequestPasswordReset, ResetPassword,
// Authenticate and CreateSession. Those are sign-up and sign-in: every one of
// them refuses a request without the header, and the document was not merely
// silent about it but was defended by a check that would REJECT the correction.
// A client generated from the published spec could not register or authenticate
// anyone.
//
// Verified against the running server, not inferred:
//
//	POST /chronos.identity.v1.IdentityService/Register  (no header)
//	  400 "Idempotency-Key is required on every mutating request"
//	POST /chronos.identity.v1.IdentityService/Register  (with header)
//	  200 {}
func checkIdempotencyAgreement(r *reporter, paths map[string]any, declared map[string]rpc) {
	var mismatched []string
	checked := 0
	for _, path := range sortedKeys(paths) {
		meta, known := declared[path]
		if !known || !meta.mutating {
			continue
		}
		item := mapOf(paths[path])
		for _, verb := range sortedKeys(item) {
			if !verbs[verb] {
				continue
			}
			checked++
			where := strings.ToUpper(verb) + " " + path
			has := declaresHeader(mapOf(item[verb]), idempotencyHeader)

			if !has {
				mismatched = append(mismatched, fmt.Sprintf(
					"%s: is a mutation, which the idempotency interceptor refuses without an "+
						"%s, but the document declares no such parameter",
					where, idempotencyHeader))
			}
		}
	}
	r.problems = append(r.problems, mismatched...)
	r.check(len(mismatched) == 0, fmt.Sprintf(
		"every mutating operation agrees with the idempotency gate about %s (%d checked)",
		idempotencyHeader, checked))
}

// idempotencyHeader is interceptor.IdempotencyHeader, restated for mutatingClass's
// reason: a build-time documentation tool does not import the running server.
const idempotencyHeader = "Idempotency-Key"

func declaresHeader(op map[string]any, name string) bool {
	for _, p := range sliceOf(op["parameters"]) {
		param := mapOf(p)
		if strings.EqualFold(str(param["name"]), name) && str(param["in"]) == "header" {
			return true
		}
	}
	return false
}

// isOpenRequirement reports whether v says "this operation needs no
// credentials", in either of the two forms that say it.
//
// `[]` is the specification's own spelling — an empty array removes the
// document-level default — and is what the published document carries, because
// internal/tools/fixopenapi rewrites the other form into it.
//
// `[{}]` is what a .proto can produce, and is therefore what arrives here before
// the fixer runs: `security` is a repeated field on the gnostic annotation, and
// an empty repeated field is indistinguishable from an unset one, so writing
// `security: []` in a .proto means "say nothing" — which leaves `bearerAuth` in
// force and publishes a public endpoint as authenticated. One requirement
// satisfiable by nothing is the only thing the annotation can express.
//
// Both are accepted because this rule is about WHICH operations are open, not
// about which spelling reached it. Accepting only the canonical form would make
// the gate depend on the fixer having run, and a gate that passes only after
// another tool has been run is a gate that reports on that tool.
func isOpenRequirement(v any) bool {
	list, isList := v.([]any)
	if !isList {
		return false
	}
	if len(list) == 0 {
		return true
	}
	if len(list) != 1 {
		return false
	}
	m, ok := list[0].(map[string]any)
	return ok && len(m) == 0
}

// checkRefsResolve walks each $ref to the node it names. A dangling one makes a
// client generator produce broken code, or silently skip a type.
func checkRefsResolve(r *reporter, spec map[string]any, refs []string) {
	var dangling []string
	for _, ref := range refs {
		if !resolves(spec, ref) {
			dangling = append(dangling, ref)
		}
	}
	msg := fmt.Sprintf("all %d $refs resolve", len(refs))
	if len(dangling) > 0 {
		msg += fmt.Sprintf(" — dangling: %v", dangling[:min(3, len(dangling))])
	}
	r.check(len(dangling) == 0, msg)
}

func resolves(spec map[string]any, ref string) bool {
	if !strings.HasPrefix(ref, "#/") {
		// An external reference cannot be resolved from this document alone and
		// is not something this generator emits; treat it as a fault rather than
		// quietly passing it.
		return false
	}
	var node any = spec
	for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		part = strings.ReplaceAll(part, "~1", "/")
		part = strings.ReplaceAll(part, "~0", "~")
		m := mapOf(node)
		if m == nil {
			return false
		}
		next, ok := m[part]
		if !ok {
			return false
		}
		node = next
	}
	return true
}

// checkSchemaReachability refuses to publish a type nothing points at.
//
// This is what `trim-unused-types` is for, and the leak it was turned on to stop
// was annotation machinery from chronos.options.v1 arriving in
// components.schemas because the generator was handed options.proto.
//
// An earlier form of this check tested `"chronos.options.v1" not in <the file>`,
// and it was WRONG in both directions: it fired on
// chronos.options.v1.AssuranceLevel, which three response messages carry as an
// ordinary field type and which therefore belongs in the document, and on prose
// in info.description that names the `public` option — the document correctly
// telling a reader where `security` comes from. Meanwhile it would have said
// nothing about an unused type from any other package. So the property is stated
// directly instead.
func checkSchemaReachability(r *reporter, components map[string]any, refs []string, exempt map[string]bool) {
	schemas := mapOf(components["schemas"])

	referenced := map[string]bool{}
	for _, ref := range refs {
		if name, ok := strings.CutPrefix(ref, "#/components/schemas/"); ok {
			referenced[name] = true
		}
	}

	var orphans []string
	for _, name := range sortedKeys(schemas) {
		if exempt[name] {
			continue
		}
		if !referenced[pointerEscape(name)] {
			orphans = append(orphans, name)
		}
	}

	// The exemption must not outlive the thing it exempts.
	for name := range exempt {
		if _, ok := schemas[name]; !ok {
			r.note("%s is exempted from the reachability check but is not published at all "+
				"— drop the exemption", name)
		}
	}

	msg := fmt.Sprintf("all %d published schemas are reachable", len(schemas))
	if len(orphans) > 0 {
		msg += fmt.Sprintf(" — unreferenced: %v", orphans[:min(5, len(orphans))])
	}
	r.check(len(orphans) == 0, msg)
	for _, name := range orphans {
		r.note("components.schemas.%s: published but referenced by nothing", name)
	}
}

// pointerEscape renders a schema name as it appears inside a JSON pointer.
func pointerEscape(name string) string {
	name = strings.ReplaceAll(name, "~", "~0")
	return strings.ReplaceAll(name, "/", "~1")
}

// collectRefs finds every $ref value anywhere in the document.
//
// A tree walk rather than a regex over the raw text: it sees a reference written
// in flow style, in a JSON-ish block, or under any nesting, and it cannot be
// fooled by the string "$ref:" appearing inside a description.
func collectRefs(node any) []string {
	seen := map[string]bool{}
	var walk func(any)
	walk = func(n any) {
		switch t := n.(type) {
		case map[string]any:
			for k, v := range t {
				if k == "$ref" {
					if s, ok := v.(string); ok {
						seen[s] = true
						continue
					}
				}
				walk(v)
			}
		case []any:
			for _, v := range t {
				walk(v)
			}
		}
	}
	walk(node)

	out := make([]string, 0, len(seen))
	for ref := range seen {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}

// --- decoding helpers -------------------------------------------------------
//
// The document is decoded into `any`, so every access is a type assertion. These
// three keep that from spreading: a missing or wrongly-typed node reads as
// absent, which is what every rule above wants to say about it.

func mapOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func sliceOf(v any) []any {
	s, _ := v.([]any)
	return s
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
