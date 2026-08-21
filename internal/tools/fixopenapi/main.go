// Command fixopenapi normalises the generated OpenAPI document.
//
// It runs in `make api-docs`, after `buf generate` and before
// `internal/tools/checkopenapi`, and it exists because a handful of the
// document's properties CANNOT be expressed in a .proto file at all:
//
//   - `additionalProperties: false` on a message. Protobuf has no way to say
//     "this object is closed", and the generator does not assume it.
//   - Annotations written beside a `$ref`. The generator emits `title`,
//     `description` and `not` as siblings of a reference. That is legal in
//     OpenAPI 3.1 and DISCARDED by a large share of client generators and
//     validators, which resolve the reference and return its target — so a
//     `not: {enum: [CHANNEL_UNSPECIFIED]}` written there reads as a constraint
//     and is enforced by nothing. Hoisted into `allOf`, every consumer honours it.
//   - The Connect protocol's own schemas and query parameters. `connect.error`,
//     `connect-timeout-header`, `message`, `encoding`, `base64` and the rest are
//     synthesised by the generator from the protocol, not from this repository's
//     schema. No .proto file mentions them, so no .proto file can bound them.
//   - The string spelling of a 64-bit integer. protobuf-JSON accepts an int64 as
//     either a number or a decimal string, so the generator emits
//     `type: [integer, string]`; the string half then needs a pattern the
//     protobuf source has no field to hang one on.
//   - A worked example for a request BODY. Every value in one comes from a
//     field's `(gnostic.openapi.v3.property).example` in the .proto, but OpenAPI
//     wants them assembled into one object on the media type, which is a shape
//     no per-field annotation can produce.
//
// # What this tool may NOT do
//
// It may not invent a bound on a chronos.* field. Not one rule below reads a
// field's meaning, and the only bounds it writes are either derived from the
// document (an int64's pattern is the JSON spelling of an integer, an assembled
// example is the field examples that are already there) or come from the closed
// `protocolBounds` table, whose every entry is a schema the CONNECT PROTOCOL
// owns rather than this repository.
//
// That restraint is what keeps `internal/tools/checkopenapi` meaningful. A fixer
// permitted to fill in a missing `maxLength` would turn every unbounded proto
// field green without anyone editing a .proto, and the gate would then be
// measuring this tool rather than the schema.
//
// # Idempotent
//
// Running it twice changes nothing the second time, and `make api-docs` is safe
// to run repeatedly. That is asserted by TestFixingIsIdempotent.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

func main() {
	spec := flag.String("spec", "docs/api/chronos-openapi.yaml", "the generated OpenAPI document")
	quiet := flag.Bool("quiet", false, "print nothing on success")
	flag.Parse()

	changed, err := fixFile(*spec, os.Stdout, *quiet)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "fixopenapi:", err)
		os.Exit(1)
	}
	if !*quiet {
		_, _ = fmt.Fprintf(os.Stdout, "  normalised %s (%d edits)\n", *spec, changed)
	}
}

func fixFile(path string, out io.Writer, quiet bool) (int, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- a build-time tool reading this repo's own artifacts
	if err != nil {
		return 0, fmt.Errorf("cannot read %s — run `buf generate --template buf.gen.openapi.yaml`: %w", path, err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return 0, fmt.Errorf("%s is not parseable YAML: %w", path, err)
	}
	if len(doc.Content) == 0 {
		return 0, fmt.Errorf("%s decoded to nothing; an empty document is not a valid spec", path)
	}
	root := doc.Content[0]

	f := &fixer{root: root, out: out, quiet: quiet}
	f.run()

	var b strings.Builder
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return 0, fmt.Errorf("cannot re-encode %s: %w", path, err)
	}
	if err := enc.Close(); err != nil {
		return 0, fmt.Errorf("cannot re-encode %s: %w", path, err)
	}

	// #nosec G306 -- generated documentation is intended to be world-readable
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return 0, fmt.Errorf("cannot write %s: %w", path, err)
	}
	return f.edits, nil
}

type fixer struct {
	root  *yaml.Node
	out   io.Writer
	quiet bool
	edits int

	// unexampled records request bodies this tool could not build an example
	// for, because a REQUIRED field carries none in the .proto. Reported rather
	// than guessed: a fabricated value for a required field is a worked example
	// that does not work.
	unexampled []string
}

func (f *fixer) run() {
	components := child(f.root, "components")
	schemas := child(components, "schemas")

	for _, s := range collectSchemas(f.root) {
		f.hoistRefSiblings(s)
		f.typeBareEnum(s)
		f.dropEnumBesideConst(s)
		f.closeObject(s)
		f.splitDualTypeInt64(s)
	}
	f.applyProtocolBounds(schemas)
	f.canonicaliseOpenSecurity()
	f.exampleParameters()
	f.exampleRequestBodies(schemas)

	sort.Strings(f.unexampled)
	for _, where := range f.unexampled {
		_, _ = fmt.Fprintf(f.out, "  no example assembled for %s — a required field has no "+
			"(gnostic.openapi.v3.property).example in the .proto\n", where)
	}
}

// --- structural rules -------------------------------------------------------

// hoistRefSiblings rewrites `{$ref, title, description, not}` as
// `{allOf: [{$ref}], title, description, not}`.
//
// `allOf` is the form every consumer honours; siblings of a `$ref` are 3.1-only
// and widely dropped. The reference moves; everything else stays where it was, so
// a reader sees the same keys in the same order.
func (f *fixer) hoistRefSiblings(s *yaml.Node) {
	ref := child(s, "$ref")
	if ref == nil || len(s.Content) <= 2 {
		return
	}
	deleteKey(s, "$ref")
	wrapper := &yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{
		mapping("$ref", ref),
	}}
	setKey(s, "allOf", wrapper)
	f.edits++
}

// typeBareEnum gives an enum whose `type` the generator omitted the JSON type its
// own members have. Connect's `encoding`, `compression` and `connect` query
// parameters arrive this way.
func (f *fixer) typeBareEnum(s *yaml.Node) {
	enum := child(s, "enum")
	if enum == nil || child(s, "type") != nil || enum.Kind != yaml.SequenceNode {
		return
	}
	t := ""
	for _, v := range enum.Content {
		switch v.Tag {
		case "!!str":
			t = mergeType(t, "string")
		case "!!int":
			t = mergeType(t, "integer")
		case "!!float":
			t = mergeType(t, "number")
		default:
			return
		}
	}
	if t == "" {
		return
	}
	setKeyBefore(s, "type", scalar(t), "enum")
	f.edits++
}

func mergeType(have, want string) string {
	switch {
	case have == "":
		return want
	case have == want:
		return have
	case (have == "integer" && want == "number") || (have == "number" && want == "integer"):
		return "number"
	default:
		// Mixed string and numeric members. Leave it alone rather than choose:
		// the gate reports it, and a human decides what the field means.
		return ""
	}
}

// dropEnumBesideConst removes an `enum` that repeats a `const`.
//
// The generator emits both for Connect-Protocol-Version. `const: 1` already fixes
// the value; the enum beside it is a second, weaker statement of the same thing,
// and a validator that reads only one of them is reading a rule someone might
// later change in the other.
func (f *fixer) dropEnumBesideConst(s *yaml.Node) {
	c := child(s, "const")
	enum := child(s, "enum")
	if c == nil || enum == nil || enum.Kind != yaml.SequenceNode {
		return
	}
	if len(enum.Content) != 1 || enum.Content[0].Value != c.Value {
		// The enum says something the const does not. That is a contradiction
		// rather than a duplicate, and it is not this tool's to resolve.
		return
	}
	deleteKey(s, "enum")
	f.edits++
}

// closeObject writes `additionalProperties: false` on an object with declared
// properties.
//
// A protobuf message is a CLOSED type: a field it does not declare is not part of
// it. The document said the opposite by omission, which is what an auditor reads
// and what a strict client generator emits a catch-all map for.
//
// A protobuf `map<k, v>` is deliberately untouched: it renders as an object whose
// `additionalProperties` IS the value schema, which is already a bounded shape.
func (f *fixer) closeObject(s *yaml.Node) {
	if child(s, "properties") == nil {
		return
	}
	if ap := child(s, "additionalProperties"); ap != nil {
		if ap.Kind == yaml.MappingNode {
			return // a map's value schema
		}
		if ap.Value == "false" {
			return
		}
		ap.SetString("false")
		ap.Tag = "!!bool"
		f.edits++
		return
	}
	setKey(s, "additionalProperties", boolean(false))
	f.edits++
}

// splitDualTypeInt64 rewrites `type: [integer, string]` as a `oneOf` of the two
// spellings, and bounds each one.
//
// protobuf-JSON allows a 64-bit integer to travel as a number OR as a decimal
// string, because a JSON number is a double and cannot hold 2^63 without loss.
// The generator states that as a two-element `type`, which is legal and which
// leaves the schema unable to describe either spelling properly:
//
//   - `format: int64` sits on a schema whose type includes `string`, and a format
//     must be applicable to the type it annotates. An auditor reports it, and it
//     is right to: read literally, the schema says a STRING may be formatted as
//     an int64, which is not a thing.
//   - the numeric bounds apply to the number spelling and the length bounds to
//     the string spelling, but written side by side there is nothing saying so —
//     a validator checks `maxLength` against a number and `maximum` against a
//     string, and skips both.
//
// Split, each branch says one true thing. The value is unchanged for a client: a
// `oneOf` of integer and string generates the same union type the two-element
// `type` did, and now with the bounds attached to the spelling they bound.
//
// This tool is forbidden from inventing bounds, and does not here. The numeric
// bounds are the ones already present, moved. The string bounds are derived: the
// JSON spelling of an integer is `^-?[0-9]+$`, and its longest form is the 20
// characters of `-9223372036854775808`. Neither is a judgement about the field.
func (f *fixer) splitDualTypeInt64(s *yaml.Node) {
	format := child(s, "format")
	if format == nil || (format.Value != "int64" && format.Value != "uint64") {
		return
	}
	t := child(s, "type")
	if t == nil || t.Kind != yaml.SequenceNode || !hasType(s, "string") || !hasType(s, "integer") {
		return
	}

	// Keys that describe the NUMBER spelling, in the order a reader wants them.
	number := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		scalar("type"), scalar("integer"),
	}}
	for _, key := range []string{"format", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf"} {
		if v := child(s, key); v != nil {
			setKey(number, key, v)
			deleteKey(s, key)
		}
	}

	text := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		scalar("type"), scalar("string"),
	}}
	for _, key := range []string{"pattern", "maxLength", "minLength"} {
		if v := child(s, key); v != nil {
			setKey(text, key, v)
			deleteKey(s, key)
		}
	}
	if child(text, "pattern") == nil {
		setKey(text, "pattern", scalar(`^-?[0-9]+$`))
	}
	if child(text, "maxLength") == nil {
		setKey(text, "maxLength", integer(20))
	}

	deleteKey(s, "type")
	setKey(s, "oneOf", &yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{number, text}})
	f.edits++
}

// canonicaliseOpenSecurity rewrites an operation's `security: [{}]` as
// `security: []`.
//
// Both mean "this operation needs no credentials". `[]` is the form the OpenAPI
// specification names for the purpose — "an empty array can be used to remove a
// top-level security declaration" — and `[{}]` is one requirement that happens to
// be satisfiable by nothing, which every auditor reads as a mistake: an empty
// requirement inside a non-empty list is, almost everywhere it appears, somebody
// having deleted a scheme and left the braces.
//
// The .proto cannot emit `[]`. `security` is a repeated field on the gnostic
// annotation, and an empty repeated field is indistinguishable from an unset one
// — so `security: []` in the proto means "say nothing", which leaves the
// document-level `bearerAuth` in force and publishes six public endpoints as
// authenticated. `[{}]` is the only thing the annotation CAN say, and this is
// where it becomes the thing the specification says.
//
// The two forms are equivalent, so `checkopenapi.isOpenRequirement` accepts
// either: the agreement it enforces — published `security` against
// `(chronos.options.v1.public)` — is about which operations are open, not about
// which of two spellings the document uses.
func (f *fixer) canonicaliseOpenSecurity() {
	paths := child(f.root, "paths")
	if paths == nil {
		return
	}
	for i := 1; i < len(paths.Content); i += 2 {
		item := paths.Content[i]
		for j := 1; j < len(item.Content); j += 2 {
			sec := child(item.Content[j], "security")
			if sec == nil || sec.Kind != yaml.SequenceNode || len(sec.Content) != 1 {
				continue
			}
			only := sec.Content[0]
			if only.Kind != yaml.MappingNode || len(only.Content) != 0 {
				continue
			}
			sec.Content = nil
			sec.Style = yaml.FlowStyle
			f.edits++
		}
	}
}

// --- the closed table of schemas this repository does not own ---------------

// protocolBounds is every bound this tool is allowed to originate, and each entry
// names a schema synthesised by protoc-gen-connect-openapi from the CONNECT
// PROTOCOL or from a well-known type — never from a .proto file in this
// repository. There is nowhere else these could be declared: no field in
// proto/chronos owns them.
//
// Keeping it a table rather than a rule is deliberate. A rule ("bound any string
// the generator emitted") would silently absorb the next unbounded field somebody
// forgets to annotate, and that field would never reach the gate.
//
// The table is checked in BOTH directions: an entry naming a schema the document
// does not publish is a stale exemption, and a stale exemption is a hole.
var protocolBounds = map[string]map[string]any{
	// RFC 3339, which is what protobuf-JSON renders a Timestamp as. The pattern
	// is the grammar, not a validity check — it admits 2026-02-31, and so does
	// every other regex anybody writes for this.
	"google.protobuf.Timestamp": {
		"maxLength": 64,
		"pattern":   `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`,
	},
	// Connect's timeout header, in milliseconds. The ceiling is one hour, well
	// above any deadline this server honours and far below "unbounded".
	//
	// `format` is `int32` rather than `int64`, and the pairing with the retype
	// below is the reason: a `format` must be applicable to the type it sits on,
	// and a millisecond count that is bounded at 3,600,000 fits an int32 with four
	// orders of magnitude to spare. Declaring int64 here would be a wider
	// precision claim than the bound one line down.
	"connect-timeout-header": {
		"format":  "int32",
		"minimum": 0,
		"maximum": 3600000,
	},
	// The developer-facing message. `pattern` is deliberately vacuous, and saying
	// so here is the point: this string is prose assembled by whichever layer
	// failed, in English, with wrapped causes and occasionally newlines. Any
	// tighter pattern would be a rule this document has no way to keep, and a
	// published pattern the server violates is worse than none — a strict client
	// would reject the error response and report a parse failure instead of the
	// error. The ceiling is the real bound.
	"connect.error/properties/message": {
		"maxLength": 4096,
		"pattern":   `^[\s\S]*$`,
	},
	"connect.error/properties/details": {
		"maxItems": 64,
	},
	// A type URL: `type.googleapis.com/chronos.errors.v1.ErrorDetail`.
	"connect.error_details.Any/properties/type": {
		"maxLength": 512,
		"pattern":   `^[A-Za-z0-9.\-]+/[A-Za-z0-9_.]+$`,
	},
	// The detail message, protobuf-serialized and base64-encoded.
	"connect.error_details.Any/properties/value": {
		"maxLength": 65536,
		"pattern":   `^[A-Za-z0-9+/]*={0,2}$`,
	},
	// One value, because the protocol has one. Omit the parameter to send an
	// unencoded message; there is no "off" spelling to publish, since anything
	// that is not "1" is off by falling through the comparison above.
	"base64": {
		"enum": []any{"1"},
	},
}

// protocolRetypes corrects a JSON type the generator chose too loosely, and it
// is the ONE table here that overwrites something rather than filling a gap — so
// it is separate, and it is one entry long.
//
// `Connect-Timeout-Ms` is a count of milliseconds. The generator types it
// `number`, which admits 5000.5, and a fractional millisecond is not a value this
// protocol has. `number` also makes any integer `format` inapplicable, so the
// schema could not carry one without contradicting itself — a document saying
// "some number, of unstated precision, meaning milliseconds".
//
// `base64` is typed `boolean` by the generator, and the Connect protocol has no
// boolean there. connect-go reads it as
//
//	query.Get(connectUnaryBase64QueryParameter) == "1"
//
// — a strict comparison against the one string, and its own client only ever
// writes "1". So `true` is not a synonym for on; it is silently OFF. That is the
// worst shape this mistake could take, because a client generated from a
// `boolean` sends `true`, the server then treats the still-encoded message as
// literal JSON, and the failure surfaces as a parse error about the payload
// rather than about the flag:
//
//	GET ...?message=e30&base64=true  400 unmarshal message: invalid value e30
//	GET ...?message=e30&base64=1     200
//
// Verified against the running server and against connect-go v1.20.0, not
// inferred from the protocol description.
var protocolRetypes = map[string]string{
	"connect-timeout-header": "integer",
	"base64":                 "string",
}

// protocolRedescribes replaces a generated description that is not merely thin
// but actively misleading. Like protocolRetypes it OVERWRITES, so it stays
// separate and stays short.
//
// The generator describes `base64` as "Specifies if the message query param is
// base64 encoded" — the phrasing of a boolean, which is exactly the reading that
// makes a client send `true` and get a parse error about its payload.
var protocolRedescribes = map[string]string{
	"base64": "Set to the string `1` when `message` is base64url-encoded; omit it " +
		"otherwise. This is NOT a boolean: the protocol compares the value against " +
		"`1` exactly, so `true` is treated as not-encoded and the still-encoded " +
		"message reaches the parser as literal JSON.",
}

func (f *fixer) applyProtocolBounds(schemas *yaml.Node) {
	if schemas == nil {
		return
	}
	for _, name := range sortedKeys(protocolRetypes) {
		target := resolvePath(schemas, name)
		if target == nil {
			_, _ = fmt.Fprintf(f.out, "  protocolRetypes names %s, which this document does "+
				"not publish — drop the entry\n", name)
			continue
		}
		if t := child(target, "type"); t == nil || t.Value != protocolRetypes[name] {
			setKey(target, "type", scalar(protocolRetypes[name]))
			f.edits++
		}
	}
	for _, name := range sortedKeys(protocolRedescribes) {
		target := resolvePath(schemas, name)
		if target == nil {
			_, _ = fmt.Fprintf(f.out, "  protocolRedescribes names %s, which this document "+
				"does not publish — drop the entry\n", name)
			continue
		}
		if d := child(target, "description"); d == nil || d.Value != protocolRedescribes[name] {
			setKey(target, "description", scalar(protocolRedescribes[name]))
			f.edits++
		}
	}
	for _, name := range sortedKeys(protocolBounds) {
		target := resolvePath(schemas, name)
		if target == nil {
			_, _ = fmt.Fprintf(f.out, "  protocolBounds names %s, which this document does "+
				"not publish — drop the entry\n", name)
			continue
		}
		for _, k := range sortedAnyKeys(protocolBounds[name]) {
			if child(target, k) != nil {
				continue
			}
			setKey(target, k, valueNode(protocolBounds[name][k]))
			f.edits++
		}
	}
}

// --- examples ---------------------------------------------------------------

// protocolExamples are worked values for the parameters Connect defines. Same
// reasoning as protocolBounds: no .proto declares them, so nothing else can.
var protocolExamples = map[string]string{
	"Connect-Protocol-Version": "1",
	"Connect-Timeout-Ms":       "5000",
	"encoding":                 "json",
	"base64":                   "1",
	"compression":              "identity",
	"connect":                  "v1",
	"message":                  "{}",
}

func (f *fixer) exampleParameters() {
	paths := child(f.root, "paths")
	if paths == nil {
		return
	}
	for i := 1; i < len(paths.Content); i += 2 {
		item := paths.Content[i]
		for j := 1; j < len(item.Content); j += 2 {
			op := item.Content[j]
			params := child(op, "parameters")
			if params == nil {
				continue
			}
			for _, p := range params.Content {
				name := valueOf(child(p, "name"))
				ex, known := protocolExamples[name]
				if !known || child(p, "example") != nil {
					continue
				}
				setKey(p, "example", scalar(ex))
				f.edits++
			}
		}
	}
}

// exampleRequestBodies assembles one worked request object per operation from the
// field examples already in the schema.
//
// Every value comes from a `(gnostic.openapi.v3.property).example` in the .proto,
// so this tool composes rather than invents — and when a REQUIRED field has no
// example, it composes nothing and says so, because a request example missing a
// required field is a request that fails.
func (f *fixer) exampleRequestBodies(schemas *yaml.Node) {
	paths := child(f.root, "paths")
	if paths == nil {
		return
	}
	for i := 1; i < len(paths.Content); i += 2 {
		path, item := paths.Content[i-1].Value, paths.Content[i]
		for j := 1; j < len(item.Content); j += 2 {
			verb, op := item.Content[j-1].Value, item.Content[j]
			content := child(child(op, "requestBody"), "content")
			if content == nil {
				continue
			}
			for k := 1; k < len(content.Content); k += 2 {
				media := content.Content[k]
				if child(media, "example") != nil || child(media, "examples") != nil {
					continue
				}
				schema := resolve(schemas, child(media, "schema"))
				example, complete := exampleFor(schema)
				if !complete {
					f.unexampled = append(f.unexampled,
						strings.ToUpper(verb)+" "+path)
					continue
				}
				setKey(media, "example", example)
				f.edits++
			}
		}
	}
}

// exampleFor builds an object from a schema's per-property examples. It reports
// false when a required property has none.
func exampleFor(schema *yaml.Node) (*yaml.Node, bool) {
	if schema == nil {
		return nil, false
	}
	required := map[string]bool{}
	if r := child(schema, "required"); r != nil {
		for _, n := range r.Content {
			required[n.Value] = true
		}
	}

	out := &yaml.Node{Kind: yaml.MappingNode}
	props := child(schema, "properties")
	if props == nil {
		// An empty request message. `{}` is the whole of it, and it is a
		// perfectly good worked example — several RPCs here take no arguments.
		out.Style = yaml.FlowStyle
		return out, true
	}
	for i := 1; i < len(props.Content); i += 2 {
		name, prop := props.Content[i-1].Value, props.Content[i]
		v := exampleValue(prop)
		if v == nil {
			if required[name] {
				return nil, false
			}
			continue
		}
		out.Content = append(out.Content, scalar(name), v)
	}
	if len(out.Content) == 0 {
		out.Style = yaml.FlowStyle
	}
	return out, true
}

// exampleValue reads the example a property carries, and lifts a scalar item
// example into a one-element array for a repeated field.
func exampleValue(prop *yaml.Node) *yaml.Node {
	if ex := child(prop, "example"); ex != nil {
		return copyNode(ex)
	}
	if exs := child(prop, "examples"); exs != nil && len(exs.Content) > 0 {
		return copyNode(exs.Content[0])
	}
	if items := child(prop, "items"); items != nil {
		if v := exampleValue(items); v != nil {
			return &yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{v}}
		}
	}
	return nil
}

// --- node helpers -----------------------------------------------------------

// collectSchemas reaches every schema node a client can encounter, by the same
// route internal/tools/checkopenapi walks: from components.schemas and from each
// operation's parameters, request body and responses. A blind walk cannot tell a
// field NAMED "items" from the `items` keyword.
func collectSchemas(root *yaml.Node) []*yaml.Node {
	var out []*yaml.Node
	seen := map[*yaml.Node]bool{}

	var descend func(*yaml.Node)
	descend = func(n *yaml.Node) {
		if n == nil || n.Kind != yaml.MappingNode || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)

		if props := child(n, "properties"); props != nil {
			for i := 1; i < len(props.Content); i += 2 {
				descend(props.Content[i])
			}
		}
		descend(child(n, "items"))
		descend(child(n, "not"))
		descend(child(n, "additionalProperties"))
		for _, key := range []string{"allOf", "anyOf", "oneOf", "prefixItems"} {
			if seq := child(n, key); seq != nil {
				for _, sub := range seq.Content {
					descend(sub)
				}
			}
		}
	}

	if schemas := child(child(root, "components"), "schemas"); schemas != nil {
		for i := 1; i < len(schemas.Content); i += 2 {
			descend(schemas.Content[i])
		}
	}
	paths := child(root, "paths")
	if paths == nil {
		return out
	}
	for i := 1; i < len(paths.Content); i += 2 {
		item := paths.Content[i]
		for j := 1; j < len(item.Content); j += 2 {
			op := item.Content[j]
			if params := child(op, "parameters"); params != nil {
				for _, p := range params.Content {
					descend(child(p, "schema"))
				}
			}
			descendContent(descend, child(child(op, "requestBody"), "content"))
			if responses := child(op, "responses"); responses != nil {
				for k := 1; k < len(responses.Content); k += 2 {
					descendContent(descend, child(responses.Content[k], "content"))
				}
			}
		}
	}
	return out
}

func descendContent(descend func(*yaml.Node), content *yaml.Node) {
	if content == nil {
		return
	}
	for i := 1; i < len(content.Content); i += 2 {
		descend(child(content.Content[i], "schema"))
	}
}

// resolve follows a local `$ref` into components.schemas. It does not follow a
// chain: the generator emits one level, and a loop here would need a cycle guard
// for no benefit.
func resolve(schemas, node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	ref := child(node, "$ref")
	if ref == nil {
		return node
	}
	name, ok := strings.CutPrefix(ref.Value, "#/components/schemas/")
	if !ok {
		return nil
	}
	return child(schemas, name)
}

// resolvePath finds `Name` or `Name/properties/field` under components.schemas.
func resolvePath(schemas *yaml.Node, path string) *yaml.Node {
	parts := strings.Split(path, "/")
	node := child(schemas, parts[0])
	for _, part := range parts[1:] {
		node = child(node, part)
	}
	return node
}

func child(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func setKey(n *yaml.Node, key string, val *yaml.Node) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			n.Content[i+1] = val
			return
		}
	}
	n.Content = append(n.Content, scalar(key), val)
}

// setKeyBefore inserts a key ahead of another, so `type` reads before the `enum`
// it types rather than after it.
func setKeyBefore(n *yaml.Node, key string, val *yaml.Node, before string) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == before {
			rest := append([]*yaml.Node{scalar(key), val}, n.Content[i:]...)
			n.Content = append(n.Content[:i:i], rest...)
			return
		}
	}
	setKey(n, key, val)
}

func deleteKey(n *yaml.Node, key string) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			n.Content = append(n.Content[:i:i], n.Content[i+2:]...)
			return
		}
	}
}

func mapping(key string, val *yaml.Node) *yaml.Node {
	return &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{scalar(key), val}}
}

func scalar(v string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
}

func integer(v int) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprint(v)}
}

func boolean(v bool) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: fmt.Sprint(v)}
}

func valueNode(v any) *yaml.Node {
	switch t := v.(type) {
	case int:
		return integer(t)
	case bool:
		return boolean(t)
	case []any:
		seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, e := range t {
			seq.Content = append(seq.Content, valueNode(e))
		}
		return seq
	default:
		return scalar(fmt.Sprint(t))
	}
}

func copyNode(n *yaml.Node) *yaml.Node {
	out := *n
	out.Content = nil
	for _, c := range n.Content {
		out.Content = append(out.Content, copyNode(c))
	}
	return &out
}

func valueOf(n *yaml.Node) string {
	if n == nil {
		return ""
	}
	return n.Value
}

// hasType reports whether a schema declares the given JSON type, in either of the
// two forms OpenAPI 3.1 allows — `type: string` or `type: [integer, string]`.
func hasType(s *yaml.Node, want string) bool {
	t := child(s, "type")
	if t == nil {
		return false
	}
	if t.Kind == yaml.ScalarNode {
		return t.Value == want
	}
	for _, v := range t.Content {
		if v.Value == want {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedAnyKeys(m map[string]any) []string { return sortedKeys(m) }
