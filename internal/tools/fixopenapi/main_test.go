package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const specPath = "../../../docs/api/chronos-openapi.yaml"

// copyOfPublished writes the committed document to a temporary file, so a test
// can run the fixer over the real thing without editing the repository.
func copyOfPublished(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("reading the published spec: %v", err)
	}
	path := filepath.Join(t.TempDir(), "openapi.yaml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	return path
}

// TestFixingIsIdempotent is the property `make api-docs` depends on.
//
// The tool runs on every documentation build, over a file the previous build
// already normalised. If a rule were not idempotent — hoisting an `allOf` into
// another `allOf`, appending a second `pattern` — the document would grow on
// every build and the diff would be noise nobody reads. So: fix the committed
// document, fix it again, and require the second pass to change nothing.
func TestFixingIsIdempotent(t *testing.T) {
	t.Parallel()

	path := copyOfPublished(t)

	if _, err := fixFile(path, io.Discard, true); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading after the first pass: %v", err)
	}

	edits, err := fixFile(path, io.Discard, true)
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading after the second pass: %v", err)
	}

	if edits != 0 {
		t.Errorf("the second pass made %d edits; the tool is not idempotent", edits)
	}
	if string(first) != string(second) {
		t.Error("the second pass changed the document; the tool is not idempotent")
	}
}

// TestTheCommittedDocumentIsAlreadyFixed asserts that what is in git is what the
// pipeline produces.
//
// `make api-docs` runs the fixer, so a committed document that still needs edits
// means somebody generated it another way — and the next person's build produces
// a diff they did not make.
func TestTheCommittedDocumentIsAlreadyFixed(t *testing.T) {
	t.Parallel()

	edits, err := fixFile(copyOfPublished(t), io.Discard, true)
	if err != nil {
		t.Fatalf("fixing the committed document: %v", err)
	}
	if edits != 0 {
		t.Errorf("the committed document needs %d edits — run `make api-docs` and commit the result",
			edits)
	}
}

// TestRulesApplyToASyntheticDocument drives each rule from a document small
// enough to read, so a failure names the rule rather than a line number in a
// 6,000-line artifact.
func TestRulesApplyToASyntheticDocument(t *testing.T) {
	t.Parallel()

	const in = `
openapi: 3.1.0
paths:
  /Thing/Do:
    post:
      parameters:
        - name: encoding
          in: query
          schema:
            $ref: '#/components/schemas/encoding'
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/DoRequest'
      responses:
        "200":
          description: ok
      security:
        - {}
components:
  schemas:
    encoding:
      enum:
        - json
        - proto
    DoRequest:
      type: object
      properties:
        name:
          type: string
          maxLength: 8
          pattern: ^x$
          examples:
            - alice
        size:
          type:
            - integer
            - string
          format: int64
          maximum: 100
        kind:
          $ref: '#/components/schemas/Kind'
          title: kind
          description: which kind
    Kind:
      type: string
      enum:
        - A
`

	path := filepath.Join(t.TempDir(), "openapi.yaml")
	if err := os.WriteFile(path, []byte(in), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	if _, err := fixFile(path, io.Discard, true); err != nil {
		t.Fatalf("fixing: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the result: %v", err)
	}
	var out map[string]any
	if err := yaml.Unmarshal(raw, &out); err != nil {
		t.Fatalf("the result is not parseable YAML: %v\n%s", err, raw)
	}

	schemas := out["components"].(map[string]any)["schemas"].(map[string]any)
	req := schemas["DoRequest"].(map[string]any)
	props := req["properties"].(map[string]any)

	t.Run("a bare enum is typed", func(t *testing.T) {
		if got := schemas["encoding"].(map[string]any)["type"]; got != "string" {
			t.Errorf("encoding.type = %v, want string", got)
		}
	})

	t.Run("an object is closed", func(t *testing.T) {
		if got := req["additionalProperties"]; got != false {
			t.Errorf("DoRequest.additionalProperties = %v, want false", got)
		}
	})

	t.Run("a dual-typed int64 becomes one branch per spelling", func(t *testing.T) {
		size := props["size"].(map[string]any)
		if _, still := size["type"]; still {
			t.Error("size still declares a two-element type")
		}
		branches, ok := size["oneOf"].([]any)
		if !ok || len(branches) != 2 {
			t.Fatalf("size.oneOf = %v", size["oneOf"])
		}

		number := branches[0].(map[string]any)
		if number["type"] != "integer" || number["format"] != "int64" {
			t.Errorf("the number branch is %v; format must travel with the type it describes",
				number)
		}
		if number["maximum"] != 100 {
			t.Errorf("the number branch lost its ceiling: %v", number)
		}

		text := branches[1].(map[string]any)
		if text["type"] != "string" || text["pattern"] != `^-?[0-9]+$` || text["maxLength"] != 20 {
			t.Errorf("the string branch is %v; it must carry the JSON spelling of an integer",
				text)
		}
		if _, leaked := text["format"]; leaked {
			t.Error("the string branch carries a numeric format")
		}
	})

	t.Run("annotations beside a $ref are hoisted into allOf", func(t *testing.T) {
		kind := props["kind"].(map[string]any)
		if _, still := kind["$ref"]; still {
			t.Error("kind still carries an inline $ref")
		}
		all, ok := kind["allOf"].([]any)
		if !ok || len(all) != 1 {
			t.Fatalf("kind.allOf = %v", kind["allOf"])
		}
		if got := all[0].(map[string]any)["$ref"]; got != "#/components/schemas/Kind" {
			t.Errorf("the hoisted reference is %v", got)
		}
		if kind["title"] != "kind" || kind["description"] != "which kind" {
			t.Error("the annotations did not survive the hoist")
		}
	})

	t.Run("an open security requirement becomes an empty array", func(t *testing.T) {
		post := out["paths"].(map[string]any)["/Thing/Do"].(map[string]any)["post"].(map[string]any)
		sec, ok := post["security"].([]any)
		if !ok {
			t.Fatalf("security = %v (%T), want an empty array", post["security"], post["security"])
		}
		if len(sec) != 0 {
			t.Errorf("security = %v; `[]` is the specification's spelling for \"no credentials\", "+
				"and `[{}]` is what every auditor reads as a deleted scheme", sec)
		}
	})

	t.Run("a protocol parameter gets its example", func(t *testing.T) {
		params := out["paths"].(map[string]any)["/Thing/Do"].(map[string]any)["post"].(map[string]any)["parameters"].([]any)
		if got := params[0].(map[string]any)["example"]; got != "json" {
			t.Errorf("the encoding parameter's example is %v, want json", got)
		}
	})

	t.Run("a request body example is assembled from field examples", func(t *testing.T) {
		media := out["paths"].(map[string]any)["/Thing/Do"].(map[string]any)["post"].(map[string]any)["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)
		example, ok := media["example"].(map[string]any)
		if !ok {
			t.Fatalf("no example was assembled: %v", media["example"])
		}
		if example["name"] != "alice" {
			t.Errorf("the assembled example is %v; `name` should carry the field's own example", example)
		}
		if _, invented := example["size"]; invented {
			t.Error("the fixer invented a value for `size`, which declares no example")
		}
	})
}

// TestARequiredFieldWithNoExampleIsReportedNotInvented pins the restraint that
// makes the assembled examples trustworthy.
//
// A worked example missing a required field is an example that fails when a
// reader pastes it, and a fabricated value for a required field is worse: it
// looks right. So the tool composes nothing and says which operation needs an
// annotation in the .proto.
func TestARequiredFieldWithNoExampleIsReportedNotInvented(t *testing.T) {
	t.Parallel()

	const in = `
openapi: 3.1.0
paths:
  /Thing/Do:
    post:
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/DoRequest'
      responses:
        "200":
          description: ok
components:
  schemas:
    DoRequest:
      type: object
      required:
        - token
      properties:
        token:
          type: string
`

	path := filepath.Join(t.TempDir(), "openapi.yaml")
	if err := os.WriteFile(path, []byte(in), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	var report strings.Builder
	if _, err := fixFile(path, &report, false); err != nil {
		t.Fatalf("fixing: %v", err)
	}

	raw, _ := os.ReadFile(path) //nolint:errcheck // written by fixFile above
	var out map[string]any
	if err := yaml.Unmarshal(raw, &out); err != nil {
		t.Fatalf("the result is not parseable YAML: %v", err)
	}
	media := out["paths"].(map[string]any)["/Thing/Do"].(map[string]any)["post"].(map[string]any)["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)
	if _, invented := media["example"]; invented {
		t.Errorf("an example was invented for a required field with none: %v", media["example"])
	}
	if !strings.Contains(report.String(), "POST /Thing/Do") {
		t.Errorf("the missing example was not reported:\n%s", report.String())
	}
}

// TestAMapIsNotClosed keeps the closure rule off protobuf maps.
//
// A `map<string, string>` renders as an object whose `additionalProperties` IS
// the value schema. Overwriting that with `false` publishes a map that can hold
// nothing — and it would look like a tightening rather than a break.
func TestAMapIsNotClosed(t *testing.T) {
	t.Parallel()

	const in = `
openapi: 3.1.0
paths: {}
components:
  schemas:
    Holder:
      type: object
      properties:
        metadata:
          type: object
          additionalProperties:
            type: string
            maxLength: 8
`

	path := filepath.Join(t.TempDir(), "openapi.yaml")
	if err := os.WriteFile(path, []byte(in), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	if _, err := fixFile(path, io.Discard, true); err != nil {
		t.Fatalf("fixing: %v", err)
	}

	raw, _ := os.ReadFile(path) //nolint:errcheck // written by fixFile above
	var out map[string]any
	if err := yaml.Unmarshal(raw, &out); err != nil {
		t.Fatalf("the result is not parseable YAML: %v", err)
	}
	metadata := out["components"].(map[string]any)["schemas"].(map[string]any)["Holder"].(map[string]any)["properties"].(map[string]any)["metadata"].(map[string]any)
	if _, stillASchema := metadata["additionalProperties"].(map[string]any); !stillASchema {
		t.Fatalf("the map's value schema was replaced by %v; it can now hold nothing",
			metadata["additionalProperties"])
	}
}

// TestAContradictoryEnumBesideAConstIsLeftAlone pins the one case the const rule
// must not touch.
//
// Dropping an enum that REPEATS a const removes a duplicate. Dropping one that
// disagrees with it removes evidence of a contradiction, and this tool is not
// where a contradiction gets resolved.
func TestAContradictoryEnumBesideAConstIsLeftAlone(t *testing.T) {
	t.Parallel()

	const in = `
openapi: 3.1.0
paths: {}
components:
  schemas:
    Version:
      type: integer
      const: 1
      enum:
        - 1
        - 2
`

	path := filepath.Join(t.TempDir(), "openapi.yaml")
	if err := os.WriteFile(path, []byte(in), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	if _, err := fixFile(path, io.Discard, true); err != nil {
		t.Fatalf("fixing: %v", err)
	}

	raw, _ := os.ReadFile(path) //nolint:errcheck // written by fixFile above
	var out map[string]any
	if err := yaml.Unmarshal(raw, &out); err != nil {
		t.Fatalf("the result is not parseable YAML: %v", err)
	}
	version := out["components"].(map[string]any)["schemas"].(map[string]any)["Version"].(map[string]any)
	if _, kept := version["enum"]; !kept {
		t.Error("an enum that disagrees with its const was silently dropped")
	}
}

// TestAStaleProtocolBoundIsReported checks the exemption table in the direction
// nobody remembers to check.
//
// An entry naming a schema the document no longer publishes is a bound that
// applies to nothing, and it will sit there looking like coverage. The same
// two-way check guards `intentionallyUnreferenced` in checkopenapi, for the same
// reason.
func TestAStaleProtocolBoundIsReported(t *testing.T) {
	t.Parallel()

	const in = `
openapi: 3.1.0
paths: {}
components:
  schemas:
    Something:
      type: string
      maxLength: 4
      pattern: ^a$
`

	path := filepath.Join(t.TempDir(), "openapi.yaml")
	if err := os.WriteFile(path, []byte(in), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	var report strings.Builder
	if _, err := fixFile(path, &report, false); err != nil {
		t.Fatalf("fixing: %v", err)
	}
	// Every entry in the table names a schema this fixture does not publish, so
	// each one must be reported. Checking one is enough to prove the direction
	// is checked at all.
	if !strings.Contains(report.String(), "google.protobuf.Timestamp") {
		t.Errorf("a protocolBounds entry matching nothing was not reported:\n%s", report.String())
	}
}

// The `base64` query parameter is published as the protocol actually reads it.
//
// # The defect this exists to prevent, which shipped
//
// protoc-gen-connect-openapi types this parameter `boolean`. The Connect
// protocol has no boolean there. connect-go v1.20.0 decides whether to decode
// with a strict string comparison:
//
//	msgReader := queryValueReader(msg, query.Get(connectUnaryBase64QueryParameter) == "1")
//
// and its own client only ever writes "1". So `true` does not mean on — it
// falls through the comparison and means OFF, which is the worst available
// outcome: a client generated from a `boolean` schema sends `base64=true`, the
// server treats the still-encoded payload as literal JSON, and the error names
// the payload rather than the flag. Confirmed against the running server:
//
//	GET /chronos.system.v1.SystemService/GetStatus?message=e30&base64=true
//	  400 unmarshal message: proto: syntax error (line 1:1): invalid value e30
//	GET /chronos.system.v1.SystemService/GetStatus?message=e30&base64=1
//	  200
//
// The published example was `false`, which is a value that has no meaning to the
// server either — it is off only by accident of not being "1".
//
// This asserts the published shape rather than the tables that produce it,
// because a table entry that stops resolving is reported and skipped, and a
// report nobody reads is how the boolean would come back.
func TestTheBase64ParameterIsNotPublishedAsABoolean(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("reading the published spec: %v", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing the published spec: %v", err)
	}

	schema := resolvePath(child(doc.Content[0], "components"), "schemas/base64")
	if schema == nil {
		t.Fatal("the document does not publish a `base64` schema; if the parameter was " +
			"removed, delete this test, and if it was renamed, follow it")
	}

	if got := valueOf(child(schema, "type")); got != "string" {
		t.Errorf("`base64` is published as %q; the protocol compares it against the string "+
			"\"1\", so a client generated from this sends a value the server reads as off", got)
	}

	enum := child(schema, "enum")
	if enum == nil {
		t.Fatal("`base64` publishes no enum; the one accepted value is what a client author " +
			"needs and is the whole content of this parameter")
	}
	var values []string
	for _, v := range enum.Content {
		values = append(values, v.Value)
	}
	if len(values) != 1 || values[0] != "1" {
		t.Errorf("`base64` publishes enum %v; connect-go accepts exactly \"1\" and treats "+
			"every other value, `true` included, as not-encoded", values)
	}
}
