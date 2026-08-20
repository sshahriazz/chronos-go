// Command checkopenapi validates the generated OpenAPI spec, and cross-checks it
// against the .proto sources it is generated from.
//
// It exists because a generator misconfiguration once produced a spec with
// `paths: {}` — structurally valid YAML, completely useless, and silent. A
// published API document that is quietly empty is worse than none, because
// consumers trust it.
//
// # A gate that cannot run has not been satisfied
//
// This tool's predecessor was a Python script that called `sys.exit(0)` when
// PyYAML was missing. PyYAML was missing everywhere, CI included, so the gate
// passed by doing nothing for its entire life. Nothing here may skip: the YAML
// parser and the protobuf descriptors are compiled in, an unreadable or
// unparseable spec is a failure rather than a shrug, and finding zero RPCs is a
// failure too — an empty comparison satisfies every rule and proves nothing.
//
// Exits non-zero on any problem.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"go.yaml.in/yaml/v3"
)

func main() {
	spec := flag.String("spec", "docs/api/chronos-openapi.yaml", "the generated OpenAPI document")
	protoDir := flag.String("proto", "proto/chronos", "the .proto sources the document is generated from")
	noColor := flag.Bool("no-color", false, "never colourize the report")
	flag.Parse()

	if err := run(os.Stdout, *spec, *protoDir, useColor(*noColor)); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "checkopenapi:", err)
		os.Exit(1)
	}
}

// errProblems is returned when the document is readable but wrong. The report
// has already been printed; main only needs the exit code.
var errProblems = errors.New("the published API document does not satisfy its contract (see above)")

func run(out io.Writer, specPath, protoDir string, color bool) error {
	raw, err := os.ReadFile(specPath) // #nosec G304 -- a build-time tool reading this repo's own artifacts
	if err != nil {
		return fmt.Errorf("cannot read %s — run `make api-docs`: %w", specPath, err)
	}

	var spec map[string]any
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		return fmt.Errorf("%s is not parseable YAML: %w", specPath, err)
	}
	if len(spec) == 0 {
		return fmt.Errorf("%s decoded to nothing; an empty document is not a valid spec", specPath)
	}

	r := &reporter{out: out, color: color}

	declared := routes()
	found, problems := crossCheckAgainstSources(protoDir, declared)
	r.problems = append(r.problems, problems...)
	r.check(len(problems) == 0, fmt.Sprintf(
		"the descriptor registry covers every RPC in %s (%d found in the sources)", protoDir, found))
	r.check(found > 0, fmt.Sprintf("the .proto sources under %s were read", protoDir))

	validate(r, spec, declared)

	_, _ = fmt.Fprintln(out)
	if len(r.problems) > 0 {
		_, _ = fmt.Fprintf(out, "%s\n", r.paint(red, fmt.Sprintf("%d problem(s)", len(r.problems))))
		for _, p := range r.problems {
			_, _ = fmt.Fprintf(out, "  - %s\n", p)
		}
		return errProblems
	}
	_, _ = fmt.Fprintf(out, "%s\n", r.paint(green, "spec is valid and non-empty"))
	return nil
}

// useColor keeps ANSI out of a pipe and honours NO_COLOR.
func useColor(disabled bool) bool {
	if disabled || os.Getenv("NO_COLOR") != "" {
		return false
	}
	info, err := os.Stdout.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
