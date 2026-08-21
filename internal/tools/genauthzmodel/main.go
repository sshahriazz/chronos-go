// Command genauthzmodel renders the authorization model from the fragments the
// modules declare, and can check that the rendered file has not fallen behind.
//
// # Why the model is a checked-in artifact at all
//
// The deployed model is built from Go values, so nothing needs a file to run.
// The file exists for the review: access.md §10 calls a model change "the
// highest-blast-radius deploy in the system", and a reviewer cannot judge one
// from a diff of Go struct literals spread across several modules. The rendered
// artifact is one document, in OpenFGA's own DSL, and its diff shows exactly
// what a deploy would change.
//
// # What -check buys
//
// Fragments live with their modules; the artifact lives here. Two copies of one
// fact drift, and this drift is silent in the worst direction — the file that
// gets reviewed stops describing the model that gets deployed. `-check` fails
// the build when they disagree, which is the same guard `make api` puts on the
// OpenAPI document.
//
// It does NOT check the artifact against the model deployed to a live OpenFGA
// store. That is a different question — drift between the tree and the server —
// and belongs with reconciliation (access.md §11).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/chronos/chronos-go/internal/authzmodel"
)

const header = `# Authorization model — GENERATED, do not edit.
#
# Assembled from the fragments each module declares. Run ` + "`make authz-model`" + `.
# The deployed model is built from those fragments, never parsed from this file;
# this is the artifact a reviewer reads before a model deploy.
#
# Deploy ordering is not negotiable (access.md §10):
#   1. deploy the model      (additive only)
#   2. deploy code pinning the new model id
#   3. deploy code writing the new tuples
`

func main() {
	out := flag.String("out", "docs/access/authorization-model.fga", "where to write the model")
	check := flag.Bool("check", false, "fail if the file on disk differs from the fragments")
	flag.Parse()

	model, err := authzmodel.Assemble()
	if err != nil {
		fmt.Fprintf(os.Stderr, "genauthzmodel: %v\n", err)
		os.Exit(1)
	}
	rendered := header + "\n" + model.String()

	if *check {
		onDisk, err := os.ReadFile(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "genauthzmodel: cannot read %s: %v\n"+
				"  The authorization model is generated. Run `make authz-model`.\n", *out, err)
			os.Exit(1)
		}
		if string(onDisk) != rendered {
			fmt.Fprintf(os.Stderr,
				"genauthzmodel: %s is STALE — a module's fragment changed and the reviewed\n"+
					"artifact did not. The file a reviewer reads before a model deploy no longer\n"+
					"describes the model that would be deployed.\n\n"+
					"  Run `make authz-model` and commit the result.\n\n"+
					"--- fragments would render ---\n%s\n"+
					"--- %s holds ---\n%s\n",
				*out, rendered, *out, string(onDisk))
			os.Exit(1)
		}
		fmt.Printf("  OK    %s matches the module fragments (%s)\n", *out, plural(len(model.Types)))
		return
	}

	if err := os.MkdirAll(filepath.Dir(*out), 0o750); err != nil {
		fmt.Fprintf(os.Stderr, "genauthzmodel: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, []byte(rendered), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "genauthzmodel: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  wrote %s (%s)\n", *out, plural(len(model.Types)))
}

func plural(n int) string {
	if n == 1 {
		return "1 type"
	}
	return fmt.Sprintf("%d types", n)
}
