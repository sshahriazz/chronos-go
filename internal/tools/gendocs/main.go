// Command gendocs renders the published error catalogue from the Go source of
// truth (CONVENTIONS §7.1), so the documentation cannot disagree with the
// server's behaviour.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/chronos/chronos-go/internal/platform/errs"
)

func main() {
	var b strings.Builder
	b.WriteString("# API Error Catalogue\n\n")
	b.WriteString("> **Generated** from `internal/platform/errs`. Do not edit.\n")
	b.WriteString("> Run `make api-docs`.\n\n")
	b.WriteString("Clients branch on `reason`, never on the HTTP status or the message.\n")
	b.WriteString("The status and Connect code are shown for transport handling only.\n\n")
	b.WriteString("| Reason | Connect code | HTTP | Retryable | Meaning | Client should |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- |\n")
	for _, d := range errs.Catalogue() {
		retry := "no"
		if d.Retryable {
			retry = "**yes**"
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | %d | %s | %s | %s |\n",
			d.Reason, d.ConnectCode, d.HTTPStatus, retry, d.Meaning, d.ClientShould)
	}
	b.WriteString(`
## The distinction that matters most

` + "`ACCESS_DENIED`" + ` and ` + "`PLAN_UPGRADE_REQUIRED`" + ` are both refusals and must never
be collapsed into a generic 403. One means *ask an admin*; the other means
*upgrade your plan*. They lead to completely different user journeys, and a
client that cannot tell them apart will send people down the wrong one.

## Why NOT_FOUND is deliberately ambiguous

` + "`NOT_FOUND`" + ` covers three cases: the resource does not exist, it exists but the
caller may not know that, and it exists but the caller is refused. This is
intentional (ADR-036) — distinguishing them across a tenant boundary would let
identifiers be probed for existence.

Inside a tenant, where the caller has already proven membership, errors *are*
specific.
`)
	const out = "docs/api/errors.md"
	// #nosec G306 -- generated documentation is intended to be world-readable
	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "gendocs:", err)
		os.Exit(1)
	}
	fmt.Printf("  wrote %s (%d reasons)\n", out, len(errs.Catalogue()))
}
