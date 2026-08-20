// Command gendashboards is the source of truth for the provisioned Grafana
// dashboards.
//
// Grafana reads the generated JSON from infra/grafana/dashboards/. Edit THIS
// package and run `make dashboards`, not the JSON: the provisioner sets
// allowUiUpdates=false, so a dashboard edited in the browser is overwritten on
// the next reload and the edit is lost with no message.
//
// The output is deterministic — same input, same bytes — which is what makes a
// regeneration reviewable. A generator that reordered keys would produce a
// four-thousand-line diff in which the one changed metric name is invisible, so
// the encoder in json.go emits authored key order rather than sorted, and a
// golden test in this package fails if the committed files and a fresh
// generation disagree by a single byte.
//
// Every PromQL expression here is validated against a live Prometheus by
// internal/tools/checkdashboards — run `make dashboards-check` after changing
// one. A panel with a wrong metric name renders as "0", which reads as healthy
// when it is not.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// defaultOut is where Grafana's provisioner looks, relative to the repo root.
const defaultOut = "infra/grafana/dashboards"

func main() {
	out := flag.String("out", defaultOut, "directory to write the dashboard JSON into")
	flag.Parse()

	if err := run(os.Stdout, *out); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "gendashboards:", err)
		os.Exit(1)
	}
}

func run(w io.Writer, out string) error {
	if err := os.MkdirAll(out, 0o750); err != nil {
		return err
	}
	for _, g := range dashboards() {
		targetN = 0
		d := g.build()
		path := filepath.Join(out, g.name)
		// #nosec G306 -- provisioned dashboards are intended to be world-readable
		if err := os.WriteFile(path, encode(d), 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
		_, _ = fmt.Fprintf(w, "  wrote %-28s %2d panels\n", g.name, panelCount(d))
	}
	return nil
}

// panelCount counts everything that is not a row header.
func panelCount(d obj) int {
	panels, ok := lookup(d, "panels").(arr)
	if !ok {
		return 0
	}
	n := 0
	for _, p := range panels {
		if po, ok := p.(obj); ok && lookup(po, "type") != "row" {
			n++
		}
	}
	return n
}

// lookup returns the value of an object member, or nil when absent.
func lookup(o obj, key string) any {
	for _, m := range o {
		if m.Key == key {
			return m.Value
		}
	}
	return nil
}
