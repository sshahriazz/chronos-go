// Command checkdashboards runs every PromQL expression in every provisioned
// dashboard against a live Prometheus and reports the ones returning no data.
//
// A panel that renders nothing is worse than no panel: "0" and "wrong metric
// name" look identical on a wall display, and the second one reads as healthy.
// Grafana will not tell you which it is — the query is valid PromQL either way —
// so the only way to know is to ask Prometheus for real series. Run this after
// changing internal/tools/gendashboards.
//
// It needs the stack running (`make up`). The exit code is the number of
// expressions that returned nothing, capped so it cannot collide with a signal
// status.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/chronos/chronos-go/internal/platform/codec"
)

// maxExit keeps the count from reaching the range a shell reads as "killed by a
// signal". A hundred and twenty dead panels and two hundred are the same news.
const maxExit = 120

func main() {
	dir := flag.String("dashboards", "infra/grafana/dashboards", "directory of provisioned dashboards")
	addr := flag.String("prometheus", defaultPrometheus(), "base URL of the Prometheus to query")
	timeout := flag.Duration("timeout", 15*time.Second, "per-query timeout")
	flag.Parse()

	empty, err := run(context.Background(), os.Stdout, *dir, *addr, *timeout)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "checkdashboards:", err)
		os.Exit(1)
	}
	os.Exit(min(empty, maxExit))
}

func defaultPrometheus() string {
	port := os.Getenv("PROMETHEUS_PORT")
	if port == "" {
		port = "9090"
	}
	return "http://localhost:" + port
}

func run(ctx context.Context, out io.Writer, dir, addr string, timeout time.Duration) (int, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return 0, err
	}
	if len(files) == 0 {
		// Reporting "0 problems" over an empty set is the failure this whole
		// family of checks exists to avoid.
		return 0, fmt.Errorf("no dashboards found in %s — run `make dashboards`", dir)
	}
	sort.Strings(files)

	client := &http.Client{Timeout: timeout}
	var total, empty int

	for _, file := range files {
		_, _ = fmt.Fprintf(out, "\n%s\n", filepath.Base(file))
		raw, err := os.ReadFile(file) // #nosec G304 -- a build-time tool reading this repo's own artifacts
		if err != nil {
			return 0, err
		}
		doc, err := codec.Tolerant[map[string]any](raw)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", file, err)
		}

		for _, panel := range walk(doc["panels"]) {
			title, _ := panel["title"].(string)
			targets, _ := panel["targets"].([]any)
			for _, t := range targets {
				target, _ := t.(map[string]any)
				expr, _ := target["expr"].(string)
				// Tempo-backed panels have no Prometheus series until traces flow.
				if expr == "" {
					continue
				}
				total++
				n, qerr := promQuery(ctx, client, addr, expr)
				switch {
				case qerr != nil:
					_, _ = fmt.Fprintf(out, "  %s %s %v\n", paint(red, "ERR "), label(title), qerr)
					empty++
				case n == 0:
					_, _ = fmt.Fprintf(out, "  %s %s %s\n", paint(yellow, "NODATA"), label(title), truncate(expr, 80))
					empty++
				default:
					_, _ = fmt.Fprintf(out, "  %s   %s %d series\n", paint(green, "OK"), label(title), n)
				}
			}
		}
	}

	_, _ = fmt.Fprintf(out, "\n%d/%d expressions returning data\n", total-empty, total)
	return empty, nil
}

// walk yields every panel in a dashboard, descending into collapsed rows.
func walk(v any) []map[string]any {
	var out []map[string]any
	list, _ := v.([]any)
	for _, item := range list {
		panel, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, panel)
		out = append(out, walk(panel["panels"])...)
	}
	return out
}

// promResponse is the part of Prometheus's query envelope this tool reads.
type promResponse struct {
	Status string `json:"status"`
	Error  string `json:"error"`
	Data   struct {
		Result []any `json:"result"`
	} `json:"data"`
}

// promQuery returns the number of series an instant query produced.
func promQuery(ctx context.Context, client *http.Client, addr, expr string) (int, error) {
	u := addr + "/api/v1/query?" + url.Values{"query": {expr}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Prometheus answers a bad query with 400 AND a JSON body naming the fault,
	// which is more useful than the status line, so the body is read either way.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, err
	}
	parsed, err := codec.Tolerant[promResponse](body)
	if err != nil {
		return 0, fmt.Errorf("HTTP %d: %w", resp.StatusCode, err)
	}
	if parsed.Status != "success" {
		if parsed.Error != "" {
			return 0, errors.New(parsed.Error)
		}
		return 0, fmt.Errorf("query failed (HTTP %d)", resp.StatusCode)
	}
	return len(parsed.Data.Result), nil
}

const (
	green  = "\033[32m"
	red    = "\033[31m"
	yellow = "\033[33m"
)

func paint(code, s string) string {
	if os.Getenv("NO_COLOR") != "" {
		return s
	}
	return code + s + "\033[0m"
}

// label pads a panel title into a fixed column so the verdicts line up.
func label(title string) string {
	return fmt.Sprintf("%-44s", truncate(title, 42))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
