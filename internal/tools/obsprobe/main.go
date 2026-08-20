// Command obsprobe asks the running stack three questions that used to be
// answered by piping curl into an inline Python one-liner.
//
//	obsprobe targets   Prometheus scrape target health, one line per job
//	obsprobe traces     services currently reporting spans to Tempo
//	obsprobe status     the API's own GetStatus response, pretty-printed
//
// All three read a JSON API and print a few lines. Shell alone cannot do that
// without a JSON parser, and adding `jq` would trade one external runtime for
// another — so they live here, where the only requirement is the Go toolchain
// the rest of the build already needs.
//
// # Reachability is reported, not swallowed
//
// `targets` fails when Prometheus cannot be reached: it is asked precisely to
// find out whether scraping works, and "no answer" is the most important answer
// it has. `traces` does not, because an empty Tempo is the normal state of a
// stack nobody has driven traffic through yet, and telling a developer their
// build is broken because they have not made a request would train them to
// ignore it.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/chronos/chronos-go/internal/platform/codec"
)

func main() {
	timeout := flag.Duration("timeout", 10*time.Second, "per-request timeout")
	downOnly := flag.Bool("down", false, "targets: print only the jobs that are NOT up, comma-separated")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 1 {
		usage()
		os.Exit(2) // usage error, per the Unix convention
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	var err error
	switch cmd := flag.Arg(0); cmd {
	case "targets":
		err = targets(ctx, os.Stdout, *downOnly)
	case "traces":
		err = traces(ctx, os.Stdout)
	case "status":
		err = status(ctx, os.Stdout)
	default:
		_, _ = fmt.Fprintf(os.Stderr, "obsprobe: unknown command %q\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "obsprobe:", err)
		os.Exit(1)
	}
}

func usage() {
	_, _ = fmt.Fprint(os.Stderr, `usage: obsprobe [flags] <targets|traces|status>

  targets   Prometheus scrape target health (-down: just the unhealthy jobs)
  traces    services currently reporting traces to Tempo
  status    the API's GetStatus response, pretty-printed

flags:
`)
	flag.PrintDefaults()
}

// port reads a compose port override, falling back to the committed default.
// The Makefile resolved these with ${VAR:-default}; doing it here keeps the
// recipe to one line.
func port(env, fallback string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	return fallback
}

// --- targets ----------------------------------------------------------------

type targetsResponse struct {
	Data struct {
		ActiveTargets []struct {
			Health    string            `json:"health"`
			ScrapeURL string            `json:"scrapeUrl"`
			Labels    map[string]string `json:"labels"`
		} `json:"activeTargets"`
	} `json:"data"`
}

// targets prints one line per scrape target, sorted by job.
//
// With downOnly it prints instead the comma-separated jobs that are NOT up, and
// nothing at all when every target is healthy — the shape `scripts/smoke.sh`
// tests with `[ -z "$down" ]`. Correlating a target's health with its job label
// is why this is a program and not a grep: the two live in different parts of
// the same JSON object, and no line-oriented tool can pair them.
func targets(ctx context.Context, out io.Writer, downOnly bool) error {
	addr := "http://localhost:" + port("PROMETHEUS_PORT", "9090") + "/api/v1/targets"
	body, err := get(ctx, addr)
	if err != nil {
		return fmt.Errorf("cannot reach Prometheus on %s: %w", addr, err)
	}
	parsed, err := codec.Tolerant[targetsResponse](body)
	if err != nil {
		return err
	}

	active := parsed.Data.ActiveTargets
	sort.Slice(active, func(i, j int) bool {
		return active[i].Labels["job"] < active[j].Labels["job"]
	})

	if downOnly {
		var down []string
		for _, t := range active {
			if t.Health != "up" {
				down = append(down, t.Labels["job"])
			}
		}
		if len(down) > 0 {
			_, _ = fmt.Fprintln(out, strings.Join(down, ","))
		}
		return nil
	}

	if len(active) == 0 {
		_, _ = fmt.Fprintln(out, "  (Prometheus has no active scrape targets)")
		return nil
	}
	for _, t := range active {
		_, _ = fmt.Fprintf(out, "  %-8s %-20s %s\n", t.Health, t.Labels["job"], t.ScrapeURL)
	}
	return nil
}

// --- traces -----------------------------------------------------------------

type tagValuesResponse struct {
	TagValues []struct {
		Value string `json:"value"`
	} `json:"tagValues"`
}

func traces(ctx context.Context, out io.Writer) error {
	p := port("TEMPO_PORT", "3200")
	addr := "http://localhost:" + p + "/api/v2/search/tag/.service.name/values"
	body, err := get(ctx, addr)
	if err != nil {
		// Not an error, deliberately: a stack that has served no request has no
		// traces, and this command is how you find that out. Failing here would
		// mean `make traces` reports a broken build to anyone who has not yet
		// made a request — which is how a command gets ignored.
		_, _ = fmt.Fprintf(out, "  (Tempo unreachable on %s)\n", p)
		return nil //nolint:nilerr // an absent Tempo is this command's answer, not its failure
	}
	parsed, err := codec.Tolerant[tagValuesResponse](body)
	if err != nil {
		return err
	}
	if len(parsed.TagValues) == 0 {
		_, _ = fmt.Fprintln(out, "  (no traces received yet)")
		return nil
	}
	names := make([]string, 0, len(parsed.TagValues))
	for _, v := range parsed.TagValues {
		names = append(names, v.Value)
	}
	sort.Strings(names)
	for _, n := range names {
		_, _ = fmt.Fprintln(out, "  "+n)
	}
	return nil
}

// --- status -----------------------------------------------------------------

// status calls the SystemService over HTTP/JSON — the same one port that serves
// gRPC (ADR-007) — and prints the response indented.
func status(ctx context.Context, out io.Writer) error {
	addr := "http://localhost:" + port("API_PORT", "8090") +
		"/chronos.system.v1.SystemService/GetStatus"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr, strings.NewReader("{}"))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("the API is unreachable on %s: %w", addr, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	// A Connect error is JSON too, and printing it is more useful than a status
	// line, so the body is rendered whatever the code was.
	pretty, err := codec.Indent(body, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintf(out, "HTTP %d (response is not JSON):\n%s\n", resp.StatusCode, body)
		return nil
	}
	_, _ = fmt.Fprintln(out, string(pretty))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the API answered HTTP %d", resp.StatusCode)
	}
	return nil
}

// --- transport --------------------------------------------------------------

func get(ctx context.Context, addr string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("HTTP " + resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}
