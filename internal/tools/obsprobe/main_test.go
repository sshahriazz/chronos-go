package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// serveOn starts a test server and points the given port variable at it, so the
// command under test resolves its address exactly the way it does in production.
func serveOn(t *testing.T, env string, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(env, u.Port())
}

func TestTargets(t *testing.T) {
	serveOn(t, "PROMETHEUS_PORT", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/targets" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"data":{"activeTargets":[
		  {"health":"up","scrapeUrl":"http://valkey:9121/metrics","labels":{"job":"valkey"}},
		  {"health":"down","scrapeUrl":"http://openfga:2112/metrics","labels":{"job":"openfga"}}
		]}}`)
	})

	var out strings.Builder
	if err := targets(t.Context(), &out, false); err != nil {
		t.Fatalf("targets() = %v", err)
	}
	got := out.String()
	// Sorted by job, so openfga precedes valkey.
	if i, j := strings.Index(got, "openfga"), strings.Index(got, "valkey"); i == -1 || j == -1 || i > j {
		t.Errorf("targets are not sorted by job:\n%s", got)
	}
	if !strings.Contains(got, "down") || !strings.Contains(got, "http://openfga:2112/metrics") {
		t.Errorf("a target's health or scrape URL is missing:\n%s", got)
	}
}

// TestTargetsDownOnly pins the contract scripts/smoke.sh depends on: the
// unhealthy jobs, comma-separated, and EMPTY output when everything is up.
func TestTargetsDownOnly(t *testing.T) {
	body := `{"data":{"activeTargets":[
	  {"health":"up","labels":{"job":"valkey"}},
	  {"health":"down","labels":{"job":"openfga"}},
	  {"health":"unknown","labels":{"job":"tempo"}}
	]}}`
	serveOn(t, "PROMETHEUS_PORT", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	})

	var out strings.Builder
	if err := targets(t.Context(), &out, true); err != nil {
		t.Fatalf("targets() = %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != "openfga,tempo" {
		t.Errorf("targets(-down) = %q, want %q", got, "openfga,tempo")
	}
}

func TestTargetsDownOnlyIsSilentWhenAllAreUp(t *testing.T) {
	serveOn(t, "PROMETHEUS_PORT", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"activeTargets":[{"health":"up","labels":{"job":"valkey"}}]}}`)
	})

	var out strings.Builder
	if err := targets(t.Context(), &out, true); err != nil {
		t.Fatalf("targets() = %v", err)
	}
	// smoke.sh tests this with [ -z "$down" ]; a "(none)" line would read as a
	// failing job named "(none)".
	if out.String() != "" {
		t.Errorf("targets(-down) printed %q with every target up; want nothing", out.String())
	}
}

// TestTargetsFailsWhenPrometheusIsUnreachable pins the asymmetry between the two
// probes: this one is asked whether scraping works, so no answer is the answer.
func TestTargetsFailsWhenPrometheusIsUnreachable(t *testing.T) {
	t.Setenv("PROMETHEUS_PORT", "1") // nothing listens on port 1
	if err := targets(t.Context(), io.Discard, false); err == nil {
		t.Fatal("targets() succeeded with no Prometheus to talk to")
	}
}

func TestTraces(t *testing.T) {
	serveOn(t, "TEMPO_PORT", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"tagValues":[{"value":"chronos-api"},{"value":"openfga"}]}`)
	})

	var out strings.Builder
	if err := traces(t.Context(), &out); err != nil {
		t.Fatalf("traces() = %v", err)
	}
	if !strings.Contains(out.String(), "chronos-api") {
		t.Errorf("service names missing:\n%s", out.String())
	}
}

func TestTracesReportsAnEmptyTempoWithoutFailing(t *testing.T) {
	serveOn(t, "TEMPO_PORT", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	})

	var out strings.Builder
	if err := traces(t.Context(), &out); err != nil {
		t.Fatalf("traces() = %v", err)
	}
	if !strings.Contains(out.String(), "no traces received yet") {
		t.Errorf("an empty Tempo was not explained:\n%s", out.String())
	}
}

// TestTracesToleratesAnAbsentTempo: a stack nobody has driven traffic through
// has no traces, and saying so is this command's job — not failing the build.
func TestTracesToleratesAnAbsentTempo(t *testing.T) {
	t.Setenv("TEMPO_PORT", "1")

	var out strings.Builder
	if err := traces(t.Context(), &out); err != nil {
		t.Fatalf("traces() = %v", err)
	}
	if !strings.Contains(out.String(), "Tempo unreachable") {
		t.Errorf("an unreachable Tempo was not explained:\n%s", out.String())
	}
}

func TestStatusPrettyPrints(t *testing.T) {
	serveOn(t, "API_PORT", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q", ct)
		}
		body, _ := io.ReadAll(r.Body)
		if strings.TrimSpace(string(body)) != "{}" {
			t.Errorf("body = %q, want {}", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"SERVING","dependencies":[{"name":"postgres"}]}`)
	})

	var out strings.Builder
	if err := status(t.Context(), &out); err != nil {
		t.Fatalf("status() = %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "\n  \"status\": \"SERVING\"") {
		t.Errorf("the response was not indented:\n%s", got)
	}
}

// TestStatusSurfacesAConnectError: a Connect error is JSON too, and printing it
// is more useful than a bare status line — but it must still be a failure.
func TestStatusSurfacesAConnectError(t *testing.T) {
	serveOn(t, "API_PORT", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"code":"internal","message":"nope"}`)
	})

	var out strings.Builder
	err := status(t.Context(), &out)
	if err == nil {
		t.Fatal("status() succeeded on an HTTP 500")
	}
	if !strings.Contains(out.String(), "nope") {
		t.Errorf("the error body was not printed:\n%s", out.String())
	}
}

func TestPortFallsBackToTheCommittedDefault(t *testing.T) {
	t.Setenv("PROMETHEUS_PORT", "")
	if got := port("PROMETHEUS_PORT", "9090"); got != "9090" {
		t.Errorf("port() = %q, want the default 9090", got)
	}
	t.Setenv("PROMETHEUS_PORT", "19090")
	if got := port("PROMETHEUS_PORT", "9090"); got != "19090" {
		t.Errorf("port() = %q, want the override 19090", got)
	}
}
