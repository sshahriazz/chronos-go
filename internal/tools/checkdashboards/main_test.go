package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWalkDescendsIntoCollapsedRows(t *testing.T) {
	t.Parallel()

	// A collapsed row carries its children in its own "panels" array, so a
	// flat scan would silently skip every query inside one.
	doc := []any{
		map[string]any{"title": "top"},
		map[string]any{"title": "row", "panels": []any{
			map[string]any{"title": "nested"},
			map[string]any{"title": "row2", "panels": []any{
				map[string]any{"title": "deep"},
			}},
		}},
		"not a panel",
	}

	var titles []string
	for _, p := range walk(doc) {
		titles = append(titles, p["title"].(string))
	}
	want := []string{"top", "row", "nested", "row2", "deep"}
	if strings.Join(titles, ",") != strings.Join(want, ",") {
		t.Errorf("walk() = %v, want %v", titles, want)
	}
}

func TestPromQuery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		status  int
		body    string
		want    int
		wantErr string
	}{
		{
			name:   "two series",
			status: http.StatusOK,
			body:   `{"status":"success","data":{"resultType":"vector","result":[{},{}]}}`,
			want:   2,
		},
		{
			// The case the whole tool exists for: valid PromQL, no such metric.
			name:   "no series",
			status: http.StatusOK,
			body:   `{"status":"success","data":{"resultType":"vector","result":[]}}`,
			want:   0,
		},
		{
			name:    "prometheus rejects the query",
			status:  http.StatusBadRequest,
			body:    `{"status":"error","errorType":"bad_data","error":"parse error: unexpected ]"}`,
			wantErr: "parse error",
		},
		{
			name:    "a failure with no explanation still fails",
			status:  http.StatusBadRequest,
			body:    `{"status":"error"}`,
			wantErr: "query failed",
		},
		{
			name:    "a non-JSON body is not silently a pass",
			status:  http.StatusBadGateway,
			body:    `<html>502</html>`,
			wantErr: "HTTP 502",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.URL.Query().Get("query"); got != "up" {
					t.Errorf("query = %q, want %q", got, "up")
				}
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer srv.Close()

			got, err := promQuery(t.Context(), srv.Client(), srv.URL, "up")
			switch {
			case tt.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("promQuery() error = %v, want it to mention %q", err, tt.wantErr)
				}
			case err != nil:
				t.Errorf("promQuery() = %v", err)
			case got != tt.want:
				t.Errorf("promQuery() = %d series, want %d", got, tt.want)
			}
		})
	}
}

func TestRunCountsEmptyExpressions(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// One metric exists; the other is the typo this tool hunts.
		if r.URL.Query().Get("query") == "real_metric" {
			_, _ = io.WriteString(w, `{"status":"success","data":{"result":[{}]}}`)
			return
		}
		_, _ = io.WriteString(w, `{"status":"success","data":{"result":[]}}`)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dashboard := `{"panels":[
	  {"type":"row","title":"r","panels":[
	    {"type":"timeseries","title":"nested","targets":[{"expr":"typo_metric"}]}
	  ]},
	  {"type":"timeseries","title":"good","targets":[{"expr":"real_metric"}]},
	  {"type":"text","title":"prose","targets":[{"expr":""}]}
	]}`
	if err := os.WriteFile(filepath.Join(dir, "d.json"), []byte(dashboard), 0o600); err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	empty, err := run(t.Context(), &out, dir, srv.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("run() = %v", err)
	}
	if empty != 1 {
		t.Errorf("run() reported %d empty expressions, want 1", empty)
	}
	if !strings.Contains(out.String(), "1/2 expressions returning data") {
		t.Errorf("summary missing or wrong:\n%s", out.String())
	}
	// A panel with no expression is skipped, not counted as a failure.
	if strings.Contains(out.String(), "prose") {
		t.Error("a panel with an empty expr was queried")
	}
}

func TestRunFailsOnAnEmptyDashboardDirectory(t *testing.T) {
	t.Parallel()

	// Zero dashboards checked cleanly is the same lie as a gate that never ran.
	_, err := run(context.Background(), io.Discard, t.TempDir(), "http://127.0.0.1:1", time.Second)
	if err == nil {
		t.Fatal("run() succeeded over no dashboards at all")
	}
	if !strings.Contains(err.Error(), "no dashboards found") {
		t.Errorf("run() = %v, want it to say no dashboards were found", err)
	}
}
