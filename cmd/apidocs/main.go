// Command apidocs serves the API contract: the REST/OpenAPI surface, the proto
// sources and the error catalogue.
//
// REST is the only PUBLISHED surface. The server still speaks gRPC and
// gRPC-Web on the same port (ADR-007) and still exposes reflection, so gRPC
// clients explore a running server or generate from the .proto sources served
// under /proto/ — but there is no second reference document to keep in step with
// the first.
//
// Everything is embedded, so the binary is self-contained and the image needs
// no volume. Assets are generated — `make api-docs` regenerates and copies
// them here — so the documentation cannot drift from the schema the server
// actually serves (CONVENTIONS §7.1).
package main

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

//go:embed assets
var assets embed.FS

func main() {
	addr := flag.String("addr", envOr("DOCS_ADDR", ":"+envOr("DOCS_PORT", "8091")), "listen address")
	flag.Parse()

	// Used only in the copy-pasteable examples on the index page.
	apiPort := envOr("API_PORT", "8090")
	docsPort := strings.TrimPrefix(*addr, ":")

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		log.Error("embedded assets unavailable", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", page(indexHTML(apiPort, docsPort)))
	mux.HandleFunc("GET /reference", page(referenceHTML()))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	spec, err := fs.ReadFile(sub, "openapi.yaml")
	if err != nil {
		log.Error("the embedded OpenAPI document is missing — run `make api-docs`", "error", err)
		os.Exit(1)
	}
	mux.HandleFunc("GET /openapi.yaml", serveSpec(withLocalServer(spec, apiPort)))

	// Serve the generated artifacts directly: the spec, the error catalogue, and
	// the proto sources under /proto/.
	mux.Handle("GET /", withContentTypes(http.FileServer(http.FS(sub))))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Info("serving api documentation", "addr", *addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listen failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	log.Info("stopped")
}

// withLocalServer puts the dev stack back at the top of `servers`.
//
// The PUBLISHED document declares https servers only, deliberately: it describes
// an API whose one credential is a bearer token, and `http://localhost:8090` sat
// at the top of that list telling every reader that the default way to call it is
// in the clear (proto/openapi.base.yaml says more).
//
// The convenience was real, though — a docs UI with no reachable server has no
// working "Try it" button — so it is restored HERE, in a binary that only ever
// runs beside a dev stack, and never written to the artefact `make api-docs`
// produces. That is the whole difference: the same YAML reaches a developer's
// browser, and nothing reaches a client, a registry or an auditor.
//
// A textual splice rather than a parse-and-re-emit. Round-tripping this document
// through a YAML library rewrites every block scalar in it — the introduction
// alone is 200 lines of Markdown — so the diff between what is published and what
// is served would stop being one entry long, and nobody could see at a glance
// that the two are otherwise the same file.
func withLocalServer(spec []byte, apiPort string) []byte {
	const anchor = "\nservers:\n"
	i := bytes.Index(spec, []byte(anchor))
	if i < 0 {
		// Serve what we have. A missing `servers:` block is a generator fault
		// that `internal/tools/checkopenapi` fails the build for; degrading the
		// docs UI a second time here would add nothing.
		return spec
	}
	local := fmt.Sprintf("  - url: http://localhost:%s\n    description: Local development (injected by cmd/apidocs; not in the published document)\n", apiPort)
	out := make([]byte, 0, len(spec)+len(local))
	out = append(out, spec[:i+len(anchor)]...)
	out = append(out, local...)
	return append(out, spec[i+len(anchor):]...)
}

func serveSpec(spec []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		_, _ = w.Write(spec)
	}
}

func page(html string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, html)
	}
}

// withContentTypes labels artifacts that Go's sniffer gets wrong, so a browser
// renders YAML and Markdown instead of downloading them.
func withContentTypes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case hasSuffix(r.URL.Path, ".yaml"), hasSuffix(r.URL.Path, ".yml"):
			w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		case hasSuffix(r.URL.Path, ".md"):
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		case hasSuffix(r.URL.Path, ".proto"):
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		case hasSuffix(r.URL.Path, ".js"):
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=86400")
		}
		next.ServeHTTP(w, r)
	})
}

func hasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
