// Command operatorlab is a browser harness for the operator plane.
//
// # Why it exists, and why it is not part of cmd/operator
//
// Two of the three things the operator plane does can only be exercised by a
// browser: an OIDC redirect and a WebAuthn ceremony. Neither can be driven by
// curl, so without a page there is no way to prove the sign-in operator.md §3
// mandates actually works end to end — and "the RPCs return plausible errors"
// is exactly the evidence this repository has learned not to accept.
//
// It is a separate tool rather than a route in cmd/operator because that binary
// is the cross-tenant surface. A console served by it would be one more thing
// on the port that reads every customer we have, and the dev affordances a
// harness wants — no caching, permissive reloading, a page that edits and
// reloads — are the opposite of what belongs there.
//
// # The ports, and why they are this way round
//
// The harness listens on :8095 and the PLANE moves to :8096, which is the
// reverse of the obvious arrangement. Two things pin it:
//
//   - Google compares the redirect URI as a WHOLE STRING against its
//     registration, and the registered one names :8095.
//   - A WebAuthn credential is bound to the ORIGIN the ceremony ran in, so the
//     browser's origin must be what OPERATOR_WEBAUTHN_ORIGINS names.
//
// Both are properties of where the BROWSER is, not of where the server is, so
// the browser-facing port is the one that has to keep the number.
//
//	go run ./internal/tools/operatorlab
//	OPERATOR_ADDR=:8096 go run ./cmd/operator
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var (
	addr   = flag.String("addr", "localhost:8095", "address to serve the harness on")
	target = flag.String("operator", "http://localhost:8096", "the operator plane to proxy to")
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "operatorlab:", err)
		os.Exit(1)
	}
}

func run() error {
	plane, err := url.Parse(*target)
	if err != nil {
		return fmt.Errorf("parsing -operator: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(plane)
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		// Answered as JSON so the page can show it, rather than a bare 502 the
		// fetch reports as an opaque failure.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprintf(w, `{"code":"unavailable","message":%q}`,
			"the operator plane at "+plane.String()+" is not answering: "+err.Error())
	}

	mux := http.NewServeMux()

	// Google redirects the BROWSER here after consent, with the code and state
	// on the query string.
	//
	// It serves a page rather than completing the ceremony itself: the code
	// exchange needs the client secret and the PKCE verifier, and both live
	// server-side in cmd/operator. This tool holds no credentials and must not.
	//
	// The path is registered explicitly because Google compares the redirect URI
	// as a whole string. A harness that served it anywhere else produces a
	// redirect_uri_mismatch that says nothing about which side is wrong.
	mux.HandleFunc("/operator/callback", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(callbackPage))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Dispatched by PREFIX inside the root handler, NOT registered as a mux
		// pattern. `mux.Handle("/chronos.")` is an EXACT match — Go's ServeMux
		// treats a pattern as a prefix only when it ends in "/" — so registering
		// it that way silently 404s every RPC. passkeylab shipped that bug and
		// it cost an afternoon.
		if strings.HasPrefix(r.URL.Path, "/chronos.") {
			proxy.ServeHTTP(w, r)
			return
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// No caching: the whole point is to edit this page and reload.
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(page))
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	origin := "http://" + *addr
	log.Printf("operatorlab on %s, proxying RPCs to %s", origin, plane)
	log.Printf("the plane must have OPERATOR_WEBAUTHN_RP_ID=%s, %s in OPERATOR_WEBAUTHN_ORIGINS,",
		hostOf(*addr), origin)
	log.Printf("and OPERATOR_OIDC_REDIRECT_URL=%s/operator/callback registered with the provider",
		origin)

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func hostOf(addr string) string {
	if i := strings.LastIndex(addr, ":"); i > 0 {
		return addr[:i]
	}
	return addr
}
