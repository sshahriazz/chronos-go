// Command passkeylab serves a browser harness for exercising the WebAuthn RPCs
// by hand.
//
// # Why this exists
//
// A WebAuthn ceremony cannot be driven from Go. The signature comes from an
// authenticator — a laptop's secure enclave, a phone, a security key — reached
// only through a browser API, so the one thing no test in this repository can
// do is produce a real assertion. Every layer below is unit-tested and the store
// is covered against the real database; this is the part that needs a person and
// a fingerprint.
//
// # Why it PROXIES instead of just serving a file
//
// Two constraints meet here. WebAuthn requires a secure context, so the page
// must be served over http://localhost or https — a file:// page cannot call
// `navigator.credentials` at all. And the RP's declared origin must match the
// page's, so a page on :3000 calling an API on :8090 is cross-origin and needs
// CORS the API does not serve.
//
// Proxying makes the browser see ONE origin. The page and the RPCs are both
// http://localhost:3000, which is already in IDENTITY_WEBAUTHN_ORIGINS, and
// nothing about cmd/api has to change to accommodate a test harness.
//
// # It is a tool, not a product surface
//
// It ships no credentials, stores nothing, and is never wired into a binary
// that runs in production. Run it with `go run ./internal/tools/passkeylab`.
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

//nolint:gochecknoglobals // flags
var (
	addr   = flag.String("addr", "localhost:3000", "address to serve the harness on")
	target = flag.String("api", "http://localhost:8090", "the chronos API to proxy to")
	mail   = flag.String("mailpit", "http://localhost:8025", "the Mailpit to read verification links from")
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "passkeylab:", err)
		os.Exit(1)
	}
}

func run() error {
	api, err := url.Parse(*target)
	if err != nil {
		return fmt.Errorf("parsing -api: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(api)
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		// Answered as JSON so the page can show it, rather than a bare 502 the
		// fetch reports as an opaque failure.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprintf(w, `{"code":"unavailable","message":%q}`,
			"the API at "+api.String()+" is not answering: "+err.Error())
	}

	mailAPI, err := url.Parse(*mail)
	if err != nil {
		return fmt.Errorf("parsing -mailpit: %w", err)
	}
	mailProxy := httputil.NewSingleHostReverseProxy(mailAPI)
	mailProxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, err error) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprintf(w, `{"message":%q}`,
			"Mailpit at "+mailAPI.String()+" is not answering: "+err.Error())
	}

	mux := http.NewServeMux()

	// Mailpit, proxied for the same reason the API is: one origin.
	//
	// # Why the harness reads mail at all
	//
	// Creating an account needs the verification token, and there is deliberately
	// no RPC that hands one out — identity.md §12 is explicit that only the
	// mailbox holder may complete a verification. So the harness does what a
	// person does: it reads the mailbox. Mailpit IS the dev mailbox, and reading
	// it is the honest way to get the token rather than minting one out of band.
	//
	// It follows that cmd/worker must be running: the verification mail is sent
	// by a reactor, not by the API, so without the worker no message ever
	// arrives and the page says so.
	mux.Handle("/mailpit/", http.StripPrefix("/mailpit", mailProxy))

	// Everything Connect serves lives under the fully-qualified service name, so
	// one prefix covers every RPC and nothing else is forwarded.
	//
	// Dispatched by PREFIX inside the root handler rather than registered as a
	// mux pattern, and the distinction is not stylistic: `mux.Handle("/chronos.")`
	// is an EXACT match, because Go's ServeMux only treats a pattern as a prefix
	// when it ends in "/". Registering it that way silently 404s every RPC —
	// which is what this harness did until a signup smoke test asked for one.
	//
	// The service names carry a dot and cannot end in "/", so a prefix check here
	// is the honest way to express "everything Connect serves".
	// The federated callback. Google redirects the BROWSER here after consent,
	// with the code and state on the query string.
	//
	// It serves a page rather than completing the ceremony itself, and the
	// difference matters: this tool holds no credentials and must not — the code
	// exchange needs the client secret and the PKCE verifier, both of which live
	// server-side in cmd/api. So the page reads the query string and posts it to
	// FinishFederatedSignIn or FinishFederatedLink through the same proxy
	// everything else uses.
	//
	// The path is registered because Google compares the redirect URI as a WHOLE
	// STRING against its registration. A harness that served it anywhere else
	// would produce a redirect_uri_mismatch that says nothing about which side
	// is wrong.
	mux.HandleFunc("/federated/callback", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(callbackPage))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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
		// context.WithoutCancel, not a fresh Background: the shutdown must
		// OUTLIVE the signal that triggered it — a context already cancelled
		// would make Shutdown return immediately and drop the connection it was
		// meant to drain — while still carrying whatever the parent held.
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	origin := "http://" + *addr
	log.Printf("passkeylab on %s, proxying RPCs to %s", origin, api)
	log.Printf("the server must have IDENTITY_WEBAUTHN_RP_ID=%s and %s in "+
		"IDENTITY_WEBAUTHN_ORIGINS", hostOf(*addr), origin)

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// hostOf strips the port, which is what an RP id is: a registrable domain with
// no scheme and no port.
func hostOf(a string) string {
	if h, _, ok := strings.Cut(a, ":"); ok {
		return h
	}
	return a
}
