// Command oidcsubject prints the provider subject for whoever signs in.
//
// # Why this is needed at all
//
// `provisionoperator` matches on the IdP's IMMUTABLE SUBJECT, never on an
// address — identity.md §7 rule 5, applied to the operator plane for the same
// reason: an identifier that can change is not an identity, and matching on the
// address is the takeover the rule exists to prevent.
//
// That leaves a bootstrap gap. In a Workspace the subject is visible in the
// admin console, so an administrator provisioning a colleague reads it there.
// For a personal account, or for a developer setting this up on a laptop, there
// is nowhere to read it from — and the operator plane will not tell you.
//
// It refuses to tell you on purpose. `CompleteSignIn` answers an unknown
// operator and a disabled one with the same error and logs the ISSUER without
// the subject, because that branch is what somebody probing would hit
// repeatedly and a log line naming them would be a record of failed sign-ins by
// people who are not our staff. So the plane cannot be the thing that closes
// this gap.
//
// # Why this closes it safely
//
// The subject is disclosed to the person who just proved they hold the account,
// and to nobody else. It runs the same PKCE ceremony the plane does, against
// the same configured client, and prints the two fields provisioning needs. It
// stores nothing, writes nothing, and exits.
//
//	go run ./internal/tools/oidcsubject
//
// The operator plane's harness must not be running: this listens on the
// registered redirect URI, which is the same port.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	oidcadapter "github.com/chronos/chronos-go/internal/adapter/oidc"
	"github.com/chronos/chronos-go/internal/platform/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "oidcsubject:", err)
		os.Exit(1)
	}
}

func run() error {
	timeout := flag.Duration("timeout", 3*time.Minute, "how long to wait for the browser")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}
	if !cfg.Operator.Configured() {
		return errors.New("the operator IdP is not configured; set OPERATOR_OIDC_ISSUER, " +
			"OPERATOR_OIDC_CLIENT_ID, OPERATOR_OIDC_CLIENT_SECRET and OPERATOR_OIDC_REDIRECT_URL")
	}

	redirect, err := url.Parse(cfg.Operator.OIDCRedirectURL)
	if err != nil {
		return fmt.Errorf("OPERATOR_OIDC_REDIRECT_URL is not a URL: %w", err)
	}
	host := redirect.Host
	if host == "" {
		return errors.New("OPERATOR_OIDC_REDIRECT_URL has no host")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	provider, err := oidcadapter.New(ctx, oidcadapter.Config{
		Issuer:       cfg.Operator.OIDCIssuer,
		ClientID:     cfg.Operator.OIDCClientID,
		ClientSecret: cfg.Operator.OIDCClientSecret.Expose(),
		RedirectURL:  cfg.Operator.OIDCRedirectURL,
		Scopes:       []string{"openid", "email", "profile"},
	})
	if err != nil {
		return fmt.Errorf("reaching the provider: %w", err)
	}

	ceremony, err := provider.Begin()
	if err != nil {
		return fmt.Errorf("starting the ceremony: %w", err)
	}

	// The ceremony's state lives in THIS process for its whole life, which is
	// the difference between this tool and the plane. There is no store, so
	// there is nothing to consume, replay or leak — the ceremony ends when the
	// process does.
	type result struct {
		identity oidcadapter.Identity
		err      error
	}
	done := make(chan result, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(redirect.Path, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		if e := q.Get("error"); e != "" {
			http.Error(w, "the provider refused: "+e, http.StatusBadRequest)
			done <- result{err: fmt.Errorf("the provider refused: %s %s", e, q.Get("error_description"))}
			return
		}

		identity, err := provider.Finish(r.Context(), ceremony, oidcadapter.Callback{
			Code:   q.Get("code"),
			State:  q.Get("state"),
			Issuer: q.Get("iss"),
		})
		if err != nil {
			http.Error(w, "this ceremony did not verify", http.StatusBadRequest)
			done <- result{err: err}
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		// The subject goes to the TERMINAL, not to this page. The browser has
		// just come back from a provider redirect, and a page that rendered an
		// identifier would be one a referrer header, an extension or a
		// screenshot could carry further than intended.
		_, _ = w.Write([]byte("Done. The subject is printed in the terminal that started this.\n" +
			"You can close this tab.\n"))
		done <- result{identity: identity}
	})

	// ListenConfig rather than net.Listen, so the bind honours the timeout the
	// whole ceremony runs under instead of blocking on a resolver that is not
	// answering.
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", host)
	if err != nil {
		return fmt.Errorf("listening on %s: %w\n\n"+
			"That is the registered redirect URI's port. Stop operatorlab first — "+
			"they cannot both hold it", host, err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	fmt.Println("Open this in a browser and sign in as the person to be provisioned:")
	fmt.Println()
	fmt.Println("  " + ceremony.AuthorizationURL)
	fmt.Println()
	fmt.Println("Waiting…")

	select {
	case <-ctx.Done():
		return errors.New("nobody completed the ceremony before the timeout")
	case res := <-done:
		if res.err != nil {
			return res.err
		}
		fmt.Println()
		fmt.Println("issuer:           " + res.identity.Issuer)
		fmt.Println("provider subject: " + res.identity.Subject)
		fmt.Println()
		fmt.Println("Provision with:")
		fmt.Println()
		fmt.Printf("  go run ./internal/tools/provisionoperator \\\n"+
			"      -email <their work address> \\\n"+
			"      -provider-subject %s \\\n"+
			"      -role operator_admin\n", res.identity.Subject)
		fmt.Println()
		fmt.Println("The address is stored in the VAULT and never in an event, so it is what")
		fmt.Println("a display name resolves to and nothing more. The subject above is what")
		fmt.Println("sign-in actually matches on.")
		return nil
	}
}
