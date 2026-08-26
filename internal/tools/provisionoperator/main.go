// Command provisionoperator grants an employee access to the back office.
//
// # Why this is a CLI and not an RPC
//
// It is both, eventually: operator.md §7 puts operator account management on
// `operator_admin`, and that RPC is slice 2. But the first operator cannot be
// provisioned by an RPC, because every RPC on that plane needs a session and
// there is nobody to sign in as — the classic bootstrap, and the honest
// resolution is a tool that runs where the credentials already are rather than
// an endpoint that is exempt from authentication.
//
// It writes through the SAME aggregate the RPC will, so the two cannot diverge:
// the event is identical, the projection is identical, and switching to the RPC
// later changes who may call it and nothing about what is recorded.
//
// # It does not create the WebAuthn credential
//
// Deliberately. The operator enrols their own authenticator on first sign-in,
// through the bootstrap window in the sign-in flow — so the person who runs
// this tool never holds anything that could authenticate as the operator they
// provisioned.
//
//	go run ./internal/tools/provisionoperator \
//	    -email alice@example.com \
//	    -provider-subject 1234567890 \
//	    -role support
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	kurrentadapter "github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	"github.com/chronos/chronos-go/internal/adapter/openbao"
	"github.com/chronos/chronos-go/internal/adapter/piivault"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	"github.com/chronos/chronos-go/internal/operator"
	"github.com/chronos/chronos-go/internal/operator/contract"
	"github.com/chronos/chronos-go/internal/operator/domain"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "provisionoperator: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		email    = flag.String("email", "", "the employee's work address; stored in the VAULT, never in an event")
		subject  = flag.String("provider-subject", "", "the IdP's immutable subject for them (Google's `sub`)")
		issuer   = flag.String("issuer", "", "the IdP issuer; defaults to OPERATOR_OIDC_ISSUER")
		roleName = flag.String("role", string(contract.RoleSupport), "support | billing_ops | catalogue_admin | operator_admin")
		by       = flag.String("by", "", "the operator_admin doing this; empty for the FIRST operator, which nobody provisioned")
	)
	flag.Parse()

	switch {
	case *email == "":
		return errors.New("-email is required: it is what the vault stores and what a display name resolves to")
	case *subject == "":
		return errors.New("-provider-subject is required: sign-in matches on the IdP's immutable subject, never on the address")
	}

	role, err := domain.ParseRole(*roleName)
	if err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}
	iss := *issuer
	if iss == "" {
		iss = cfg.Operator.OIDCIssuer
	}
	if iss == "" {
		return errors.New("no issuer: pass -issuer or set OPERATOR_OIDC_ISSUER")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The OWNER pool, not the operator role's.
	//
	// This tool WRITES the vault, and chronos_operator holds SELECT on it and
	// nothing else (migration 00038). That asymmetry is the design — the
	// operator plane reads personal data on justified access and never writes
	// it — so the bootstrap has to run with credentials the plane itself does
	// not have.
	pool, err := pgadapter.NewPool(ctx, cfg.Postgres.AppDSN(), 4)
	if err != nil {
		return fmt.Errorf("connecting to postgres: %w", err)
	}
	defer pool.Close()

	bao, err := openbao.Dial(cfg.OpenBao.Address, cfg.OpenBao.Token.Expose())
	if err != nil {
		return fmt.Errorf("reaching the key store: %w", err)
	}
	vault := piivault.New(pgadapter.New(pool), openbao.NewKeyRing(bao, cfg.OpenBao.KEKName))

	upcasters := eventsourcing.NewUpcasterRegistry()
	codec := eventcodec.NewJSON(upcasters)
	operator.RegisterEvents(codec)
	operator.RegisterSchemas(upcasters)

	kc, err := kurrentadapter.Dial(cfg.KurrentDB.ConnectionString)
	if err != nil {
		return fmt.Errorf("connecting to the event log: %w", err)
	}
	defer func() { _ = kc.Close() }()
	store := kurrentadapter.NewStore(kc, codec)

	now := time.Now().UTC()
	operatorID := ids.New[ids.Operator](now, rand.Reader).String()
	subjectID := ids.New[ids.Subject](now, rand.Reader).String()

	// The vault write comes FIRST, and the ordering matters.
	//
	// If it succeeds and the append then fails, the result is an orphaned vault
	// row: personal data with no operator pointing at it, which is untidy and
	// harmless — nothing can reach it, and it is erasable by its own key.
	//
	// The reverse ordering gives an operator account whose address cannot be
	// resolved, which is the failure this repository has already lived through
	// once: authentication keeps working, and every attempt to name the person
	// fails one at a time.
	if err := vault.Put(ctx, pii.SubjectID(subjectID), pii.FieldEmail, *email); err != nil {
		return fmt.Errorf("storing the address: %w", err)
	}

	repo := eventsourcing.NewRepository(store, codec, upcasters,
		domain.OperatorCategory, domain.NewOperator)

	agg, err := repo.Load(ctx, domain.OperatorStreamKey(operatorID))
	if err != nil {
		return fmt.Errorf("loading the operator stream: %w", err)
	}
	if err := agg.Provision(operatorID, subjectID, iss, *subject, role, *by, now); err != nil {
		return err
	}
	if _, err := repo.Save(ctx, domain.OperatorStreamKey(operatorID), agg, operatorID,
		eventsourcing.Metadata{}); err != nil {
		return fmt.Errorf("recording the provisioning: %w", err)
	}

	fmt.Printf("operator:   %s\n", operatorID)
	fmt.Printf("subject:    %s\n", subjectID)
	fmt.Printf("issuer:     %s\n", iss)
	fmt.Printf("role:       %s\n", role)
	fmt.Println()
	fmt.Println("They sign in through the operator console. Their FIRST sign-in enrols an")
	fmt.Println("authenticator through the bootstrap window; every one after that requires it.")
	fmt.Println()
	fmt.Println("cmd/operator must be running for the projection to pick this up — the row")
	fmt.Println("sign-in resolves against is built by that binary, not by cmd/projector.")
	return nil
}
