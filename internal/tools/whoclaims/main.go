// Command whoclaims answers "which account claims this address, and can the
// vault still read it".
//
// # Why it exists
//
// Identity works in blind indexes: the address is never stored and never
// compared in the clear, so there is deliberately no query that goes from an
// address to a row. That is the right design and it makes one operational
// question unanswerable without a tool — "the mail is not arriving for this
// person, is it the account or the vault?"
//
// It reads and prints NOTHING personal beyond what the operator already typed.
// The address goes in, the index and the subject pseudonym come out.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"

	"github.com/chronos/chronos-go/internal/adapter/openbao"
	"github.com/chronos/chronos-go/internal/adapter/piivault"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/blindindex"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

func main() {
	email := flag.String("email", "", "the address to look up")
	flag.Parse()
	if *email == "" {
		fmt.Fprintln(os.Stderr, "whoclaims: -email is required")
		os.Exit(1)
	}
	if err := run(*email); err != nil {
		fmt.Fprintln(os.Stderr, "whoclaims:", err)
		os.Exit(1)
	}
}

func run(email string) error {
	ctx := context.Background()

	key, err := hex.DecodeString(os.Getenv("IDENTITY_EMAIL_INDEX_KEY"))
	if err != nil {
		return fmt.Errorf("IDENTITY_EMAIL_INDEX_KEY is not hex: %w", err)
	}
	index, err := blindindex.New(key)
	if err != nil {
		return err
	}
	idx, err := index.Of(email)
	if err != nil {
		return fmt.Errorf("indexing the address: %w", err)
	}
	fmt.Println("index:", idx)

	pool, err := pgxpool.New(ctx, os.Getenv("APP_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer pool.Close()

	// The login lookup's own statement, by its generated constant. SQL in Go
	// source is banned (CONVENTIONS §8) and the ban earns its keep here: writing
	// the query by hand would have re-derived `email_released_at IS NULL`, and a
	// tool that omitted it would report whichever of two accounts the planner
	// reached first — which for a diagnostic is worse than no answer.
	var (
		subject, userID, gotIndex, state        string
		verified                                bool
		registered, activated, deact, suspended pgtype.Timestamptz
	)
	err = pool.QueryRow(ctx, identitydb.GetUserByEmailIndex, string(idx)).
		Scan(&subject, &userID, &gotIndex, &state, &verified,
			&registered, &activated, &deact, &suspended)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		fmt.Println("account:  NONE claims this index")
		return nil
	case err != nil:
		// REPORTED, not swallowed. The first version returned "no account" for
		// every error, so a column list that had drifted from the query read as a
		// definitive answer — and the whole point of this tool is to be believed.
		return fmt.Errorf("reading the account: %w", err)
	}
	fmt.Printf("account:  %s state=%s verified=%t\n", subject, state, verified)

	// The vault half. A subject whose data key cannot be unwrapped has an
	// account that works and an address nothing can deliver to — which is
	// exactly the shape of failure this tool exists to name.
	bao, err := openbao.Dial(os.Getenv("OPENBAO_ADDR"), os.Getenv("OPENBAO_DEV_TOKEN"))
	if err != nil {
		return fmt.Errorf("openbao: %w", err)
	}
	kek := os.Getenv("OPENBAO_KEK_NAME")
	if kek == "" {
		kek = "chronos-kek"
	}
	vault := piivault.New(pgadapter.New(pool), openbao.NewKeyRing(bao, kek))

	profile, err := vault.Profile(ctx, pii.SubjectID(subject))
	if err != nil {
		fmt.Println("vault:    UNREADABLE —", err)
		fmt.Println()
		fmt.Println("The account exists and its address cannot be resolved, so every")
		fmt.Println("notification to it is undeliverable. In dev this usually means")
		fmt.Println("OpenBao restarted: it runs in-memory, so the KEK was recreated and")
		fmt.Println("data keys wrapped under the old one can no longer be unwrapped.")
		return nil
	}
	fmt.Println("vault:    readable, fields:", len(profile.Fields),
		"has email:", profile.Get(pii.FieldEmail) != "")
	return nil
}
