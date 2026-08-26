// Command releaseaddress frees an email reservation whose account can no longer
// be recovered.
//
// # When this is the right tool
//
// An address is held by a reservation until its owner releases it, it lapses, or
// the account is erased. That is correct and it has one gap: an account whose
// VAULT DATA is unreadable — because the key-encryption key was lost or replaced
// (ADR-028) — can never be verified, never receives mail, and never erases
// itself, so its address stays claimed by something nobody can use.
//
// The KEK canary now stops that state being reached silently, but it does not
// undo the installations that already reached it.
//
// # It goes through the AGGREGATE
//
// `EmailReservation.Release` decides, exactly as it does for a sweep or an
// erasure, and the event it records is what the projector applies. Editing the
// row instead would leave the read model saying one thing and the log another —
// and the log is the authority, so the next replay would put the address back.
//
// It refuses an address whose vault data is READABLE. That account is
// recoverable by ordinary means — a resend, a reset — and releasing its address
// would be destroying something that still works.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	kurrentadapter "github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	"github.com/chronos/chronos-go/internal/adapter/openbao"
	"github.com/chronos/chronos-go/internal/adapter/piivault"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/blindindex"
	identityapp "github.com/chronos/chronos-go/internal/modules/identity/app"
	identitydomain "github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

func main() {
	email := flag.String("email", "", "the address to release")
	subject := flag.String("subject", "", "the subject that holds it, from whoclaims")
	force := flag.Bool("force", false,
		"release even though the vault data is readable — destroys a working account's claim")
	flag.Parse()

	if *email == "" || *subject == "" {
		fmt.Fprintln(os.Stderr, "releaseaddress: -email and -subject are required "+
			"(run whoclaims first)")
		os.Exit(1)
	}
	if err := run(*email, *subject, *force); err != nil {
		fmt.Fprintln(os.Stderr, "releaseaddress:", err)
		os.Exit(1)
	}
}

func run(email, subject string, force bool) error {
	ctx := context.Background()

	key, err := hex.DecodeString(os.Getenv("IDENTITY_EMAIL_INDEX_KEY"))
	if err != nil {
		return fmt.Errorf("IDENTITY_EMAIL_INDEX_KEY is not hex: %w", err)
	}
	indexer, err := blindindex.New(key)
	if err != nil {
		return err
	}
	index, err := indexer.Of(email)
	if err != nil {
		return fmt.Errorf("indexing the address: %w", err)
	}

	pool, err := pgxpool.New(ctx, os.Getenv("APP_DATABASE_URL"))
	if err != nil {
		return err
	}
	defer pool.Close()

	// The guard. An account whose data is readable is recoverable by ordinary
	// means, and releasing its address would destroy something that still works.
	if !force {
		bao, dialErr := openbao.Dial(os.Getenv("OPENBAO_ADDR"), os.Getenv("OPENBAO_DEV_TOKEN"))
		if dialErr != nil {
			return fmt.Errorf("openbao: %w", dialErr)
		}
		kek := os.Getenv("OPENBAO_KEK_NAME")
		if kek == "" {
			kek = "chronos-kek"
		}
		vault := piivault.New(pgadapter.New(pool), openbao.NewKeyRing(bao, kek))
		if _, readErr := vault.Profile(ctx, pii.SubjectID(subject)); readErr == nil {
			return errors.New("this subject's vault data is READABLE, so the account is " +
				"recoverable by ordinary means — a verification resend, or a password " +
				"reset. Releasing its address would destroy a claim that still works. " +
				"Pass -force only if you mean it")
		}
	}

	upcasters := eventsourcing.NewUpcasterRegistry()
	identity.RegisterSchemas(upcasters)
	codec := eventcodec.NewJSON(upcasters)
	identity.RegisterEvents(codec)

	dsn := os.Getenv("KURRENTDB_CONNECTION_STRING")
	if dsn == "" {
		// The compose default. Named here rather than left to fail, because the
		// variable is absent from .env by default and a scheme error says nothing
		// about which variable was missing.
		dsn = "kurrentdb://localhost:2113?tls=false"
	}
	client, err := kurrentadapter.Dial(dsn)
	if err != nil {
		return fmt.Errorf("kurrentdb: %w", err)
	}
	defer func() { _ = client.Close() }()

	repo := eventsourcing.NewRepository[*identitydomain.EmailReservation](
		kurrentadapter.NewStore(client, codec), codec, upcasters,
		identityapp.ReservationCategory, identitydomain.NewReservation)

	reservation, err := repo.Load(ctx, string(index))
	if err != nil {
		return fmt.Errorf("loading the reservation: %w", err)
	}
	if !reservation.Held() {
		fmt.Println("the address is already free")
		return nil
	}

	now := time.Now().UTC()
	// ReleaseErased, because that is what happened: the key that made this
	// subject's data readable is gone, which is erasure by accident rather than
	// by request. identity.md §12 already treats identifier reuse after erasure
	// as a stated requirement, so the address becoming available again is the
	// intended consequence rather than a side effect.
	if err := reservation.Release(subject, identitydomain.ReleaseErased, now); err != nil {
		return fmt.Errorf("releasing: %w", err)
	}
	if _, err := repo.Save(ctx, string(index), reservation,
		"release-address:"+string(index),
		eventsourcing.Metadata{OccurredAt: now, SubjectIDs: []string{subject}},
	); err != nil {
		return fmt.Errorf("recording the release: %w", err)
	}

	fmt.Printf("released %s\n", index)
	fmt.Println("the projector applies it in a moment; the address can then be registered again")
	return nil
}
