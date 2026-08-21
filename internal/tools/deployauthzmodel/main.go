// Command deployauthzmodel provisions the OpenFGA store and deploys the
// authorization model, printing the ids to pin.
//
// # Why this is an operator command and not something the server does
//
// It would be convenient for cmd/api to ensure its own store and model at boot.
// It would also be the worst possible failure mode: a server that provisions its
// own authorization store answers every check against whatever store it just
// created. Point it at the wrong endpoint, or start it before the real store
// exists, and it creates an EMPTY one — then denies everything while reporting
// itself healthy, because an empty graph is a perfectly valid graph.
//
// So provisioning is deliberate, out-of-band, and prints ids a human puts into
// configuration. That is also what access.md §10's deploy ordering requires:
//
//  1. deploy the model      (this command)
//  2. deploy code pinning the new model id
//  3. deploy code writing the new tuples
//
// Running it is idempotent in the way that matters: the store is found by name
// rather than recreated. The MODEL, though, is appended every time — OpenFGA
// does not update models — so each run produces a new id, and running it without
// then pinning the new id leaves the server on the previous model.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/openfga"
	"github.com/chronos/chronos-go/internal/authzmodel"
)

func main() {
	endpoint := flag.String("endpoint", env("OPENFGA_ENDPOINT", "localhost:8081"),
		"the OpenFGA gRPC endpoint")
	key := flag.String("preshared-key", os.Getenv("OPENFGA_PRESHARED_KEY"),
		"the OpenFGA preshared key")
	storeName := flag.String("store", env("OPENFGA_STORE_NAME", "chronos"),
		"the store name; found by name, created only if absent")
	dryRun := flag.Bool("dry-run", false, "assemble and print the model, contact nothing")
	flag.Parse()

	model, err := authzmodel.Assemble()
	if err != nil {
		fail("%v", err)
	}

	if *dryRun {
		fmt.Print(model.String())
		return
	}
	if *key == "" {
		fail("OPENFGA_PRESHARED_KEY is not set; the server refuses an unauthenticated client")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn, err := openfga.Dial(*endpoint, *key)
	if err != nil {
		fail("dialling %s: %v", *endpoint, err)
	}
	defer func() { _ = conn.Close() }()

	deployer, err := openfga.NewDeployer(conn)
	if err != nil {
		fail("%v", err)
	}

	storeID, err := deployer.EnsureStore(ctx, *storeName)
	if err != nil {
		fail("%v", err)
	}
	modelID, err := deployer.Deploy(ctx, storeID, model)
	if err != nil {
		fail("%v", err)
	}

	fmt.Printf("  store %q -> %s\n", *storeName, storeID)
	types := fmt.Sprintf("%d types", len(model.Types))
	if len(model.Types) == 1 {
		types = "1 type"
	}
	fmt.Printf("  model deployed -> %s (%s)\n\n", modelID, types)
	fmt.Printf("Pin these, then restart the server:\n\n")
	fmt.Printf("OPENFGA_STORE_ID=%s\nOPENFGA_MODEL_ID=%s\n\n", storeID, modelID)
	fmt.Printf("Until OPENFGA_MODEL_ID is pinned the checker resolves \"latest\", which makes\n" +
		"a deploy racy: a request in flight during the next deploy is evaluated against a\n" +
		"model it was not written for.\n")
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "deployauthzmodel: "+format+"\n", args...)
	os.Exit(1)
}
