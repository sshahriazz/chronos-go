//go:build integration

package openbao_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/chronos/chronos-go/internal/adapter/openbao"
)

// secrets builds a reader against the REAL OpenBao.
func secrets(t *testing.T) *openbao.Secrets {
	t.Helper()
	token := os.Getenv("OPENBAO_DEV_TOKEN")
	if token == "" {
		t.Skip("OPENBAO_DEV_TOKEN is not set")
	}
	addr := os.Getenv("OPENBAO_ADDR")
	if addr == "" {
		addr = "http://localhost:8200"
	}
	client, err := openbao.Dial(addr, token)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	mount := os.Getenv("OPENBAO_KV_MOUNT")
	if mount == "" {
		mount = "secret"
	}
	s, err := openbao.NewSecrets(client, mount)
	if err != nil {
		t.Fatalf("NewSecrets: %v", err)
	}
	return s
}

// THE SEEDED STRIPE SECRETS ARE READABLE.
//
// Only the live server settles this, and the thing it settles is the KV v2
// nesting: a v2 read needs `<mount>/data/<path>` and returns the payload under
// `data.data`. Reading `<mount>/<path>` instead returns NOTHING and no error,
// which is indistinguishable from an unpopulated path — so this asserts against
// the shape the bootstrap script actually writes.
func TestTheSeededStripeSecretsAreReadable(t *testing.T) {
	path := os.Getenv("OPENBAO_STRIPE_PATH")
	if path == "" {
		// `make up` seeds this path whether or not the variable is set, because
		// the bootstrap script defaults it. The variable only decides whether
		// the BINARIES read from custody.
		path = "chronos/stripe"
	}

	values, err := secrets(t).Values(context.Background(), path)
	if err != nil {
		if errors.Is(err, openbao.ErrNoSecret) {
			t.Skipf("%s holds nothing; run `make up` to seed it", path)
		}
		t.Fatalf("reading %s: %v", path, err)
	}

	key, ok := values["api_key"]
	if !ok || key == "" {
		t.Fatalf("%s carries no non-empty api_key; keys present: %v", path, keysOf(values))
	}
	// The value's SHAPE, never the value. A test that logged a Stripe key on
	// failure would put one in CI output.
	if len(key) < 8 {
		t.Errorf("the api_key in custody is %d characters, which is not a Stripe key",
			len(key))
	}
}

// A PATH THAT HOLDS NOTHING IS ErrNoSecret, NOT AN EMPTY MAP.
//
// The distinction is what lets startup say "custody was never populated" rather
// than "the api_key is missing" — a deployment step nobody ran, versus a secret
// somebody wrote wrongly.
func TestAnEmptyPathIsReportedAsSuch(t *testing.T) {
	_, err := secrets(t).Values(context.Background(), "chronos/does-not-exist")
	if !errors.Is(err, openbao.ErrNoSecret) {
		t.Fatalf("returned %v, want ErrNoSecret", err)
	}
}

// A READER NEEDS A CLIENT AND A MOUNT.
func TestSecretsRefusesAnIncompleteWiring(t *testing.T) {
	if _, err := openbao.NewSecrets(nil, "secret"); err == nil {
		t.Error("a reader with no client was accepted")
	}
	client, err := openbao.Dial("http://localhost:8200", "t")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openbao.NewSecrets(client, ""); err == nil {
		t.Error("a reader with no mount was accepted")
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
