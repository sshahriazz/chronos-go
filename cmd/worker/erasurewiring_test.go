package main

import (
	"log/slog"
	"reflect"
	"testing"

	identityapp "github.com/chronos/chronos-go/internal/modules/identity/app"
)

// ERASURE REACHES THE PASSKEYS.
//
// # The failure this exists for, which shipped
//
// `passkey_credential` is the ONE erasure target with no key to destroy. Every
// other piece of personal data here is readable only through a subject key the
// vault shreds (ADR-002); a WebAuthn public key is verification material, so the
// vault never held it and shredding leaves it untouched. Migration 00033 also
// removed the foreign key that would have cascaded, because `user_view` is a
// projection and a rebuild truncating it would have taken every passkey in the
// installation with it.
//
// So NOTHING else deletes these rows. The store's Erase was written, had its own
// integration test, and passed it — while no caller existed. A person exercised
// erasure, their vault key was destroyed, and their credential id and public key
// stayed in the database. The integration test proved the method WORKED; nothing
// proved it RAN.
//
// # Why it is asserted on the struct
//
// The use case's own field, read by reflection, because the alternative is
// asserting on a result count from a full erasure — which needs a live event
// store, a directory and an account that has requested deletion. This is the
// cheap assertion that the collaborator is present at all, which is the entire
// failure mode: not a wrong deletion, an absent one.
func TestAccountErasureIsWiredToThePasskeyStore(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	erasure, err := newAccountErasure(d)
	if err != nil {
		t.Skipf("account erasure could not be built in this environment: %v", err)
	}

	field := reflect.ValueOf(erasure).Elem().FieldByName("passkeys")
	if !field.IsValid() {
		t.Fatal("identityapp.Erasure has no passkeys field; the erasure cannot reach " +
			"WebAuthn material at all")
	}
	if field.IsNil() {
		t.Fatal("the account erasure was built with NO passkey store. Erasing a subject " +
			"destroys their vault key and leaves their credential id and public key in " +
			"the database forever — readable material about a person who asked to be " +
			"forgotten, and nothing else deletes it: there is no key to shred and " +
			"migration 00033 removed the cascade on purpose")
	}
}

// The port exists and is the narrow one.
//
// Pinned so the erasure cannot acquire the whole passkey flow by widening this
// field: an erasure that could REGISTER a credential is an erasure with a
// capability it has no business holding.
func TestThePasskeyEraserPortStaysNarrow(t *testing.T) {
	typ := reflect.TypeOf((*identityapp.PasskeyEraser)(nil)).Elem()
	if got := typ.NumMethod(); got != 1 {
		t.Fatalf("PasskeyEraser declares %d methods, want exactly 1. Erasure needs to "+
			"delete and nothing else; a wider port lets it enrol", got)
	}
	if name := typ.Method(0).Name; name != "Erase" {
		t.Fatalf("the one method is %q, want Erase", name)
	}
}
