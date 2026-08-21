package authz_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/authz"
)

// recorder logs the order of every effect, because the ORDER is the property
// under test — not the fact that both things happened.
type recorder struct {
	order []string

	deleteErr  error
	writeErr   error
	confirmErr error
}

func (r *recorder) Write(_ context.Context, ts []authz.Tuple) error {
	r.order = append(r.order, "write")
	return r.writeErr
}

func (r *recorder) Delete(_ context.Context, ts []authz.Tuple) error {
	r.order = append(r.order, "delete")
	return r.deleteErr
}

func (r *recorder) Confirm(_ context.Context, q authz.Query) error {
	r.order = append(r.order, "confirm:"+q.Principal.String())
	return r.confirmErr
}

func directGrant(id string) authz.Tuple {
	return authz.Tuple{
		Subject:  authz.Subject{Principal: authz.Principal{Kind: authz.KindUser, ID: id}},
		Relation: "editor",
		Resource: authz.ResourceRef{Type: "folder", ID: "f1"},
	}
}

func confirming(t *testing.T, r *recorder) *authz.ConfirmingWriter {
	t.Helper()
	w, err := authz.NewConfirmingWriter(r, r, nil)
	if err != nil {
		t.Fatalf("ConfirmingWriter: %v", err)
	}
	return w
}

// The tuple goes first, the tombstone is cleared after.
//
// Reversed, a failed deletion would leave the tuple in place with nothing
// denying against it — the revoked principal silently regains access, with no
// event and no log line.
func TestTheTupleIsRemovedBeforeTheTombstoneIsCleared(t *testing.T) {
	r := &recorder{}
	if err := confirming(t, r).Delete(context.Background(), []authz.Tuple{directGrant("alice")}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	want := []string{"delete", "confirm:user:alice"}
	if len(r.order) != len(want) || r.order[0] != want[0] || r.order[1] != want[1] {
		t.Fatalf("effects ran in the order %v; want %v — a tombstone cleared before its tuple "+
			"is a revocation that did not take effect", r.order, want)
	}
}

// A failed deletion confirms NOTHING. The tombstone is the only thing denying
// access while the tuple is still there.
func TestAFailedDeletionClearsNoTombstone(t *testing.T) {
	r := &recorder{deleteErr: errors.New("openfga unreachable")}
	err := confirming(t, r).Delete(context.Background(), []authz.Tuple{directGrant("bob")})
	if err == nil {
		t.Fatal("a failed deletion was reported as success")
	}
	for _, step := range r.order {
		if strings.HasPrefix(step, "confirm") {
			t.Fatal("a tombstone was cleared although the tuple removal failed: the tuple is " +
				"still in the graph and nothing denies against it any more")
		}
	}
}

// A confirmation failure is reported, not swallowed.
//
// The projector retries — safe, because Delete is idempotent — and the
// alternative is a tombstone left to reach its TTL, which is an over-denial that
// looks like a permissions bug and arrives an hour after the cause.
func TestAFailedConfirmationIsReported(t *testing.T) {
	r := &recorder{confirmErr: errors.New("valkey unreachable")}
	err := confirming(t, r).Delete(context.Background(), []authz.Tuple{directGrant("carol")})
	if err == nil {
		t.Fatal("a tombstone that could not be cleared was reported as confirmed; it will now " +
			"expire on its TTL instead, denying a principal whose access was restored")
	}
	if !strings.Contains(err.Error(), "not confirmed") {
		t.Errorf("the error does not say what failed: %v", err)
	}
}

// Writing a grant must never clear a tombstone.
//
// Otherwise an arriving grant cancels a revocation the projector has not caught
// up to yet — the two events are unrelated, and one is not evidence about the
// other.
func TestWritingAGrantClearsNoTombstone(t *testing.T) {
	r := &recorder{}
	if err := confirming(t, r).Write(context.Background(), []authz.Tuple{directGrant("dave")}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	for _, step := range r.order {
		if strings.HasPrefix(step, "confirm") {
			t.Fatal("writing a tuple cleared a tombstone: a grant now cancels an unrelated " +
				"revocation that has not been applied yet")
		}
	}
}

// A userset removal has no single tombstone, so it confirms none.
//
// Removing `team:eng#member editor folder:f` revokes everyone in the team, and
// each of those revocations has its own principal-keyed tombstone. Confirming
// one here would clear a tombstone that names the TEAM — which no Guard ever
// consults, so the real ones would survive to their TTL.
func TestAUsersetRemovalConfirmsNoPrincipalTombstone(t *testing.T) {
	r := &recorder{}
	team := authz.Tuple{
		Subject: authz.Subject{
			Principal: authz.Principal{Kind: authz.KindUser, ID: "eng"},
			Relation:  "member",
		},
		Relation: "editor",
		Resource: authz.ResourceRef{Type: "folder", ID: "f1"},
	}
	if err := confirming(t, r).Delete(context.Background(), []authz.Tuple{team}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	for _, step := range r.order {
		if strings.HasPrefix(step, "confirm") {
			t.Fatalf("a userset removal confirmed %q, which is not a tombstone any Guard reads", step)
		}
	}
}

// Every tuple in a batch gets its tombstone confirmed, not just the first.
func TestEveryRemovalInABatchIsConfirmed(t *testing.T) {
	r := &recorder{}
	batch := []authz.Tuple{directGrant("a"), directGrant("b"), directGrant("c")}
	if err := confirming(t, r).Delete(context.Background(), batch); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	for _, id := range []string{"user:a", "user:b", "user:c"} {
		var found bool
		for _, step := range r.order {
			if step == "confirm:"+id {
				found = true
			}
		}
		if !found {
			t.Errorf("%s's tuple was removed but their tombstone was never confirmed, so they "+
				"stay denied until it expires", id)
		}
	}
}

// A ConfirmingWriter with no Revocations store is refused at construction.
//
// Optional would mean a deployment could lose confirmation silently, and
// discover it only as tombstones aging out — which is precisely the failure the
// confirmation design exists to prevent.
func TestAConfirmingWriterWithoutRevocationsIsRefused(t *testing.T) {
	if _, err := authz.NewConfirmingWriter(&recorder{}, nil, nil); err == nil {
		t.Fatal("a ConfirmingWriter was built with no revocation store: tombstones would only " +
			"ever be cleared by their TTL")
	}
	if _, err := authz.NewConfirmingWriter(nil, &recorder{}, nil); err == nil {
		t.Fatal("a ConfirmingWriter was built with no tuple writer")
	}
}

// A userset reference renders the way OpenFGA expects, and a direct principal
// does not accidentally acquire one.
func TestSubjectRendering(t *testing.T) {
	direct := authz.Subject{Principal: authz.Principal{Kind: authz.KindUser, ID: "alice"}}
	if got := direct.String(); got != "user:alice" {
		t.Errorf("direct subject rendered %q, want user:alice", got)
	}
	if direct.IsUserset() {
		t.Error("a direct principal was reported as a userset, so no tombstone would ever be " +
			"confirmed for it")
	}
	set := authz.Subject{
		Principal: authz.Principal{Kind: authz.KindUser, ID: "eng"},
		Relation:  "member",
	}
	if got := set.String(); got != "user:eng#member" {
		t.Errorf("userset rendered %q, want user:eng#member", got)
	}
}

// Reserved characters are refused, on every part of a tuple.
//
// ':' separates type from id and '#' introduces a userset, so a value carrying
// either addresses a different object than the caller named — a grant to the
// wrong people, written by a projector that thought it was applying an event.
func TestReservedCharactersAreRefusedInATuple(t *testing.T) {
	for name, mutate := range map[string]func(*authz.Tuple){
		"principal id": func(tp *authz.Tuple) { tp.Subject.Principal.ID = "alice#member" },
		"relation":     func(tp *authz.Tuple) { tp.Relation = "editor#viewer" },
		"resource id":  func(tp *authz.Tuple) { tp.Resource.ID = "f1:other" },
		"subject relation": func(tp *authz.Tuple) {
			tp.Subject.Relation = "member:admin"
		},
		"empty relation": func(tp *authz.Tuple) { tp.Relation = "" },
	} {
		tp := directGrant("alice")
		mutate(&tp)
		if err := tp.Validate(); err == nil {
			t.Errorf("a tuple with a bad %s was accepted", name)
		} else if !errors.Is(err, authz.ErrInvalid) {
			t.Errorf("a bad %s is not reported as invalid: %v", name, err)
		}
	}
}

// ConfirmAll is how the fan-out from a userset removal is cleared, and a partial
// failure is visible rather than being mistaken for a complete one.
func TestConfirmAllReportsTheFirstFailure(t *testing.T) {
	r := &recorder{}
	w := confirming(t, r)
	qs := []authz.Query{
		{Principal: authz.Principal{Kind: authz.KindUser, ID: "a"}, Relation: "editor",
			Resource: authz.ResourceRef{Type: "folder", ID: "f1"}},
		{Principal: authz.Principal{Kind: authz.KindUser, ID: "b"}, Relation: "editor",
			Resource: authz.ResourceRef{Type: "folder", ID: "f1"}},
	}
	if err := w.ConfirmAll(context.Background(), qs); err != nil {
		t.Fatalf("ConfirmAll: %v", err)
	}
	if len(r.order) != 2 {
		t.Fatalf("confirmed %d of %d revocations", len(r.order), len(qs))
	}

	r.confirmErr = errors.New("valkey unreachable")
	if err := w.ConfirmAll(context.Background(), qs); err == nil {
		t.Fatal("a failed confirmation was reported as success")
	}
}

// A tuple subject may be an OBJECT, and must not be both.
//
// # Why this shape
//
// `organization:acme parent workspace:eng` is the edge the whole access topology
// rests on — it is what makes an org admin an admin of every workspace in the
// org with no fan-out — and an organization is not an actor. PrincipalKind is a
// closed set on purpose, so that a typo cannot invent an actor kind, which left
// that edge unwritable: the first attempt failed with `unknown principal kind
// "organization"`.
//
// Widening PrincipalKind would have been the wrong repair. It would also permit
// an organization as the subject of a CHECK — "may organization:acme read this"
// — which is a question with no meaning, and the type would have stopped
// refusing it.
//
// So the two are separate fields and exactly one may be set. A subject carrying
// both is refused rather than resolved by precedence, because whichever one a
// precedence rule picked would silently be a different grant than the caller
// wrote.
func TestATupleSubjectIsAPrincipalOrAnObjectButNeverBoth(t *testing.T) {
	t.Parallel()

	resource := authz.ResourceRef{Type: "workspace", ID: "eng"}

	t.Run("an object subject is valid and renders as an object reference", func(t *testing.T) {
		t.Parallel()
		tuple := authz.Tuple{
			Subject:  authz.Subject{Object: authz.ResourceRef{Type: "organization", ID: "acme"}},
			Relation: "parent",
			Resource: resource,
		}
		if err := tuple.Validate(); err != nil {
			t.Fatalf("the parent edge is refused, so the inheritance topology cannot be "+
				"written at all: %v", err)
		}
		if got, want := tuple.Subject.String(), "organization:acme"; got != want {
			t.Errorf("rendered %q, want %q", got, want)
		}
	})

	t.Run("a principal subject still works", func(t *testing.T) {
		t.Parallel()
		tuple := authz.Tuple{
			Subject:  authz.Subject{Principal: authz.Principal{Kind: authz.KindUser, ID: "alice"}},
			Relation: "admin",
			Resource: resource,
		}
		if err := tuple.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if got, want := tuple.Subject.String(), "user:alice"; got != want {
			t.Errorf("rendered %q, want %q", got, want)
		}
	})

	t.Run("both set is refused", func(t *testing.T) {
		t.Parallel()
		tuple := authz.Tuple{
			Subject: authz.Subject{
				Principal: authz.Principal{Kind: authz.KindUser, ID: "alice"},
				Object:    authz.ResourceRef{Type: "organization", ID: "acme"},
			},
			Relation: "parent",
			Resource: resource,
		}
		if err := tuple.Validate(); err == nil {
			t.Fatal("a subject naming both a principal and an object was accepted; whichever " +
				"one the writer picks is silently a different grant than was written")
		}
	})

	t.Run("an object subject may still be a userset", func(t *testing.T) {
		t.Parallel()
		tuple := authz.Tuple{
			Subject: authz.Subject{
				Object:   authz.ResourceRef{Type: "team", ID: "eng"},
				Relation: "member",
			},
			Relation: "viewer",
			Resource: resource,
		}
		if err := tuple.Validate(); err != nil {
			t.Fatalf("a team userset is the scale lever in access.md §4 and it is refused: %v", err)
		}
		if got, want := tuple.Subject.String(), "team:eng#member"; got != want {
			t.Errorf("rendered %q, want %q", got, want)
		}
	})
}
