package app_test

import (
	"context"
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/profile/app"
	"github.com/chronos/chronos-go/internal/modules/profile/domain"
)

// TestGrantIsIssuedUnderTheCallersOwnPrefix is the structural half of the
// upload's authorization: the server never signs a policy for a key outside the
// caller's namespace, which is what makes the confirm call's prefix check
// sufficient.
func TestGrantIsIssuedUnderTheCallersOwnPrefix(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	grant, err := h.avatars.Grant(context.Background(), app.UploadGrantCommand{
		SubjectID: subject, ContentType: "image/png", SizeBytes: 1024, IdempotencyKey: "k1",
	})
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}

	wantPrefix := domain.AvatarPrefix(subject) + "/"
	if !strings.HasPrefix(grant.ObjectKey, wantPrefix) {
		t.Fatalf("ObjectKey = %q, want it under %q — a key outside the caller's prefix "+
			"is one they could not confirm, and one somebody else could", grant.ObjectKey, wantPrefix)
	}
	if strings.HasPrefix(grant.ObjectKey, domain.AvatarPrefix(otherSubject)) {
		t.Fatal("the grant landed in another subject's namespace")
	}

	// The DECLARED size, not the ceiling. Pinning the ceiling would let a caller
	// who declared 10 KiB store 5 MiB, which is the whole point of asking.
	if grant.MaxBytes != 1024 {
		t.Fatalf("MaxBytes = %d, want the declared 1024", grant.MaxBytes)
	}
	if len(h.store.granted) != 1 {
		t.Fatalf("the store was asked for %d grants, want one", len(h.store.granted))
	}
	req := h.store.granted[0]
	if req.ContentType != "image/png" {
		t.Fatalf("the policy pins content type %q, want image/png — without it the "+
			"stored object can claim to be something else", req.ContentType)
	}
	if req.Expiry <= 0 {
		t.Fatal("the policy has no expiry; a grant is a capability and a leaked one " +
			"should stop working")
	}
}

// TestEveryGrantIsANewKey is what keeps stored objects immutable: a replaced
// avatar is a new key and a new event, never an overwrite (ADR-013).
func TestEveryGrantIsANewKey(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	ctx := context.Background()
	seen := map[string]struct{}{}
	for i := range 5 {
		grant, err := h.avatars.Grant(ctx, app.UploadGrantCommand{
			SubjectID: subject, ContentType: "image/png", SizeBytes: 10,
			IdempotencyKey: "k" + string(rune('0'+i)),
		})
		if err != nil {
			t.Fatalf("Grant %d: %v", i, err)
		}
		if _, dup := seen[grant.ObjectKey]; dup {
			t.Fatalf("grant %d reissued key %q; a repeated key means a new upload "+
				"OVERWRITES the object an earlier event still points at", i, grant.ObjectKey)
		}
		seen[grant.ObjectKey] = struct{}{}
	}
}

func TestGrantRefusals(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cmd  app.UploadGrantCommand
		why  string
	}{
		{
			name: "no subject",
			cmd:  app.UploadGrantCommand{ContentType: "image/png", SizeBytes: 10, IdempotencyKey: "k"},
			why:  "there would be no namespace to issue the key under",
		},
		{
			name: "no idempotency key",
			cmd:  app.UploadGrantCommand{SubjectID: subject, ContentType: "image/png", SizeBytes: 10},
			why:  "a double-clicked button would mint two grants and abandon one object",
		},
		{
			name: "svg",
			cmd: app.UploadGrantCommand{
				SubjectID: subject, ContentType: "image/svg+xml", SizeBytes: 10, IdempotencyKey: "k",
			},
			why: "SVG executes script from an origin the session cookie is scoped to",
		},
		{
			name: "an undeclared size",
			cmd: app.UploadGrantCommand{
				SubjectID: subject, ContentType: "image/png", IdempotencyKey: "k",
			},
			why: "the policy's content-length-range is what the store enforces before storing",
		},
		{
			name: "over the ceiling",
			cmd: app.UploadGrantCommand{
				SubjectID: subject, ContentType: "image/png",
				SizeBytes: domain.MaxAvatarBytes + 1, IdempotencyKey: "k",
			},
			why: "the ceiling is the bound on what this system will ever store",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			if _, err := h.avatars.Grant(context.Background(), tt.cmd); err == nil {
				t.Fatalf("Grant was accepted, want a refusal (%s)", tt.why)
			}
			if len(h.store.granted) != 0 {
				t.Fatal("a refused grant still asked the object store to sign a policy")
			}
		})
	}
}

// TestGrantFieldsAreStablyOrdered — a client diffing two responses should see a
// real difference rather than Go's map iteration order.
func TestGrantFieldsAreStablyOrdered(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	grant, err := h.avatars.Grant(context.Background(), app.UploadGrantCommand{
		SubjectID: subject, ContentType: "image/png", SizeBytes: 10, IdempotencyKey: "k",
	})
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	for i := 1; i < len(grant.Fields); i++ {
		if grant.Fields[i-1].Key > grant.Fields[i].Key {
			t.Fatalf("fields are not sorted: %q before %q",
				grant.Fields[i-1].Key, grant.Fields[i].Key)
		}
	}
}
