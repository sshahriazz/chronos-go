package app

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/chronos/chronos-go/internal/modules/profile/domain"
	"github.com/chronos/chronos-go/internal/platform/blob"
	"github.com/chronos/chronos-go/internal/platform/errs"
)

// UploadGrantTTL is how long a signed upload target stays usable.
//
// A grant is a CAPABILITY: whoever holds it can store one object of a declared
// type and size under one key. Short, because a leaked one should stop working;
// long enough for a browser to pick a file, read it and POST it over a slow
// connection.
const UploadGrantTTL = 10 * time.Minute

// UploadGrantCommand asks for somewhere to put an avatar.
type UploadGrantCommand struct {
	// SubjectID is the CALLER'S pseudonym, from the session. It is what the key
	// prefix is derived from, and it is why a grant cannot be issued for
	// somebody else's namespace.
	SubjectID string

	// ContentType and SizeBytes are what the browser is about to upload. Both
	// are pinned into the signed policy, so the store enforces them BEFORE a
	// byte is written rather than this server checking afterwards.
	ContentType string
	SizeBytes   int64

	IdempotencyKey string
}

// UploadGrant is a signed, expiring upload target.
//
// It is deliberately not a `blob.Grant`: this type crosses into the API layer,
// and re-declaring it here keeps the kernel's shape free to change without a
// wire change — and keeps the API layer from acquiring a dependency on the
// object-store port.
type UploadGrant struct {
	URL       string
	Fields    []GrantField
	ObjectKey string
	Expires   time.Time
	MaxBytes  int64
}

// GrantField is one form field the browser must send with the upload, in order.
type GrantField struct {
	Key   string
	Value string
}

// Avatars mints upload targets. It is the only part of this module that talks
// to the object store on the write path, and it never sees an image.
type Avatars struct {
	store AvatarStore
}

// AvatarsDeps is what the use case needs.
type AvatarsDeps struct {
	Store AvatarStore
}

// NewAvatars builds the use case, refusing a partial one.
func NewAvatars(deps AvatarsDeps) (*Avatars, error) {
	if deps.Store == nil {
		return nil, errors.New("profile/app: minting an avatar upload needs an object store")
	}
	return &Avatars{store: deps.Store}, nil
}

// Grant signs an upload target for exactly one object.
//
// # No image passes through this server, ever
//
// The browser POSTs the bytes straight to the object store. This process never
// reads, buffers, decodes or forwards them. That is a security decision before
// it is a performance one: an image arriving through the API would put a
// client-controlled decoder on the request path of every replica that could
// receive it, and would make the request-size limit a product setting rather
// than a hard bound enforced by storage.
//
// # What the signed policy pins
//
//	bucket               the grant cannot be redirected elsewhere
//	key                  WE choose it, under a prefix derived from the CALLER
//	content-length-range enforced by the store before storing — the property a
//	                     presigned PUT cannot give, and the reason this is a POST
//	Content-Type         the stored object cannot claim to be something else
//	expiration           a leaked capability stops working
//
// # The key is new every time
//
// blob.NewKey appends 16 random bytes to the prefix, so a replaced avatar is a
// new object and never an overwrite. Objects here are immutable — a new version
// is a new key plus a new event (ADR-013) — which is also what makes a
// half-finished upload harmless: it lands on a key nothing references.
//
// # It is a mutation, and the idempotency gate is why that matters
//
// Declaring this a read would make a double-clicked button mint two grants and
// leave one object abandoned in the bucket for a sweep to find. As a mutation it
// carries an idempotency key, so the retry returns the stored response — the
// SAME grant, for the same key.
func (a *Avatars) Grant(ctx context.Context, cmd UploadGrantCommand) (UploadGrant, error) {
	if err := requireSubject(cmd.SubjectID, "granting an avatar upload"); err != nil {
		return UploadGrant{}, err
	}
	if cmd.IdempotencyKey == "" {
		return UploadGrant{}, errs.ValidationFailedf("an idempotency key is required")
	}

	// Repeated from the schema deliberately, and for the reason the domain's own
	// comment gives: the schema constrains what a CLIENT may send, and this
	// constrains what this system will ever sign a policy for — including calls
	// that are not RPCs.
	if !slices.Contains(domain.AllowedAvatarTypes(), cmd.ContentType) {
		return UploadGrant{}, errs.ValidationFailedf(
			"an avatar must be one of %v", domain.AllowedAvatarTypes())
	}
	switch {
	case cmd.SizeBytes <= 0:
		return UploadGrant{}, errs.ValidationFailedf(
			"an avatar upload must declare how many bytes it will be")
	case cmd.SizeBytes > domain.MaxAvatarBytes:
		return UploadGrant{}, errs.ValidationFailedf(
			"an avatar may be at most %d bytes", domain.MaxAvatarBytes)
	}

	grant, err := a.store.GrantUpload(ctx, blob.UploadRequest{
		// THE binding. The prefix is derived from the caller's own pseudonym, so
		// the key this returns is inside their namespace and inside nobody
		// else's — which is what lets the confirm call accept a client-supplied
		// key without a token, a table or a secret (domain.AvatarPrefix).
		Prefix:      domain.AvatarPrefix(cmd.SubjectID),
		ContentType: cmd.ContentType,
		// The DECLARED size, not the ceiling: pinning the ceiling would let a
		// caller who declared 10 KiB store 5 MiB, which is the whole point of
		// asking.
		MaxBytes: cmd.SizeBytes,
		Expiry:   UploadGrantTTL,
	})
	if err != nil {
		if errors.Is(err, blob.ErrPolicyRefused) {
			// The store's own limits refused it — a smaller ceiling, or a
			// content-type allowlist narrower than this module's. Reported as a
			// validation failure because it is a fact about the request, and the
			// message is the store's, which names the limit rather than the
			// value.
			return UploadGrant{}, errs.ValidationFailedf("%v", err).Wrap(err)
		}
		return UploadGrant{}, errs.Internalf("granting an avatar upload").Wrap(err)
	}

	return UploadGrant{
		URL: grant.URL,
		// Sorted, so the same grant renders the same way twice and a client
		// diffing two responses sees a real difference rather than map ordering.
		Fields:    sortedFields(grant.Fields),
		ObjectKey: grant.Key.String(),
		Expires:   grant.Expires.UTC(),
		MaxBytes:  grant.MaxBytes,
	}, nil
}

func sortedFields(in map[string]string) []GrantField {
	out := make([]GrantField, 0, len(in))
	for k, v := range in {
		out = append(out, GrantField{Key: k, Value: v})
	}
	slices.SortFunc(out, func(a, b GrantField) int {
		switch {
		case a.Key < b.Key:
			return -1
		case a.Key > b.Key:
			return 1
		default:
			return 0
		}
	})
	return out
}
