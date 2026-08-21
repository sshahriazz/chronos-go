package app

import (
	"context"
	"errors"
	"time"

	"github.com/chronos/chronos-go/internal/platform/blob"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// AvatarURLTTL is how long a signed avatar URL stays valid.
//
// Short, because the URL IS the authorisation: anyone holding it can read the
// object until it expires, and links are pasted into chat. Long enough that a
// page which loads the profile and then renders the image does not race its own
// URL.
//
// It must stay at or below the object store's configured MaxExpiry, which
// refuses anything longer (blob.Limits.Check). The default there is fifteen
// minutes.
const AvatarURLTTL = 10 * time.Minute

// AvatarView is an avatar as a client receives it: a URL, never bytes.
type AvatarView struct {
	URL         string
	ContentType string
	SizeBytes   int64
	URLExpires  time.Time
}

// IsZero reports the absence of an avatar.
func (a AvatarView) IsZero() bool { return a.URL == "" }

// Profile is one person's profile, assembled from the two places it lives: the
// projection, which holds the non-personal facts, and the PII vault, which
// holds the values.
//
// This struct is the ONLY place those two meet, and it exists to be turned
// straight into a response. Nothing stores it, logs it or puts it on an event.
type Profile struct {
	SubjectID   string
	DisplayName string
	Locale      string
	Timezone    string
	Avatar      AvatarView
	UpdatedAt   time.Time
}

// Queries is profile's read side.
type Queries struct {
	reader  Reader
	vault   SubjectVault
	avatars AvatarStore
	clock   func() time.Time
}

// QueriesDeps is what the read side needs.
type QueriesDeps struct {
	Reader  Reader
	Vault   SubjectVault
	Avatars AvatarStore

	// Now is used only to report when a signed URL expires. Injected so a test
	// can assert the expiry the client is told matches the one the signature
	// carries.
	Now func() time.Time
}

// NewQueries builds the read side, refusing a partial one.
func NewQueries(deps QueriesDeps) (*Queries, error) {
	switch {
	case deps.Reader == nil:
		return nil, errors.New("profile/app: the read side needs a projection reader")
	case deps.Vault == nil:
		// Refused rather than tolerated as "the name is optional". A nil here
		// serves GetProfile with a panic, and this is the only endpoint through
		// which a person can see the name others read for them.
		return nil, errors.New("profile/app: the read side needs the PII vault; the " +
			"display name, locale and timezone live there and nowhere else")
	case deps.Avatars == nil:
		return nil, errors.New("profile/app: the read side needs an object store to sign " +
			"avatar URLs with; a stored object key is not a URL")
	}
	if deps.Now == nil {
		deps.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Queries{
		reader: deps.Reader, vault: deps.Vault, avatars: deps.Avatars, clock: deps.Now,
	}, nil
}

// Get returns one person's own profile.
//
// # An absent profile is not an error
//
// Every account has a profile the moment it exists, in the sense that every
// account HAS a display name — it is simply empty until they set one. Returning
// NOT_FOUND for an account that has never opened the settings screen would make
// the client branch on a distinction that is not one.
//
// # An erased subject is not an error either
//
// Erasure destroyed the key, so there is nothing left to decrypt and the fields
// come back empty. That is the correct outcome rather than a failure, and it is
// the same reading NOTIFICATIONS §4 gives: a subject who exercised erasure has
// no name, and reporting that as an error would make every replay of an erased
// subject a paging alert.
func (q *Queries) Get(ctx context.Context, subjectID string) (Profile, error) {
	if err := requireSubject(subjectID, "reading a profile"); err != nil {
		return Profile{}, err
	}

	view, err := q.reader.View(ctx, subjectID)
	if err != nil {
		return Profile{}, errs.Internalf("reading a profile").Wrap(err)
	}

	out := Profile{SubjectID: subjectID, UpdatedAt: view.UpdatedAt}

	stored, err := q.vault.Profile(ctx, pii.SubjectID(subjectID))
	switch {
	case errors.Is(err, pii.ErrErased), errors.Is(err, pii.ErrNoSubject):
		// Nothing to resolve. Left empty rather than reported: see above.
	case err != nil:
		// The vault may genuinely be unreachable, which is retryable and must
		// NOT be reported as "this person has no name" — a caller that saw the
		// empty answer would render it as a profile with the name removed.
		return Profile{}, errs.Internalf("resolving a profile").Wrap(err)
	default:
		out.DisplayName = stored.Get(pii.FieldName)
		out.Locale = stored.Get(pii.FieldLocale)
		out.Timezone = stored.Get(pii.FieldTimezone)
	}

	if !view.Avatar.IsZero() {
		avatar, err := q.signAvatar(ctx, view)
		if err != nil {
			return Profile{}, err
		}
		out.Avatar = avatar
	}
	return out, nil
}

// signAvatar turns a stored object key into a time-limited URL.
//
// A failure here fails the whole read, deliberately. Presigning is a LOCAL
// operation — the SDK computes a signature and contacts nothing — so it cannot
// fail because the object store is down; it fails only on input this server
// produced. Degrading to "no avatar" would therefore hide a bug behind a
// perfectly plausible-looking profile.
func (q *Queries) signAvatar(ctx context.Context, view View) (AvatarView, error) {
	url, err := q.avatars.GrantDownload(ctx, blob.Key(view.Avatar.ObjectKey), AvatarURLTTL)
	if err != nil {
		// The key is not in the message: it is in the URL a client will see, but
		// an error body is a different audience from the person whose avatar it
		// is.
		return AvatarView{}, errs.Internalf("signing an avatar URL").Wrap(err)
	}
	return AvatarView{
		URL:         url,
		ContentType: view.Avatar.ContentType,
		SizeBytes:   view.Avatar.SizeBytes,
		URLExpires:  q.clock().UTC().Add(AvatarURLTTL),
	}, nil
}
