package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ErrAvatarRefused is an avatar this system will not record.
var ErrAvatarRefused = errors.New("profile: avatar refused")

// MaxAvatarBytes is the ceiling the signed upload policy pins and the stored
// object is re-checked against.
//
// Checked TWICE on purpose. The object store enforces it before a byte is
// stored, because the grant carries a content-length-range — that is the whole
// reason the upload is a POST rather than a presigned PUT. This constant is the
// second check, applied to what the store says it actually holds, so a store
// that did not honour the policy cannot put an unbounded object behind a
// profile.
const MaxAvatarBytes int64 = 5 << 20 // 5 MiB

// AllowedAvatarTypes is every media type an avatar may be.
//
// A closed list, and a short one. Each entry is a format every browser decodes
// natively, so nothing here needs a decoder on the server — which matters,
// because the server never decodes an avatar at all and this list is what keeps
// that true. SVG is deliberately absent: it is a document format that executes
// script, and serving one from an origin a session cookie is scoped to is
// stored cross-site scripting with a picture frame around it.
//
// The wire schema declares the same three in `CreateAvatarUploadRequest`, and
// TestSchemaAndDomainAgreeOnAvatarTypes asserts the two lists are identical —
// so a type added to one and not the other fails the build rather than becoming
// an upload the schema permits and the domain refuses.
func AllowedAvatarTypes() []string {
	return []string{"image/png", "image/jpeg", "image/webp"}
}

// Avatar is a validated reference to a stored image.
//
// A type rather than three loose fields, so that "checked" is carried by the
// value instead of by the reader's memory of which call site checked it.
type Avatar struct {
	ObjectKey   string
	ContentType string
	SizeBytes   int64
}

// IsZero reports the absence of an avatar, which is also what a removal leaves.
func (a Avatar) IsZero() bool { return a.ObjectKey == "" }

// AvatarPrefix is the object-store prefix every one of a subject's avatars
// lives under.
//
// # This is the whole authorization story for the confirm call, and it is
// structural rather than a check
//
// The upload is two calls: the server mints a signed target, the browser POSTs
// to the object store, and the browser then tells the server which key it used.
// That last step hands the server a key CHOSEN BY THE CLIENT, and the obvious
// failure is a caller naming somebody else's object — or worse, naming an
// object that is not an avatar at all and getting a signed download URL for it
// out of the profile endpoint.
//
// Deriving the prefix from the caller's own pseudonym removes the question
// rather than answering it. GrantUpload only ever signs a policy for a key the
// SERVER chose under the CALLER's prefix, and the confirm call recomputes the
// same prefix from the same session-derived pseudonym. There is no key a caller
// can name outside their own namespace that will be accepted, and there is no
// stored state, no token and no secret to leak, rotate or forget.
//
// Three alternatives were considered and each is worse:
//
//   - A server-side table of outstanding grants. That is a write to PostgreSQL
//     from a request handler, which this system does not do (ADR-019), and it
//     would need its own expiry sweep.
//   - An HMAC-signed grant token returned to the client and handed back. It
//     works, but it introduces key material that has to be configured, rotated
//     and kept out of logs — to buy a property the prefix already gives.
//   - A key derived from the subject with no random part. That would make
//     re-uploading OVERWRITE the stored object, and objects here are immutable:
//     a new version is a new key plus a new event (ADR-013).
//
// # Why it is a digest rather than the pseudonym
//
// An object key is visible to anything that can see a signed URL, including a
// browser's network tab, a proxy log and a screenshot. A pseudonym in it would
// travel further than the pseudonym is meant to. The digest is one-way and
// keyed by nothing, so it is not a secret — it is simply not a re-usable
// identifier for the person, which is all it needs to be.
//
// The result is [a-z0-9] only, which is what keeps it a legal single path
// segment for blob.NewKey — that function refuses a prefix containing '/' or
// '.' precisely so a caller cannot smuggle a second path component into it.
func AvatarPrefix(subjectID string) string {
	sum := sha256.Sum256([]byte("chronos.profile.avatar\x00" + subjectID))
	return "avatar" + hex.EncodeToString(sum[:16])
}

// ParseAvatarKey checks that an object key names an avatar minted for THIS
// subject, and returns it normalised.
//
// The empty string is NOT accepted here: "remove my avatar" is a different
// decision and is expressed by the caller, not by a key that failed to parse.
func ParseAvatarKey(subjectID, key string) (string, error) {
	switch {
	case subjectID == "":
		return "", fmt.Errorf("%w: no subject to check it against", ErrAvatarRefused)
	case key == "":
		return "", fmt.Errorf("%w: it names no object", ErrAvatarRefused)
	case len(key) > 128:
		return "", fmt.Errorf("%w: it is %d bytes", ErrAvatarRefused, len(key))
	}

	prefix, name, ok := strings.Cut(key, "/")
	if !ok {
		return "", fmt.Errorf("%w: it is not an object key this server issues", ErrAvatarRefused)
	}
	// A plain comparison, not a constant-time one. The expected value is derived
	// from the CALLER'S OWN pseudonym, so the only thing a timing difference
	// could leak to them is a value they already hold.
	if prefix != AvatarPrefix(subjectID) {
		// The message does not say whose it is, or that it exists. A caller who
		// guessed another subject's prefix learns only that this one is not
		// theirs.
		return "", fmt.Errorf("%w: it was not issued to this account", ErrAvatarRefused)
	}
	if name == "" {
		return "", fmt.Errorf("%w: it names no object", ErrAvatarRefused)
	}
	// blob.NewKey renders 16 random bytes in a 32-character lowercase alphabet
	// with no padding, so a legitimate name is 26 characters from that set and
	// nothing else. Checked rather than assumed: this string is concatenated
	// into a URL path, and a name carrying '/', '.' or '%' is how a key becomes
	// a traversal.
	for _, r := range name {
		if !strings.ContainsRune("abcdefghijkmnpqrstuvwxyz23456789", r) {
			return "", fmt.Errorf("%w: it is not an object key this server issues", ErrAvatarRefused)
		}
	}
	if len(name) < 20 || len(name) > 48 {
		return "", fmt.Errorf("%w: it is not an object key this server issues", ErrAvatarRefused)
	}
	return key, nil
}

// NewAvatar validates what the OBJECT STORE reports about a stored object and
// returns the reference to record.
//
// contentType and sizeBytes come from the store's own answer, never from the
// request: an uploader that lied about either is caught here rather than
// believed. That is why this takes them as arguments instead of taking the
// upload request back again.
func NewAvatar(objectKey, contentType string, sizeBytes int64) (Avatar, error) {
	// The base type only. A store may report `image/jpeg; charset=binary`, and
	// refusing that would reject a perfectly good object over a parameter
	// nothing reads.
	base := contentType
	if i := strings.IndexByte(base, ';'); i >= 0 {
		base = base[:i]
	}
	base = strings.ToLower(strings.TrimSpace(base))

	switch {
	case objectKey == "":
		return Avatar{}, fmt.Errorf("%w: it names no object", ErrAvatarRefused)
	case sizeBytes <= 0:
		// An empty object behind a profile renders as a broken image forever,
		// and it is the signature of an upload that was abandoned partway.
		return Avatar{}, fmt.Errorf("%w: the stored object is empty", ErrAvatarRefused)
	case sizeBytes > MaxAvatarBytes:
		return Avatar{}, fmt.Errorf("%w: the stored object is %d bytes, over the %d-byte limit",
			ErrAvatarRefused, sizeBytes, MaxAvatarBytes)
	case !slices.Contains(AllowedAvatarTypes(), base):
		return Avatar{}, fmt.Errorf("%w: the stored object is %q, which is not one of %v",
			ErrAvatarRefused, base, AllowedAvatarTypes())
	}
	return Avatar{ObjectKey: objectKey, ContentType: base, SizeBytes: sizeBytes}, nil
}
