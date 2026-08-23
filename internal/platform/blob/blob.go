// Package blob is the object storage kernel.
//
// One rule shapes all of it: USER BYTES NEVER REACH THIS SERVER. A browser
// uploads straight to the storage service, and this application only ever issues
// a grant beforehand and records a reference afterwards.
//
// That is not only about bandwidth. A server that proxies uploads has to buffer
// or stream untrusted bytes of unknown size, becomes the place a malicious file
// is decompressed or sniffed, and turns every upload into a request that can be
// held open. Keeping the bytes out entirely removes that surface rather than
// defending it.
//
// The grant is a signed POST POLICY, not a presigned PUT. The difference is the
// security property that matters: a policy pins a CONTENT-LENGTH RANGE that the
// storage service enforces before it stores anything, so a grant for a 5 MB
// avatar cannot be used to upload 10 GB. A presigned PUT accepts whatever the
// client sends and can only be checked afterwards — by which point the bytes
// are already stored and paid for.
//
// Verified against the running SeaweedFS: a 32-byte body under a 64-byte policy
// is accepted (204); a 4 KB body under the same policy is rejected by the
// storage service with EntityTooLarge (400).
package blob

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Key identifies an object in the store.
//
// It is OPAQUE and carries no business meaning: not a tenant id, not a filename,
// not a content type (CLAUDE.md). Two reasons. A key that encodes the tenant
// leaks that tenant's structure to anyone who sees a URL, and a key that encodes
// a filename invites path traversal and unicode games in a namespace where they
// are hard to reason about. The mapping from object to tenant, filename and
// purpose lives in PostgreSQL, under row-level security, where it can be
// authorised.
type Key string

func (k Key) String() string { return string(k) }

// keyAlphabet is unpadded base32 without the ambiguous characters: keys appear
// in URLs and support tickets, and 0/O and 1/I/l get transcribed wrong.
var keyEncoding = base32.NewEncoding("abcdefghijkmnpqrstuvwxyz23456789").WithPadding(base32.NoPadding)

// NewKey generates an unguessable key.
//
// 128 bits of randomness, not a ULID: a ULID is time-ordered and therefore
// partly predictable, and while authorisation never depends on a key being
// secret, an enumerable namespace turns one leaked reference into a map of
// everything uploaded around the same moment.
func NewKey(prefix string) (Key, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("blob: generating key: %w", err)
	}
	name := keyEncoding.EncodeToString(b[:])
	if prefix == "" {
		return Key(name), nil
	}
	if strings.ContainsAny(prefix, "/.") {
		return "", fmt.Errorf("%w: prefix %q must not contain a path separator", ErrInvalidKey, prefix)
	}
	// A single flat level. Deep hierarchies in object storage buy nothing and
	// tempt people to encode meaning into the path.
	return Key(prefix + "/" + name), nil
}

// UploadRequest is what a caller asks for before a browser uploads.
type UploadRequest struct {
	// Prefix groups objects loosely for operational purposes — "avatar",
	// "export". It must carry no tenant or user identity.
	Prefix string

	// ContentType is pinned into the policy, so the stored object cannot claim
	// to be something else. An empty value is refused rather than defaulted:
	// "whatever the client says" is how an HTML file becomes an avatar and
	// then a stored XSS.
	ContentType string

	// MaxBytes is enforced BY THE STORAGE SERVICE before anything is stored.
	MaxBytes int64

	// Expiry bounds how long the grant is usable. Short by default: a grant is
	// a capability, and a leaked one is a write into our bucket.
	Expiry time.Duration
}

// Grant is what the browser needs to upload, and nothing more.
//
// Fields must be submitted verbatim as multipart form fields, with the file
// last — the storage service reads the policy before the body, and a file that
// arrives first cannot be checked against it.
type Grant struct {
	URL      string
	Fields   map[string]string
	Key      Key
	Expires  time.Time
	MaxBytes int64
}

// Object is what the store actually holds, read back from it.
//
// Every field here comes from the STORAGE SERVICE, never from the client. A
// caller compares these against what it granted; anything else is trusting the
// uploader to describe their own upload.
type Object struct {
	Key         Key
	Size        int64
	ContentType string
	ETag        string
	ModifiedAt  time.Time
}

// Store issues grants and reads back what was stored.
type Store interface {
	// GrantUpload returns a capability for one direct upload of one object.
	GrantUpload(ctx context.Context, req UploadRequest) (Grant, error)

	// Verify reads an object's real metadata from the store.
	//
	// This is what makes the design safe: a client saying "I uploaded it" is a
	// claim, and this is the check. Callers MUST call it before recording that
	// an upload succeeded, and must compare size and content type against what
	// they granted.
	Verify(ctx context.Context, key Key) (Object, error)

	// GrantDownload returns a short-lived read URL.
	//
	// Downloads are presigned too, never public: a bucket that serves anonymous
	// reads has moved authorisation from OpenFGA to whoever has the link.
	GrantDownload(ctx context.Context, key Key, expiry time.Duration) (string, error)

	// Delete removes an object. Objects are otherwise IMMUTABLE — a new version
	// is a new key and a new event (CLAUDE.md) — so this exists for erasure and
	// for cleaning up uploads that were granted and never completed.
	Delete(ctx context.Context, key Key) error

	// ListPrefix returns every key under one prefix.
	//
	// # It exists for erasure, and the shape follows from that
	//
	// Deleting a subject's objects cannot work from the read model alone. A
	// projection names the CURRENT avatar; an upload that was granted, completed
	// and then superseded leaves an object no row has mentioned since, and an
	// upload that was granted and never confirmed leaves one no row EVER
	// mentioned. Both are personal data, and both survive an erasure that only
	// deletes what a projection can see.
	//
	// A prefix works because the prefix is derived from the subject
	// (profile.AvatarPrefix), so this enumerates one person's objects rather
	// than scanning a bucket.
	//
	// BOUNDED, and the bound is a refusal rather than a page. A caller that
	// silently processed the first N would report a complete erasure having left
	// the rest, which is the failure this whole path exists to prevent —
	// implementations return ErrTooManyObjects instead.
	ListPrefix(ctx context.Context, prefix string, limit int) ([]Key, error)

	// ListPage returns ONE page of objects under a prefix, with a cursor.
	//
	// # Why this exists beside ListPrefix rather than replacing it
	//
	// The two answer different questions and fail in opposite directions.
	// ListPrefix is erasure's, and it REFUSES past its bound: an erasure that
	// silently processed the first N would report success having left personal
	// data behind, so "more than you allowed" must be an error there.
	//
	// This is the export's, and past its bound it hands back a CURSOR. An export
	// is resumable by design (compliance.md §5), so the caller's correct response
	// to "there is more" is to come back for it — and a workflow that carries the
	// cursor across a restart continues where it stopped instead of re-listing
	// from the beginning.
	//
	// It returns Objects rather than Keys because the export's manifest records
	// what each object IS — its size and its content type — and a second call per
	// object to Verify would turn one listing into N round trips.
	//
	// `after` is opaque and comes from a previous call's cursor. Empty starts at
	// the beginning. An empty cursor in the result means the listing is complete.
	ListPage(ctx context.Context, prefix, after string, limit int) (Page, error)
}

// Page is one result of ListPage.
type Page struct {
	// Objects are this page's contents, in the store's own order. That order is
	// stable for a given prefix, which is what makes the cursor meaningful.
	Objects []Object

	// Cursor resumes the listing. Empty means there is nothing after this page.
	//
	// Opaque on purpose: it is the store's own continuation token, and a caller
	// that parsed it would be depending on an implementation detail of whichever
	// S3 the deployment runs.
	Cursor string
}

var (
	// ErrNotFound means no object exists at that key. For an upload that was
	// granted but never completed this is the expected answer, not a failure.
	ErrNotFound = errors.New("blob: object not found")

	// ErrTooManyObjects means a prefix holds more than the caller allowed.
	//
	// Its own error because the caller's response is specific: an erasure that
	// hit this must FAIL rather than delete what it found, since a partial
	// deletion reported as success is indistinguishable from a complete one.
	ErrTooManyObjects = errors.New("blob: more objects under that prefix than the limit allows")

	// ErrInvalidKey means a key or prefix is malformed.
	ErrInvalidKey = errors.New("blob: invalid key")

	// ErrPolicyRefused means the request asked for something the policy will
	// not sign — an absent content type, a size beyond the ceiling.
	ErrPolicyRefused = errors.New("blob: upload policy refused")
)

// Check validates a request against the limits, before anything is signed.
func (l Limits) Check(req UploadRequest) error {
	switch {
	case req.ContentType == "":
		return fmt.Errorf("%w: a content type is required, so the stored object "+
			"cannot claim to be something else", ErrPolicyRefused)
	case req.MaxBytes <= 0:
		return fmt.Errorf("%w: a positive size limit is required", ErrPolicyRefused)
	case l.MaxBytes > 0 && req.MaxBytes > l.MaxBytes:
		return fmt.Errorf("%w: %d bytes exceeds the ceiling of %d",
			ErrPolicyRefused, req.MaxBytes, l.MaxBytes)
	case req.Expiry <= 0:
		return fmt.Errorf("%w: a positive expiry is required", ErrPolicyRefused)
	case l.MaxExpiry > 0 && req.Expiry > l.MaxExpiry:
		return fmt.Errorf("%w: an expiry of %s exceeds the maximum of %s",
			ErrPolicyRefused, req.Expiry, l.MaxExpiry)
	}

	if !l.Allows(req.ContentType) {
		return fmt.Errorf("%w: content type %q is not permitted", ErrPolicyRefused, req.ContentType)
	}
	return nil
}

// Matches reports whether a stored object is what was granted.
//
// The comparison a caller must make before recording an upload as complete.
// Size is checked as well as content type even though the policy pins both,
// because "the storage service enforced it" is an assumption worth verifying
// once per upload rather than trusting forever.
func (o Object) Matches(req UploadRequest) error {
	if o.Size > req.MaxBytes {
		return fmt.Errorf("blob: stored object is %d bytes, over the granted %d",
			o.Size, req.MaxBytes)
	}
	if o.Size == 0 {
		return errors.New("blob: stored object is empty")
	}
	if req.ContentType != "" && o.ContentType != req.ContentType {
		return fmt.Errorf("blob: stored object is %q, not the granted %q",
			o.ContentType, req.ContentType)
	}
	return nil
}

// ---------------------------------------------------------------------------
// resumable uploads
// ---------------------------------------------------------------------------

// ResumableGrant begins a multipart upload.
//
// Above the threshold a single POST is the wrong shape: one dropped connection
// at 90% means starting again, and mobile connections drop. Multipart lets the
// client retry ONE part, and it is the only S3 mechanism that does.
type ResumableGrant struct {
	Key      Key
	UploadID string
	PartSize int64
	Parts    int
	Expires  time.Time
}

// PartGrant is a capability to upload exactly one part.
//
// Parts are signed on demand rather than all at once: a 100 MB file is 13 parts,
// and signing every URL for every upload that might happen wastes work on the
// uploads that stall at part two.
type PartGrant struct {
	PartNumber int
	URL        string
	Expires    time.Time
}

// UploadedPart is what the client reports back after a part succeeds.
//
// The ETag comes from the storage service's response, not from the client's
// imagination — completion fails if it does not match what was stored, which is
// what stops a client claiming parts it never uploaded.
type UploadedPart struct {
	PartNumber int
	ETag       string
}

// Resumable is the multipart capability. Separate from Store because it is
// optional: a store that cannot do multipart is still a usable store for small
// objects, and the interface should say so rather than panic.
type Resumable interface {
	// BeginResumable starts a multipart upload for a file of a known size.
	BeginResumable(ctx context.Context, req UploadRequest, size int64) (ResumableGrant, error)

	// GrantParts signs URLs for specific part numbers, so a client can retry
	// one part without re-signing the rest.
	GrantParts(ctx context.Context, key Key, uploadID string, parts []int, expiry time.Duration) ([]PartGrant, error)

	// CompleteResumable assembles the parts into an object and returns what was
	// actually stored.
	CompleteResumable(ctx context.Context, key Key, uploadID string, parts []UploadedPart) (Object, error)

	// AbortResumable discards an incomplete upload and its parts.
	//
	// Not optional housekeeping: abandoned parts occupy storage indefinitely and
	// are invisible in an object listing, so nothing else will ever find them.
	AbortResumable(ctx context.Context, key Key, uploadID string) error

	// AbandonedUploads lists multipart uploads older than a cutoff, so a sweep
	// can abort what clients never finished.
	AbandonedUploads(ctx context.Context, olderThan time.Duration) ([]Abandoned, error)
}

// Abandoned is an incomplete upload nobody came back for.
type Abandoned struct {
	Key       Key
	UploadID  string
	StartedAt time.Time
}

// ---------------------------------------------------------------------------
// content inspection
// ---------------------------------------------------------------------------

// Detected is what an object actually contains, as opposed to what it claims.
type Detected struct {
	// Declared is the content type recorded at upload — the client's claim.
	Declared string

	// Sniffed is what the leading bytes actually look like.
	Sniffed string

	// Agrees reports whether the two describe the same kind of thing.
	Agrees bool
}

// Inspector reads the first bytes of an object to find out what it really is.
//
// Necessary precisely BECAUSE the bytes never pass through this server. The
// upload policy pins a content type, but a policy pins the LABEL, not the
// contents: a client can declare image/png and upload HTML, and that HTML then
// sits at a URL our own domain serves. Sniffing after the fact is the only place
// left to catch it.
//
// It reads a bounded window — 512 bytes, what http.DetectContentType uses — via
// a ranged GET, so inspecting a 100 MB file costs the same as inspecting a small
// one.
type Inspector interface {
	Inspect(ctx context.Context, key Key) (Detected, error)
}

// SniffWindow is how many bytes are read to identify content.
const SniffWindow = 512

// TypesAgree reports whether a sniffed type is consistent with a declared one.
//
// Not string equality: http.DetectContentType returns "image/png" for PNG but
// "text/plain; charset=utf-8" for text, and a JSON upload declared as
// application/json sniffs as text/plain because JSON has no magic bytes. Exact
// matching would reject correct uploads, so the comparison is on the type and
// subtype, with a text/* declaration accepted for anything that sniffs as text.
func TypesAgree(declared, sniffed string) bool {
	d := baseType(declared)
	s := baseType(sniffed)
	if d == s {
		return true
	}
	// A declared generic binary type claims nothing, so nothing can contradict
	// it. Checked FIRST: putting it last let the text/plain branch below return
	// early and report a disagreement for a declaration that made no claim.
	if d == "application/octet-stream" {
		return true
	}
	// Anything textual — JSON, CSV, XML, SVG — sniffs as text/plain, since none
	// of them carry magic bytes. Exact matching would reject correct uploads.
	if s == "text/plain" {
		return strings.HasPrefix(d, "text/") ||
			d == "application/json" || d == "application/xml" || d == "text/csv"
	}
	return false
}

func baseType(v string) string {
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	return strings.ToLower(strings.TrimSpace(v))
}
