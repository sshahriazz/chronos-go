// Package seaweedfs implements object storage over the S3 API.
//
// The upload path is a signed POST policy, built here by hand: the AWS SDK has
// no POST-policy presigner, and POST is the only presign form whose size limit
// is enforced BY THE STORAGE SERVICE rather than checked afterwards. Everything
// else — verification, downloads, deletion — uses the official SDK.
package seaweedfs

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/chronos/chronos-go/internal/platform/blob"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/codec"
)

// Config describes the object store.
type Config struct {
	Endpoint  string
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string

	// PublicEndpoint is the address a BROWSER can reach, which differs from the
	// one this process uses whenever the store is behind a container network or
	// a CDN. Getting this wrong produces grants that work from the server and
	// fail from every browser — so it defaults to Endpoint rather than to
	// something plausible-looking.
	PublicEndpoint string

	Limits blob.Limits
}

// Store issues upload grants and reads objects back.
type Store struct {
	client *s3.Client
	cfg    Config
	clock  clock.Clock
}

var _ blob.Store = (*Store)(nil)

func New(cfg Config, clk clock.Clock) *Store {
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if cfg.PublicEndpoint == "" {
		cfg.PublicEndpoint = cfg.Endpoint
	}
	if clk == nil {
		clk = clock.System{}
	}
	client := s3.New(s3.Options{
		Region:      cfg.Region,
		Credentials: credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, ""),
		// SeaweedFS addresses buckets by path, not by virtual host.
		BaseEndpoint: aws.String(cfg.Endpoint),
		UsePathStyle: true,
	})
	return &Store{client: client, cfg: cfg, clock: clk}
}

// GrantUpload signs a POST policy for exactly one object.
//
// What the policy pins, and why each matters:
//
//	bucket               the grant cannot be redirected to another bucket
//	key                  WE choose the key, so the client cannot overwrite
//	                     another object by naming it
//	content-length-range enforced by the storage service before storing —
//	                     the property a presigned PUT cannot give
//	Content-Type         the stored object cannot claim to be something else
//	expiration           a grant is a capability; a leaked one should expire
func (s *Store) GrantUpload(ctx context.Context, req blob.UploadRequest) (blob.Grant, error) {
	if err := s.cfg.Limits.Check(req); err != nil {
		return blob.Grant{}, err
	}

	key, err := blob.NewKey(req.Prefix)
	if err != nil {
		return blob.Grant{}, err
	}

	now := s.clock.Now().UTC()
	expires := now.Add(req.Expiry)
	date := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")
	credential := fmt.Sprintf("%s/%s/%s/s3/aws4_request", s.cfg.AccessKey, date, s.cfg.Region)

	policy := map[string]any{
		"expiration": expires.Format("2006-01-02T15:04:05Z"),
		"conditions": []any{
			map[string]string{"bucket": s.cfg.Bucket},
			// Exact match, not starts-with: the client gets the key we chose
			// and cannot pick its own.
			map[string]string{"key": key.String()},
			map[string]string{"Content-Type": req.ContentType},
			// A minimum of one byte as well as a maximum: a zero-byte upload
			// looks like success and is not.
			[]any{"content-length-range", 1, req.MaxBytes},
			map[string]string{"x-amz-credential": credential},
			map[string]string{"x-amz-algorithm": signingAlgorithm},
			map[string]string{"x-amz-date": amzDate},
		},
	}
	// SeaweedFS parses these bytes, so the shape matters — but every map and
	// slice above is built here and non-nil, so the v2 rendering of a nil
	// slice as `[]` rather than v1's `null` cannot arise and NullEmpty would
	// change nothing. The deterministic key order is a bonus rather than a
	// requirement: the signature covers the base64 of exactly these bytes, so
	// any order verifies, but a stable one makes a rejected policy comparable
	// between two runs.
	raw, err := codec.Marshal(policy)
	if err != nil {
		return blob.Grant{}, fmt.Errorf("seaweedfs: encoding upload policy: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(raw)

	return blob.Grant{
		URL: strings.TrimRight(s.cfg.PublicEndpoint, "/") + "/" + s.cfg.Bucket,
		Fields: map[string]string{
			"key":              key.String(),
			"Content-Type":     req.ContentType,
			"x-amz-credential": credential,
			"x-amz-algorithm":  signingAlgorithm,
			"x-amz-date":       amzDate,
			"policy":           encoded,
			"x-amz-signature":  sign(s.cfg.SecretKey, date, s.cfg.Region, encoded),
		},
		Key:      key,
		Expires:  expires,
		MaxBytes: req.MaxBytes,
	}, nil
}

// Verify reads an object's real metadata.
//
// The client's word that it uploaded is a claim; this is the check. Nothing here
// comes from the uploader.
func (s *Store) Verify(ctx context.Context, key blob.Key) (blob.Object, error) {
	out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.cfg.Bucket),
		Key:    aws.String(key.String()),
	})
	if err != nil {
		if isNotFound(err) {
			// Expected for a grant that was issued and never used.
			return blob.Object{}, fmt.Errorf("%w: %s", blob.ErrNotFound, key)
		}
		return blob.Object{}, fmt.Errorf("seaweedfs: reading %s: %w", key, err)
	}

	obj := blob.Object{
		Key:         key,
		Size:        aws.ToInt64(out.ContentLength),
		ContentType: aws.ToString(out.ContentType),
		ETag:        strings.Trim(aws.ToString(out.ETag), `"`),
	}
	if out.LastModified != nil {
		obj.ModifiedAt = out.LastModified.UTC()
	}
	return obj, nil
}

// GrantDownload returns a short-lived read URL.
//
// Presigned rather than public: a bucket that serves anonymous reads has moved
// authorisation from OpenFGA to whoever holds the link, and links are pasted
// into chat.
func (s *Store) GrantDownload(ctx context.Context, key blob.Key, expiry time.Duration) (string, error) {
	if expiry <= 0 {
		return "", fmt.Errorf("%w: a positive expiry is required", blob.ErrPolicyRefused)
	}
	if s.cfg.Limits.MaxExpiry > 0 && expiry > s.cfg.Limits.MaxExpiry {
		return "", fmt.Errorf("%w: an expiry of %s exceeds the maximum of %s",
			blob.ErrPolicyRefused, expiry, s.cfg.Limits.MaxExpiry)
	}

	out, err := s3.NewPresignClient(s.client).PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.cfg.Bucket),
		Key:    aws.String(key.String()),
	}, s3.WithPresignExpires(expiry))
	if err != nil {
		return "", fmt.Errorf("seaweedfs: signing download for %s: %w", key, err)
	}
	return swapHost(out.URL, s.cfg.Endpoint, s.cfg.PublicEndpoint), nil
}

// Delete removes an object.
//
// Objects are otherwise immutable — a new version is a new key and a new event
// — so this serves erasure and the cleanup of grants that were never used.
// Deleting something already gone is not an error: erasure must be idempotent.
func (s *Store) Delete(ctx context.Context, key blob.Key) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.cfg.Bucket),
		Key:    aws.String(key.String()),
	})
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("seaweedfs: deleting %s: %w", key, err)
	}
	return nil
}

// Put writes an object the SERVER produced.
//
// # Why this exists when every other upload is a grant
//
// The two-call grant flow exists because the bytes come from a BROWSER: the
// server must never receive them, so it signs a policy and the client POSTs
// direct. A portability bundle has no browser in it — the server built the bytes
// from the vault — so a grant would mean signing a policy for ourselves and then
// making an HTTP request to satisfy it.
//
// It is deliberately NOT part of the grant path and takes no UploadRequest: this
// cannot be reached by a caller-chosen key or a caller-supplied content type,
// because there is no caller. Both arguments come from the code that produced
// the bytes.
func (s *Store) Put(
	ctx context.Context, key blob.Key, body []byte, contentType string,
) error {
	switch {
	case key == "":
		return fmt.Errorf("seaweedfs: a key is required")
	case len(body) == 0:
		// An empty object is almost always a serialization that failed quietly,
		// and for an export it would be a bundle a person is told is their data.
		return fmt.Errorf("seaweedfs: refusing to store an empty object at %s", key)
	case contentType == "":
		return fmt.Errorf("seaweedfs: a content type is required")
	}

	if _, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.cfg.Bucket),
		Key:         aws.String(key.String()),
		Body:        bytes.NewReader(body),
		ContentType: aws.String(contentType),
		// The LENGTH is passed explicitly. Without it the SDK streams with a
		// chunked encoding some S3 implementations reject, and SeaweedFS is one
		// of the implementations worth not finding that out from.
		ContentLength: aws.Int64(int64(len(body))),
	}); err != nil {
		return fmt.Errorf("seaweedfs: storing %s: %w", key, err)
	}
	return nil
}

// MaxReadBytes bounds what Get will read into memory.
//
// The only caller reads an export MANIFEST, which is JSON describing a person's
// profile fields and a bounded list of object keys. A megabyte is far above any
// manifest this system produces and far below anything that could exhaust a
// worker — and the bound is a REFUSAL rather than a truncation, because half a
// manifest decodes into a shorter file list and would silently hand somebody an
// incomplete answer to Article 15.
const MaxReadBytes = 1 << 20

// Get reads an object's bytes.
//
// # It is deliberately NOT on blob.Store
//
// Every other method on that interface hands out a CAPABILITY — a presigned
// upload, a presigned download — or reads metadata. This reads the bytes, which
// for this bucket means reading somebody's personal data directly into a
// process. Putting it on the shared port would give every holder of a blob.Store
// that ability by default; leaving it here means a caller has to declare a
// narrow port of its own and the composition root has to hand this in
// explicitly, which is one place to notice.
//
// Its one caller is the export poll, reading back the manifest it is about to
// hand to the person the manifest is about.
func (s *Store) Get(ctx context.Context, key blob.Key) ([]byte, error) {
	if key == "" {
		return nil, fmt.Errorf("seaweedfs: a key is required")
	}
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.cfg.Bucket),
		Key:    aws.String(key.String()),
	})
	if err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("%w: %s", blob.ErrNotFound, key)
		}
		return nil, fmt.Errorf("seaweedfs: reading %s: %w", key, err)
	}
	defer func() { _ = out.Body.Close() }()

	// LIMITED, and one byte over the bound is read on purpose: reading exactly
	// MaxReadBytes cannot tell "exactly at the limit" from "truncated here", and
	// the two need different answers.
	body, err := io.ReadAll(io.LimitReader(out.Body, MaxReadBytes+1))
	if err != nil {
		return nil, fmt.Errorf("seaweedfs: reading the body of %s: %w", key, err)
	}
	if len(body) > MaxReadBytes {
		return nil, fmt.Errorf("seaweedfs: %s is larger than %d bytes", key, MaxReadBytes)
	}
	return body, nil
}

// ListPrefix returns every key under one prefix.
//
// # Why this pages rather than trusting one call
//
// S3 truncates a listing at 1000 keys and hands back a continuation token,
// whether or not the caller asked it to. A single ListObjectsV2 that ignored
// `IsTruncated` would return the first page and look complete — and the caller
// is an erasure, so "looked complete" means a person's objects survive their own
// deletion with nothing anywhere reporting it.
//
// # And why the limit is a refusal
//
// Hitting it returns ErrTooManyObjects and NO KEYS. Returning what was found so
// far would let the caller delete a prefix partially and report success, which
// is the one outcome worse than failing: a partial erasure is indistinguishable
// from a complete one afterwards.
func (s *Store) ListPrefix(ctx context.Context, prefix string, limit int) ([]blob.Key, error) {
	switch {
	case prefix == "":
		// An empty prefix lists the WHOLE BUCKET, which for an erasure would mean
		// every tenant's objects. Refused rather than passed through.
		return nil, fmt.Errorf("seaweedfs: a prefix is required; an empty one lists every " +
			"object in the bucket")
	case limit <= 0:
		return nil, fmt.Errorf("seaweedfs: a positive limit is required, got %d", limit)
	}

	var keys []blob.Key
	var token *string
	for {
		out, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            aws.String(s.cfg.Bucket),
			Prefix:            aws.String(prefix),
			ContinuationToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("seaweedfs: listing %s: %w", prefix, err)
		}
		for _, obj := range out.Contents {
			if obj.Key == nil {
				continue
			}
			keys = append(keys, blob.Key(*obj.Key))
			if len(keys) > limit {
				return nil, fmt.Errorf("%w: %s holds more than %d",
					blob.ErrTooManyObjects, prefix, limit)
			}
		}
		if out.IsTruncated == nil || !*out.IsTruncated {
			return keys, nil
		}
		token = out.NextContinuationToken
		if token == nil {
			// Truncated with no token is a server that cannot be paged. Reported
			// rather than treated as the end, because treating it as the end is
			// exactly the silent-partial-listing failure above.
			return nil, fmt.Errorf("seaweedfs: listing %s was truncated with no "+
				"continuation token", prefix)
		}
	}
}

// ListPage returns one page of objects under a prefix, with a cursor.
//
// The export's listing, and the counterpart to ListPrefix above: where that one
// REFUSES past its bound because a truncated erasure is a failed erasure, this
// hands back a continuation token because a truncated export page is simply the
// next unit of resumable work (compliance.md §5).
//
// It returns S3's own continuation token unchanged. The caller treats it as
// opaque, which is what lets a workflow carry it across a restart without
// depending on how this store happens to page.
func (s *Store) ListPage(
	ctx context.Context, prefix, after string, limit int,
) (blob.Page, error) {
	switch {
	case prefix == "":
		// As ListPrefix: an empty prefix lists the WHOLE BUCKET, which here would
		// put another tenant's objects into somebody's data export.
		return blob.Page{}, fmt.Errorf("seaweedfs: a prefix is required; an empty one " +
			"lists every object in the bucket")
	case limit <= 0:
		return blob.Page{}, fmt.Errorf("seaweedfs: a positive limit is required, got %d", limit)
	}

	in := &s3.ListObjectsV2Input{
		Bucket: aws.String(s.cfg.Bucket),
		Prefix: aws.String(prefix),
		// CLAMPED rather than converted. S3 caps a page at 1000 anyway, so a
		// caller asking for more gets 1000 either way — and clamping is what stops
		// an oversized int from wrapping negative on the way into int32, which
		// would ask the store for a nonsensical page size.
		MaxKeys: aws.Int32(clampPageSize(limit)),
	}
	if after != "" {
		in.ContinuationToken = aws.String(after)
	}

	out, err := s.client.ListObjectsV2(ctx, in)
	if err != nil {
		return blob.Page{}, fmt.Errorf("seaweedfs: listing %s: %w", prefix, err)
	}

	page := blob.Page{Objects: make([]blob.Object, 0, len(out.Contents))}
	for _, obj := range out.Contents {
		if obj.Key == nil {
			continue
		}
		o := blob.Object{Key: blob.Key(*obj.Key)}
		if obj.Size != nil {
			o.Size = *obj.Size
		}
		if obj.ETag != nil {
			o.ETag = *obj.ETag
		}
		if obj.LastModified != nil {
			// UTC, like every other instant this system stores (ADR-008). The SDK
			// hands back whatever zone the response carried.
			o.ModifiedAt = obj.LastModified.UTC()
		}
		// ContentType is NOT in a listing — S3 does not return it — and it is left
		// empty rather than guessed from the key. A guessed type in a portability
		// manifest is a claim about somebody's data that nothing verified, and the
		// key deliberately carries no meaning to guess from (CLAUDE.md).
		page.Objects = append(page.Objects, o)
	}
	// TRUNCATION is what decides whether there is a cursor, not the token being
	// present: S3 may return a token on a final page, and treating that as "more
	// to come" would make the caller loop once more for an empty page every time.
	if out.IsTruncated != nil && *out.IsTruncated && out.NextContinuationToken != nil {
		page.Cursor = *out.NextContinuationToken
	}
	return page, nil
}

// EnsureBucket creates the bucket if it does not exist. Startup convenience for
// development; production provisions storage separately.
func (s *Store) EnsureBucket(ctx context.Context) error {
	_, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(s.cfg.Bucket)})
	if err == nil {
		return nil
	}
	if _, err := s.client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(s.cfg.Bucket),
	}); err != nil {
		return fmt.Errorf("seaweedfs: creating bucket %s: %w", s.cfg.Bucket, err)
	}
	return nil
}

const signingAlgorithm = "AWS4-HMAC-SHA256"

// sign derives the SigV4 signing key and signs the encoded policy.
func sign(secret, date, region, policy string) string {
	k := hmacSHA([]byte("AWS4"+secret), date)
	k = hmacSHA(k, region)
	k = hmacSHA(k, "s3")
	k = hmacSHA(k, "aws4_request")
	return hex.EncodeToString(hmacSHA(k, policy))
}

func hmacSHA(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// swapHost rewrites an internal endpoint to the browser-reachable one. The
// signature covers the path and query, not the host, so this is safe.
func swapHost(url, internal, public string) string {
	if internal == public || internal == "" {
		return url
	}
	return strings.Replace(url, strings.TrimRight(internal, "/"), strings.TrimRight(public, "/"), 1)
}

func isNotFound(err error) bool {
	if _, ok := errors.AsType[*s3types.NoSuchKey](err); ok {
		return true
	}
	if _, ok := errors.AsType[*s3types.NotFound](err); ok {
		return true
	}
	// SeaweedFS answers a HEAD on a missing object with a bare 404 that the SDK
	// does not always map to a typed error.
	return strings.Contains(err.Error(), "StatusCode: 404")
}

// clampPageSize bounds a requested page into what S3 accepts.
//
// BOTH ends, and the lower one is not defensive noise: without it the conversion
// below is a plain int→int32 narrowing that can wrap, and a wrapped page size
// asks the store for a nonsensical listing. The caller already refuses a
// non-positive limit; this makes the property local to the conversion rather
// than an argument about a caller three lines away.
func clampPageSize(limit int) int32 {
	const maxKeys = 1000
	switch {
	case limit < 1:
		return 1
	case limit > maxKeys:
		return maxKeys
	default:
		return int32(limit)
	}
}
