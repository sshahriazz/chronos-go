// Package seaweedfs implements object storage over the S3 API.
//
// The upload path is a signed POST policy, built here by hand: the AWS SDK has
// no POST-policy presigner, and POST is the only presign form whose size limit
// is enforced BY THE STORAGE SERVICE rather than checked afterwards. Everything
// else — verification, downloads, deletion — uses the official SDK.
package seaweedfs

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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
	var nsk *s3types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	var nf *s3types.NotFound
	if errors.As(err, &nf) {
		return true
	}
	// SeaweedFS answers a HEAD on a missing object with a bare 404 that the SDK
	// does not always map to a typed error.
	return strings.Contains(err.Error(), "StatusCode: 404")
}
