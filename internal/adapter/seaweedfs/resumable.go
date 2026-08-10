package seaweedfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/chronos/chronos-go/internal/platform/blob"
)

var (
	_ blob.Resumable = (*Store)(nil)
	_ blob.Inspector = (*Store)(nil)
)

// BeginResumable starts a multipart upload.
//
// Verified against the running SeaweedFS: parts uploaded to presigned URLs with
// no credentials, completed into a single object of the expected size.
func (s *Store) BeginResumable(
	ctx context.Context, req blob.UploadRequest, size int64,
) (blob.ResumableGrant, error) {
	if err := s.cfg.Limits.Check(req); err != nil {
		return blob.ResumableGrant{}, err
	}
	if size <= 0 {
		return blob.ResumableGrant{}, fmt.Errorf("%w: a resumable upload needs a known size",
			blob.ErrPolicyRefused)
	}
	if size > req.MaxBytes {
		return blob.ResumableGrant{}, fmt.Errorf("%w: %d bytes exceeds the granted %d",
			blob.ErrPolicyRefused, size, req.MaxBytes)
	}

	parts := s.cfg.Limits.PartsFor(size)
	if parts > blob.MaxParts {
		return blob.ResumableGrant{}, fmt.Errorf("%w: %d parts exceeds the limit of %d",
			blob.ErrPolicyRefused, parts, blob.MaxParts)
	}

	key, err := blob.NewKey(req.Prefix)
	if err != nil {
		return blob.ResumableGrant{}, err
	}

	out, err := s.client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket:      aws.String(s.cfg.Bucket),
		Key:         aws.String(key.String()),
		ContentType: aws.String(req.ContentType),
	})
	if err != nil {
		return blob.ResumableGrant{}, fmt.Errorf("seaweedfs: beginning resumable upload: %w", err)
	}

	return blob.ResumableGrant{
		Key:      key,
		UploadID: aws.ToString(out.UploadId),
		PartSize: s.cfg.Limits.PartSize,
		Parts:    parts,
		Expires:  s.clock.Now().UTC().Add(req.Expiry),
	}, nil
}

// GrantParts signs URLs for specific parts.
//
// Signed on demand so a client that loses one part re-signs one URL, and so a
// stalled upload has not already cost us thirteen signatures.
func (s *Store) GrantParts(
	ctx context.Context, key blob.Key, uploadID string, parts []int, expiry time.Duration,
) ([]blob.PartGrant, error) {
	if uploadID == "" {
		return nil, fmt.Errorf("%w: an upload id is required", blob.ErrInvalidKey)
	}
	if expiry <= 0 || (s.cfg.Limits.MaxExpiry > 0 && expiry > s.cfg.Limits.MaxExpiry) {
		return nil, fmt.Errorf("%w: expiry must be positive and at most %s",
			blob.ErrPolicyRefused, s.cfg.Limits.MaxExpiry)
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("%w: no parts requested", blob.ErrPolicyRefused)
	}

	ps := s3.NewPresignClient(s.client)
	out := make([]blob.PartGrant, 0, len(parts))
	expires := s.clock.Now().UTC().Add(expiry)

	for _, n := range parts {
		// Part numbers are 1-based in S3. A zero here signs a URL the storage
		// service rejects, and the client discovers it only after transferring.
		if n < 1 || n > blob.MaxParts {
			return nil, fmt.Errorf("%w: part number %d is outside 1..%d",
				blob.ErrPolicyRefused, n, blob.MaxParts)
		}
		pres, err := ps.PresignUploadPart(ctx, &s3.UploadPartInput{
			Bucket:     aws.String(s.cfg.Bucket),
			Key:        aws.String(key.String()),
			UploadId:   aws.String(uploadID),
			PartNumber: aws.Int32(int32(n)), //nolint:gosec // bounded above
		}, s3.WithPresignExpires(expiry))
		if err != nil {
			return nil, fmt.Errorf("seaweedfs: signing part %d: %w", n, err)
		}
		out = append(out, blob.PartGrant{
			PartNumber: n,
			URL:        swapHost(pres.URL, s.cfg.Endpoint, s.cfg.PublicEndpoint),
			Expires:    expires,
		})
	}
	return out, nil
}

// CompleteResumable assembles the parts.
//
// Parts are sorted before submission: S3 requires ascending part numbers and
// rejects the whole upload otherwise, and a client reporting parts as they
// finish reports them out of order.
func (s *Store) CompleteResumable(
	ctx context.Context, key blob.Key, uploadID string, parts []blob.UploadedPart,
) (blob.Object, error) {
	if len(parts) == 0 {
		return blob.Object{}, fmt.Errorf("%w: no parts to complete", blob.ErrPolicyRefused)
	}
	sorted := make([]blob.UploadedPart, len(parts))
	copy(sorted, parts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PartNumber < sorted[j].PartNumber })

	completed := make([]s3types.CompletedPart, 0, len(sorted))
	for i, p := range sorted {
		if p.ETag == "" {
			return blob.Object{}, fmt.Errorf("%w: part %d has no etag", blob.ErrPolicyRefused, p.PartNumber)
		}
		if i > 0 && sorted[i-1].PartNumber == p.PartNumber {
			return blob.Object{}, fmt.Errorf("%w: part %d reported twice",
				blob.ErrPolicyRefused, p.PartNumber)
		}
		completed = append(completed, s3types.CompletedPart{
			ETag:       aws.String(p.ETag),
			PartNumber: aws.Int32(int32(p.PartNumber)), //nolint:gosec // validated on grant
		})
	}

	if _, err := s.client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:          aws.String(s.cfg.Bucket),
		Key:             aws.String(key.String()),
		UploadId:        aws.String(uploadID),
		MultipartUpload: &s3types.CompletedMultipartUpload{Parts: completed},
	}); err != nil {
		return blob.Object{}, fmt.Errorf("seaweedfs: completing resumable upload: %w", err)
	}

	// Read back what was actually stored. The client reported the parts; this
	// is the store's own account of the result.
	return s.Verify(ctx, key)
}

// AbortResumable discards an incomplete upload.
func (s *Store) AbortResumable(ctx context.Context, key blob.Key, uploadID string) error {
	if _, err := s.client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(s.cfg.Bucket),
		Key:      aws.String(key.String()),
		UploadId: aws.String(uploadID),
	}); err != nil && !isNotFound(err) {
		return fmt.Errorf("seaweedfs: aborting resumable upload: %w", err)
	}
	return nil
}

// AbandonedUploads lists incomplete uploads older than a cutoff.
//
// Abandoned parts occupy storage indefinitely and never appear in an object
// listing, so nothing else will ever find them. A periodic sweep is the only
// thing that will.
func (s *Store) AbandonedUploads(ctx context.Context, olderThan time.Duration) ([]blob.Abandoned, error) {
	cutoff := s.clock.Now().UTC().Add(-olderThan)

	out, err := s.client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
		Bucket: aws.String(s.cfg.Bucket),
	})
	if err != nil {
		return nil, fmt.Errorf("seaweedfs: listing incomplete uploads: %w", err)
	}

	var abandoned []blob.Abandoned
	for _, u := range out.Uploads {
		if u.Initiated == nil || u.Initiated.After(cutoff) {
			continue
		}
		abandoned = append(abandoned, blob.Abandoned{
			Key:       blob.Key(aws.ToString(u.Key)),
			UploadID:  aws.ToString(u.UploadId),
			StartedAt: u.Initiated.UTC(),
		})
	}
	return abandoned, nil
}

// Inspect reads the leading bytes to find out what an object really is.
//
// A ranged read, so inspecting a 100 MB file costs the same as a small one. This
// is the only place a mislabelled upload can be caught: the policy pins the
// LABEL, and the bytes never pass through this server.
func (s *Store) Inspect(ctx context.Context, key blob.Key) (blob.Detected, error) {
	head, err := s.Verify(ctx, key)
	if err != nil {
		return blob.Detected{}, err
	}

	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.cfg.Bucket),
		Key:    aws.String(key.String()),
		Range:  aws.String(fmt.Sprintf("bytes=0-%d", blob.SniffWindow-1)),
	})
	if err != nil {
		if isNotFound(err) {
			return blob.Detected{}, fmt.Errorf("%w: %s", blob.ErrNotFound, key)
		}
		return blob.Detected{}, fmt.Errorf("seaweedfs: reading %s for inspection: %w", key, err)
	}
	defer func() { _ = out.Body.Close() }()

	buf := make([]byte, blob.SniffWindow)
	n, err := io.ReadFull(out.Body, buf)
	// A short read is expected: an object smaller than the sniff window fills
	// the buffer partially, which is exactly the case for a small avatar.
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return blob.Detected{}, fmt.Errorf("seaweedfs: reading sniff window: %w", err)
	}

	sniffed := http.DetectContentType(buf[:n])
	return blob.Detected{
		Declared: head.ContentType,
		Sniffed:  sniffed,
		Agrees:   blob.TypesAgree(head.ContentType, sniffed),
	}, nil
}
