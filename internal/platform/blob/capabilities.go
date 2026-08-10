package blob

import (
	"fmt"
	"slices"
	"time"
)

// S3 protocol constants. They are not ours to choose, and getting them wrong
// produces uploads that fail only for large files — the ones users care most
// about.
const (
	// MinPartSize is the smallest permitted part except the last. A part below
	// this is rejected at completion, after every byte has been transferred.
	MinPartSize int64 = 5 << 20 // 5 MiB

	// MaxParts is the ceiling on parts in one multipart upload.
	MaxParts = 10_000
)

// Capabilities is what the storage layer permits, in a form the FRONTEND can
// read before it tries anything.
//
// Published deliberately. Without it the browser learns the rules by having an
// upload rejected — after transferring the file — and the user is told "failed"
// with no way to know a 50 MB video was never going to be accepted. With it the
// picker can filter, the size can be checked locally, and the error arrives
// before the wait rather than after it.
type Capabilities struct {
	// MaxBytes is the largest single object.
	MaxBytes int64 `json:"maxBytes"`

	// MaxBatchCount is how many objects one request may be granted. It bounds
	// both the work of signing and the number of orphaned grants one caller can
	// create.
	MaxBatchCount int `json:"maxBatchCount"`

	// AllowedContentTypes is the allow-list. Empty means any type, which suits
	// internal exports and never suits user uploads.
	AllowedContentTypes []string `json:"allowedContentTypes"`

	// ResumableThreshold is the size at or above which a client should use the
	// resumable path. Below it, a single POST is simpler and a failed upload is
	// cheap to repeat.
	ResumableThreshold int64 `json:"resumableThreshold"`

	// PartSize is the size the client should cut parts at.
	PartSize int64 `json:"partSize"`

	// MaxParts bounds one resumable upload.
	MaxParts int `json:"maxParts"`

	// GrantExpiry is how long a grant stays usable.
	GrantExpiry time.Duration `json:"-"`

	// GrantExpirySeconds is the JSON form: a browser has no notion of a Go
	// duration, and serialising nanoseconds invites a client to divide by the
	// wrong constant.
	GrantExpirySeconds int `json:"grantExpirySeconds"`
}

// Limits configures the store.
type Limits struct {
	MaxBytes            int64
	MaxBatchCount       int
	AllowedContentTypes []string
	ResumableThreshold  int64
	PartSize            int64
	MaxExpiry           time.Duration
}

// Defaults fills anything unset with a working, conservative value, and rejects
// combinations that could only fail later.
//
// Validated rather than trusted, because every one of these mistakes produces a
// failure that appears only for large files or only under load: a part size
// below the S3 minimum works for a two-part upload and fails for a three-part
// one; a threshold below the part size makes the resumable path allocate a
// single undersized part that is rejected at completion.
func (l Limits) Defaults() (Limits, error) {
	if l.MaxBytes <= 0 {
		l.MaxBytes = 100 << 20 // 100 MiB
	}
	if l.MaxBatchCount <= 0 {
		l.MaxBatchCount = 20
	}
	if l.PartSize <= 0 {
		l.PartSize = 8 << 20 // 8 MiB — comfortably above the 5 MiB minimum
	}
	if l.ResumableThreshold <= 0 {
		// The part size, not a round number chosen independently: a threshold
		// below the part size means the resumable path can produce a single
		// undersized part, which S3 rejects at completion. Defaulting them to
		// the same value makes the two impossible to set inconsistently by
		// omission — which is how this went wrong the first time.
		l.ResumableThreshold = l.PartSize
	}
	if l.MaxExpiry <= 0 {
		l.MaxExpiry = 15 * time.Minute
	}

	switch {
	case l.PartSize < MinPartSize:
		return l, fmt.Errorf("%w: part size %d is below the S3 minimum of %d; every "+
			"upload of more than one part would be rejected at completion",
			ErrPolicyRefused, l.PartSize, MinPartSize)

	case l.ResumableThreshold < l.PartSize:
		return l, fmt.Errorf("%w: the resumable threshold (%d) is below the part size (%d), "+
			"so a resumable upload could consist of one undersized part",
			ErrPolicyRefused, l.ResumableThreshold, l.PartSize)

	case l.MaxBytes/l.PartSize > int64(MaxParts):
		return l, fmt.Errorf("%w: %d bytes at a part size of %d needs more than the %d "+
			"parts S3 allows; raise the part size",
			ErrPolicyRefused, l.MaxBytes, l.PartSize, MaxParts)
	}
	return l, nil
}

// Capabilities renders the limits for a client.
func (l Limits) Capabilities() Capabilities {
	return Capabilities{
		MaxBytes:            l.MaxBytes,
		MaxBatchCount:       l.MaxBatchCount,
		AllowedContentTypes: l.AllowedContentTypes,
		ResumableThreshold:  l.ResumableThreshold,
		PartSize:            l.PartSize,
		MaxParts:            MaxParts,
		GrantExpiry:         l.MaxExpiry,
		GrantExpirySeconds:  int(l.MaxExpiry.Seconds()),
	}
}

// Allows reports whether a content type is permitted. Exposed so an API can
// answer the frontend's "may I upload this?" without attempting it.
func (l Limits) Allows(contentType string) bool {
	if len(l.AllowedContentTypes) == 0 {
		return true
	}
	return slices.Contains(l.AllowedContentTypes, contentType)
}

// PartsFor reports how many parts a file of this size needs.
func (l Limits) PartsFor(size int64) int {
	if size <= 0 {
		return 0
	}
	n := (size + l.PartSize - 1) / l.PartSize
	return int(n)
}

// NeedsResumable reports whether a file should use the multipart path.
func (l Limits) NeedsResumable(size int64) bool { return size >= l.ResumableThreshold }

// CheckBatch validates a batch request before anything is signed.
func (l Limits) CheckBatch(reqs []UploadRequest) error {
	if len(reqs) == 0 {
		return fmt.Errorf("%w: an empty batch", ErrPolicyRefused)
	}
	if len(reqs) > l.MaxBatchCount {
		return fmt.Errorf("%w: %d objects exceeds the batch limit of %d",
			ErrPolicyRefused, len(reqs), l.MaxBatchCount)
	}
	for i, req := range reqs {
		if err := l.Check(req); err != nil {
			return fmt.Errorf("object %d: %w", i, err)
		}
	}
	return nil
}
