package blob_test

import (
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/blob"
)

// A policy pins the LABEL, not the contents. A client can declare image/png and
// upload HTML, which then sits at a URL our own domain serves — so what the
// bytes actually are has to be compared against what was claimed.
func TestTypesAgree(t *testing.T) {
	cases := []struct {
		declared, sniffed string
		want              bool
		why               string
	}{
		{"image/png", "image/png", true, "exact match"},
		{"image/png", "image/png; charset=binary", true, "parameters are not part of the type"},
		{"application/json", "text/plain; charset=utf-8", true, "JSON has no magic bytes"},
		{"text/csv", "text/plain; charset=utf-8", true, "CSV sniffs as text"},
		{"application/octet-stream", "text/plain; charset=utf-8", true, "a generic declaration claims nothing"},
		{"application/octet-stream", "image/png", true, "still claims nothing"},

		// The cases that matter.
		{"image/png", "text/html; charset=utf-8", false, "HTML uploaded as an image is stored XSS"},
		{"image/png", "application/zip", false, "an archive uploaded as an image"},
		{"image/jpeg", "image/png", false, "a different image format is still a mismatch"},
	}

	for _, tc := range cases {
		t.Run(tc.why, func(t *testing.T) {
			if got := blob.TypesAgree(tc.declared, tc.sniffed); got != tc.want {
				t.Errorf("TypesAgree(%q, %q) = %v, want %v — %s",
					tc.declared, tc.sniffed, got, tc.want, tc.why)
			}
		})
	}
}

// Keys appear in URLs. One that encodes the tenant leaks that tenant's
// structure; one that encodes a filename invites path traversal.
func TestKeysAreOpaqueAndUnguessable(t *testing.T) {
	seen := map[blob.Key]struct{}{}
	for range 500 {
		k, err := blob.NewKey("avatar")
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[k]; dup {
			t.Fatalf("generated the same key twice: %s", k)
		}
		seen[k] = struct{}{}
		if !strings.HasPrefix(string(k), "avatar/") {
			t.Fatalf("key %q lost its prefix", k)
		}
		if strings.ContainsAny(strings.TrimPrefix(string(k), "avatar/"), "/.") {
			t.Fatalf("key %q contains a path separator", k)
		}
	}
}

func TestKeyPrefixCannotTraverse(t *testing.T) {
	for _, bad := range []string{"../etc", "a/b", "x."} {
		if _, err := blob.NewKey(bad); err == nil {
			t.Errorf("prefix %q was accepted; it can escape the intended namespace", bad)
		}
	}
}

// These are the mistakes that only fail for LARGE files, or only under load —
// the ones a developer never hits locally.
func TestLimitsRejectInconsistentConfiguration(t *testing.T) {
	t.Run("part size below the S3 minimum", func(t *testing.T) {
		_, err := blob.Limits{PartSize: 1 << 20, ResumableThreshold: 10 << 20}.Defaults()
		if err == nil {
			t.Fatal("a part size under 5 MiB makes every multi-part upload fail at completion")
		}
	})

	t.Run("threshold below the part size", func(t *testing.T) {
		_, err := blob.Limits{PartSize: 8 << 20, ResumableThreshold: 1 << 20}.Defaults()
		if err == nil {
			t.Fatal("a resumable upload could then consist of one undersized part")
		}
	})

	t.Run("too many parts for the maximum size", func(t *testing.T) {
		_, err := blob.Limits{MaxBytes: 1 << 40, PartSize: 5 << 20, ResumableThreshold: 5 << 20}.Defaults()
		if err == nil {
			t.Fatal("1 TiB at 5 MiB parts needs more than the 10,000 parts S3 allows")
		}
	})

	t.Run("defaults are self-consistent", func(t *testing.T) {
		l, err := blob.Limits{}.Defaults()
		if err != nil {
			t.Fatalf("the defaults must be usable as they stand: %v", err)
		}
		if l.ResumableThreshold < l.PartSize {
			t.Error("the default threshold is below the default part size")
		}
	})
}

func TestBatchLimit(t *testing.T) {
	l, _ := blob.Limits{MaxBatchCount: 3, AllowedContentTypes: []string{"image/png"}}.Defaults()
	req := blob.UploadRequest{
		Prefix: "a", ContentType: "image/png", MaxBytes: 1 << 20, Expiry: time.Minute,
	}

	if err := l.CheckBatch([]blob.UploadRequest{req, req, req}); err != nil {
		t.Fatalf("a batch at the limit must be allowed: %v", err)
	}
	if err := l.CheckBatch([]blob.UploadRequest{req, req, req, req}); err == nil {
		t.Fatal("a batch over the limit must be refused before anything is signed")
	}
	if err := l.CheckBatch(nil); err == nil {
		t.Fatal("an empty batch is a client bug, not a no-op")
	}
}

// The comparison a caller must make before recording an upload as complete.
func TestObjectMatches(t *testing.T) {
	req := blob.UploadRequest{ContentType: "image/png", MaxBytes: 1 << 20}

	if err := (blob.Object{Size: 1024, ContentType: "image/png"}).Matches(req); err != nil {
		t.Errorf("a conforming object must match: %v", err)
	}
	if err := (blob.Object{Size: 0, ContentType: "image/png"}).Matches(req); err == nil {
		t.Error("a zero-byte object looks like success and is not")
	}
	if err := (blob.Object{Size: 2 << 20, ContentType: "image/png"}).Matches(req); err == nil {
		t.Error("an object over the granted size must be refused")
	}
	if err := (blob.Object{Size: 10, ContentType: "text/html"}).Matches(req); err == nil {
		t.Error("an object whose type differs from the grant must be refused")
	}
}

func TestPartsFor(t *testing.T) {
	l, _ := blob.Limits{PartSize: 8 << 20, ResumableThreshold: 8 << 20}.Defaults()
	for _, tc := range []struct {
		size int64
		want int
	}{
		{0, 0},
		{1, 1},
		{8 << 20, 1},
		{(8 << 20) + 1, 2},
		{9 << 20, 2},
	} {
		if got := l.PartsFor(tc.size); got != tc.want {
			t.Errorf("PartsFor(%d) = %d, want %d", tc.size, got, tc.want)
		}
	}
}
