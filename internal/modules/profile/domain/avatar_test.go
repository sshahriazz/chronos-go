package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/profile/domain"
	"github.com/chronos/chronos-go/internal/platform/blob"
)

const otherSubject = "subj_01BX5ZZKBKACTAV9WEVGEMMVRZ"

// TestAvatarPrefixIsPerSubjectAndOpaque is the property the whole confirm path
// rests on: two people can never be issued keys under one prefix, and the
// prefix does not contain the pseudonym it was derived from.
func TestAvatarPrefixIsPerSubjectAndOpaque(t *testing.T) {
	t.Parallel()

	mine := domain.AvatarPrefix(subject)
	theirs := domain.AvatarPrefix(otherSubject)

	if mine == theirs {
		t.Fatal("two subjects share one avatar prefix, so either could confirm the " +
			"other's uploads")
	}
	if mine != domain.AvatarPrefix(subject) {
		t.Fatal("the prefix is not stable, so a key minted by one call could not be " +
			"confirmed by the next")
	}
	if strings.Contains(mine, subject) {
		t.Fatalf("the prefix %q contains the pseudonym; an object key appears in a "+
			"browser's network tab, a proxy log and a screenshot", mine)
	}
	// blob.NewKey refuses a prefix containing a path separator, precisely so a
	// caller cannot smuggle a second path component into a key. Asserted here
	// because AvatarPrefix is the only thing this system ever passes it.
	if _, err := blob.NewKey(mine); err != nil {
		t.Fatalf("blob.NewKey(%q) = %v; the prefix must be a legal single path segment", mine, err)
	}
}

// TestParseAvatarKeyRefusesAnotherSubjectsKey is THE authorization test for the
// two-phase upload.
//
// A key is chosen by the server and handed to the client, and the client hands
// one back. Without this refusal, a caller could name a key that is not theirs
// and the profile endpoint would sign a download URL for it — turning a settings
// screen into a read primitive for the whole bucket.
func TestParseAvatarKeyRefusesAnotherSubjectsKey(t *testing.T) {
	t.Parallel()

	theirKey, err := blob.NewKey(domain.AvatarPrefix(otherSubject))
	if err != nil {
		t.Fatalf("minting the other subject's key: %v", err)
	}

	// It parses perfectly well for the person it was issued to...
	if _, err := domain.ParseAvatarKey(otherSubject, theirKey.String()); err != nil {
		t.Fatalf("the owner cannot confirm their own key: %v", err)
	}
	// ...and not at all for anybody else.
	if _, err := domain.ParseAvatarKey(subject, theirKey.String()); err == nil {
		t.Fatal("one subject confirmed another subject's object key")
	} else if !errors.Is(err, domain.ErrAvatarRefused) {
		t.Fatalf("ParseAvatarKey = %v, want it to wrap ErrAvatarRefused", err)
	}
}

func TestParseAvatarKeyRefusals(t *testing.T) {
	t.Parallel()

	mine := domain.AvatarPrefix(subject)
	tests := []struct {
		name string
		key  string
		why  string
	}{
		{
			name: "empty",
			key:  "",
			why:  "removal is a separate decision, not a key that failed to parse",
		},
		{
			name: "no prefix at all",
			key:  "aaaaaaaaaaaaaaaaaaaaaaaaaa",
			why:  "an unprefixed key is outside every subject's namespace",
		},
		{
			name: "path traversal in the name",
			key:  mine + "/../../etc/passwd",
			why:  "the name is concatenated into a URL path; '/' and '.' must never survive",
		},
		{
			name: "percent-encoding in the name",
			key:  mine + "/%2e%2e%2fsecret",
			why:  "the same, one decoding layer further out",
		},
		{
			name: "name from outside the key alphabet",
			key:  mine + "/AAAAAAAAAAAAAAAAAAAAAAAAAA",
			why:  "blob.NewKey emits a 32-character lowercase alphabet and nothing else",
		},
		{
			name: "name too short to be random",
			key:  mine + "/aaa",
			why:  "a short name is guessable, and nothing this server mints is short",
		},
		{
			name: "absurdly long",
			key:  mine + "/" + strings.Repeat("a", 200),
			why:  "an unbounded key is an unbounded column and an unbounded URL",
		},
		{
			name: "a second path component",
			key:  mine + "/aaaaaaaaaaaaaaaaaaaaaaaaaa/more",
			why:  "the key names exactly one object; a second component names a different one",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := domain.ParseAvatarKey(subject, tt.key); err == nil {
				t.Fatalf("ParseAvatarKey(%q) was accepted, want a refusal (%s)", tt.key, tt.why)
			}
		})
	}
}

// TestNewAvatarValidatesWhatTheStoreReports is the "the store's word, not the
// uploader's" rule. Everything here arrives from HeadObject.
func TestNewAvatarValidatesWhatTheStoreReports(t *testing.T) {
	t.Parallel()

	const key = "avatarx/aaaaaaaaaaaaaaaaaaaaaaaaaa"

	t.Run("accepts a stored png", func(t *testing.T) {
		t.Parallel()
		got, err := domain.NewAvatar(key, "image/png", 1024)
		if err != nil {
			t.Fatalf("NewAvatar: %v", err)
		}
		if got.ContentType != "image/png" || got.SizeBytes != 1024 || got.ObjectKey != key {
			t.Fatalf("NewAvatar = %+v", got)
		}
	})

	t.Run("tolerates a media-type parameter", func(t *testing.T) {
		t.Parallel()
		got, err := domain.NewAvatar(key, "image/JPEG; charset=binary", 10)
		if err != nil {
			t.Fatalf("NewAvatar: %v; refusing a good object over a parameter nothing "+
				"reads is a bug, not strictness", err)
		}
		if got.ContentType != "image/jpeg" {
			t.Fatalf("ContentType = %q, want the base type lowercased", got.ContentType)
		}
	})

	refusals := []struct {
		name        string
		contentType string
		size        int64
		why         string
	}{
		{
			name: "empty object", contentType: "image/png", size: 0,
			why: "the signature of an abandoned upload; it renders as a broken image forever",
		},
		{
			name: "over the ceiling", contentType: "image/png", size: domain.MaxAvatarBytes + 1,
			why: "the store enforces this too, and this is the check that survives a store " +
				"which did not honour the policy",
		},
		{
			name: "svg", contentType: "image/svg+xml", size: 10,
			why: "SVG is a document format that executes script; serving one from an origin " +
				"a session is scoped to is stored cross-site scripting",
		},
		{
			name: "html wearing an image name", contentType: "text/html", size: 10,
			why: "the store reported what it actually holds, and it is not an image",
		},
	}
	for _, tt := range refusals {
		t.Run("refuses/"+tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := domain.NewAvatar(key, tt.contentType, tt.size); err == nil {
				t.Fatalf("NewAvatar(%q, %d) was accepted, want a refusal (%s)",
					tt.contentType, tt.size, tt.why)
			} else if !errors.Is(err, domain.ErrAvatarRefused) {
				t.Fatalf("NewAvatar = %v, want it to wrap ErrAvatarRefused", err)
			}
		})
	}
}
