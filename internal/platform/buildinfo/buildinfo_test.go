package buildinfo

import (
	"runtime/debug"
	"testing"
)

// buildInfo assembles the shape debug.ReadBuildInfo returns, so the resolution
// policy can be tested against builds a test binary can never be.
func buildInfo(mainVersion string, settings map[string]string) *debug.BuildInfo {
	bi := &debug.BuildInfo{}
	bi.Main.Version = mainVersion
	for k, v := range settings {
		bi.Settings = append(bi.Settings, debug.BuildSetting{Key: k, Value: v})
	}
	return bi
}

func TestResolve(t *testing.T) {
	const rev = "278cd47ab3ce9f10122334455667788990aabbcc"

	cases := []struct {
		name        string
		ldVersion   string
		ldCommit    string
		bi          *debug.BuildInfo
		ok          bool
		wantVersion string
		wantCommit  string
	}{
		{
			name:        "link-time flags win over everything",
			ldVersion:   "v1.2.3",
			ldCommit:    rev,
			bi:          buildInfo("(devel)", map[string]string{"vcs.revision": "0000000000000000000000000000000000000000"}),
			ok:          true,
			wantVersion: "v1.2.3",
			wantCommit:  rev,
		},
		{
			name:        "go install module@tag reports the tag",
			bi:          buildInfo("v0.4.1", nil),
			ok:          true,
			wantVersion: "v0.4.1",
			wantCommit:  "",
		},
		{
			// The everyday case: `go run ./cmd/api` from a clean checkout.
			name:        "an unstamped build falls back to the revision",
			bi:          buildInfo("(devel)", map[string]string{"vcs.revision": rev, "vcs.modified": "false"}),
			ok:          true,
			wantVersion: "278cd47ab3ce",
			wantCommit:  rev,
		},
		{
			// A dirty tree must say so. A build that silently reports the last
			// commit while serving uncommitted code is how a bug gets attributed
			// to a release that never contained it.
			name:        "a modified tree is marked dirty",
			bi:          buildInfo("(devel)", map[string]string{"vcs.revision": rev, "vcs.modified": "true"}),
			ok:          true,
			wantVersion: "278cd47ab3ce-dirty",
			wantCommit:  rev,
		},
		{
			name:        "no flags and no VCS data is honestly dev",
			bi:          buildInfo("", nil),
			ok:          true,
			wantVersion: devVersion,
			wantCommit:  "",
		},
		{
			name:        "absent build info does not panic",
			ok:          false,
			wantVersion: devVersion,
			wantCommit:  "",
		},
		{
			// `-X …commit=` alone, which is what a build outside a checkout can
			// still pass. The version is derived from nothing, so it stays dev,
			// but the commit must survive.
			name:        "a stamped commit without a stamped version is kept",
			ldCommit:    rev,
			bi:          buildInfo("", nil),
			ok:          true,
			wantVersion: devVersion,
			wantCommit:  rev,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotVersion, gotCommit := resolve(tc.ldVersion, tc.ldCommit, tc.bi, tc.ok)
			if gotVersion != tc.wantVersion {
				t.Errorf("version: got %q want %q", gotVersion, tc.wantVersion)
			}
			if gotCommit != tc.wantCommit {
				t.Errorf("commit: got %q want %q", gotCommit, tc.wantCommit)
			}
		})
	}
}

// The exported surface must never hand back an empty string: it is written into
// a trace attribute and a status response, and an empty version there reads as
// a broken deployment rather than an unstamped build.
func TestVersionIsNeverEmpty(t *testing.T) {
	if Version() == "" {
		t.Fatal("Version() returned an empty string")
	}
}
