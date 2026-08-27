// Package buildinfo answers one question for every binary in this tree: which
// build is this?
//
// It exists because the answer had three different homes. Each of cmd/api,
// cmd/worker and cmd/projector declared its own `var version = "dev"` with a
// comment describing an `-ldflags` invocation that no build actually passed, so
// every process reported `dev` — in its logs, in its `service.version` trace
// attribute, and in the GetStatus response the operator console reads. A
// version that is always the same string is not a version; a latency
// regression could not be attributed to a release, and a customer report could
// not be tied to the build that served it.
//
// One package means one link-time symbol. The Makefile stamps
// `-X github.com/chronos/chronos-go/internal/platform/buildinfo.version=…`
// once and every binary in ./cmd/... picks it up.
//
// # Never "dev" by accident
//
// An unstamped build still answers usefully. `go build` from inside a checkout
// records the VCS state (`-buildvcs=auto`) and Go synthesises a pseudo-version
// from it, so `air` and a bare `go build` report the commit and whether the tree
// was dirty. `go run` does NOT stamp, which is why the Makefile passes LDFLAGS
// to the `make run`, `make worker` and `make projector` targets too. Only a
// build with neither link-time flags nor VCS data — a `go test` binary, or a
// build from an extracted tarball — reports "dev", and there it is true rather
// than a default nobody noticed.
package buildinfo

import (
	"runtime/debug"
	"sync"
)

// version and commit are set at link time; see the Makefile's LDFLAGS. They are
// deliberately unexported and empty by default — an empty value means "not
// stamped", which is distinguishable from a stamped value that happens to be a
// placeholder.
var (
	version string
	commit  string
)

// devVersion is what an unstamped build outside a checkout reports.
const devVersion = "dev"

// resolved memoises the answer. Nothing here changes during a process's life,
// and ReadBuildInfo walks the binary's embedded tables on every call.
var resolved = sync.OnceValues(func() (string, string) {
	bi, ok := debug.ReadBuildInfo()
	return resolve(version, commit, bi, ok)
})

// Version is the release this binary was built from: a semver tag such as
// "v0.4.1" when stamped or installed from a tag, otherwise a commit-derived
// description, otherwise "dev".
func Version() string {
	v, _ := resolved()
	return v
}

// Commit is the full git revision this binary was built from, or "" when the
// build carried no VCS information.
func Commit() string {
	_, c := resolved()
	return c
}

// resolve is the whole policy, separated from the globals so it can be tested
// against inputs a test binary can never produce for itself.
func resolve(ldVersion, ldCommit string, bi *debug.BuildInfo, ok bool) (string, string) {
	var vcsRevision string
	var vcsModified bool
	if ok && bi != nil {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				vcsRevision = s.Value
			case "vcs.modified":
				vcsModified = s.Value == "true"
			}
		}
	}

	commit := ldCommit
	if commit == "" {
		commit = vcsRevision
	}

	version := ldVersion
	if version == "" {
		// `go install module@v1.2.3` records the tag here, and a plain `go build`
		// from a checkout records a pseudo-version derived from the commit. Only
		// "(devel)" — a build with no VCS data at all — says nothing a caller
		// wants, so it falls through to the revision below.
		if ok && bi != nil && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			version = bi.Main.Version
		}
	}
	if version == "" && vcsRevision != "" {
		version = shorten(vcsRevision)
		if vcsModified {
			version += "-dirty"
		}
	}
	if version == "" {
		version = devVersion
	}
	return version, commit
}

// shorten renders a git revision the way `git rev-parse --short` does, so a
// version printed by a binary can be pasted straight into a git command.
func shorten(rev string) string {
	const short = 12
	if len(rev) <= short {
		return rev
	}
	return rev[:short]
}

// String renders the build for a human: "v0.4.1 (278cd4729ff6)", or just the
// version when there is no commit to name.
func String() string {
	v, c := resolved()
	if c == "" {
		return v
	}
	return v + " (" + shorten(c) + ")"
}
