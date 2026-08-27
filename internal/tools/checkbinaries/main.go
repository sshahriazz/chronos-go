// Command checkbinaries refuses to let a compiled executable be tracked in this
// repository.
//
// # Why .gitignore was not enough
//
// Nine executables — 180 MB of arm64 Mach-O, in a repository whose entire source
// is under 6 MB — were committed between 2026-08-10 and 2026-08-26. They are what
// `go build ./internal/tools/whoclaims` leaves behind when it is run from the
// repository root instead of `go run`, and `git add -A` swept them up.
//
// .gitignore already listed some of them. That does nothing: an ignore rule is
// not consulted for a path that is ALREADY tracked, so `/gendashboards` sat in
// .gitignore while `gendashboards` sat in the index, and every clone paid for it.
// GitHub warned on every push — "GH001: Large files detected" — and a warning
// that appears on a command nobody reads the output of is not a control.
//
// So the rule is enforced where every other rule in this repository is enforced:
// in `make check`, against the index rather than the working tree, because the
// index is what a commit is made from.
//
// Detection is by magic number, not by extension or size. A 200-byte ELF is
// still an executable, and a 40 MB vendored JavaScript file is still source.
//
// Exits non-zero if any tracked file is an executable.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	noColor := flag.Bool("no-color", false, "never colourize the report")
	flag.Parse()

	if err := run(os.Stdout, useColor(*noColor)); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "checkbinaries:", err)
		os.Exit(1)
	}
}

var errProblems = errors.New("compiled executables are tracked in this repository (see above)")

func run(w io.Writer, colour palette) error {
	if exec.CommandContext(context.Background(), "git", "rev-parse", "--git-dir").Run() != nil {
		// Not a violation: an exported tarball has no index to inspect. It is
		// reported rather than passed silently.
		printf(w, "  %sskip%s  not a git repository\n", colour.yellow, colour.reset)
		return nil //nolint:nilerr // there is no error here; Run() is a probe
	}

	paths, err := trackedFiles()
	if err != nil {
		return err
	}
	// Finding nothing to inspect is a failure, not a pass: it means the listing
	// broke, and an empty comparison satisfies every rule while proving nothing.
	if len(paths) == 0 {
		return errors.New("git listed no tracked files; refusing to report success on an empty set")
	}

	var found []string
	for _, path := range paths {
		kind, err := executableKind(path)
		if err != nil {
			// A tracked file missing from the working tree is somebody's
			// in-flight deletion, not a violation.
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		if kind != "" {
			found = append(found, fmt.Sprintf("%s (%s)", path, kind))
		}
	}

	if len(found) == 0 {
		printf(w, "  %sOK%s    %d tracked files, no executables\n", colour.green, colour.reset, len(paths))
		return nil
	}

	printf(w, "  %sFAIL%s  %d compiled executable(s) are tracked:\n", colour.red, colour.reset, len(found))
	for _, f := range found {
		printf(w, "          %s\n", f)
	}
	printf(w, "        Untrack it:   git rm --cached <path>\n")
	printf(w, "        Then ignore it, and build with `go run` or into ./bin.\n")
	return errProblems
}

// repoRoot is where the index lives. Without it the listing would be scoped to
// the caller's directory, so running the gate from anywhere but the root would
// inspect a subset and report OK — the silent-pass shape this repository has
// been bitten by more than once.
func repoRoot() (string, error) {
	cmd := exec.CommandContext(context.Background(), "git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git rev-parse --show-toplevel: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// trackedFiles lists every path in the index, as absolute paths.
func trackedFiles() ([]string, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	// root came from `git rev-parse` on this repository, not from a request.
	cmd := exec.CommandContext(context.Background(), "git", "-C", root, "ls-files", "-z") //nolint:gosec // G204: see above
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	var paths []string
	for _, p := range strings.Split(string(out), "\x00") {
		if p != "" {
			paths = append(paths, filepath.Join(root, p))
		}
	}
	return paths, nil
}

// magics are the leading bytes of the executable formats this repository could
// plausibly grow: Linux and macOS native, macOS universal, and Windows.
var magics = []struct {
	prefix []byte
	kind   string
}{
	{[]byte{0x7f, 'E', 'L', 'F'}, "ELF"},
	{le32(0xFEEDFACE), "Mach-O 32-bit"},
	{le32(0xFEEDFACF), "Mach-O 64-bit"},
	{be32(0xFEEDFACE), "Mach-O 32-bit, big-endian"},
	{be32(0xFEEDFACF), "Mach-O 64-bit, big-endian"},
	{be32(0xCAFEBABE), "Mach-O universal"},
	{be32(0xCAFEBABF), "Mach-O universal, 64-bit"},
	{[]byte{'M', 'Z'}, "PE"},
}

// executableKind names the executable format of a file, or "" if it is not one.
func executableKind(path string) (string, error) {
	// path comes from `git ls-files` on this repository — the set of files a
	// commit is made from, not anything a request supplies.
	f, err := os.Open(path) //nolint:gosec // G304: see above
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	header := make([]byte, 4)
	n, err := io.ReadFull(f, header)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	header = header[:n]

	for _, m := range magics {
		if bytes.HasPrefix(header, m.prefix) {
			// A Windows PE begins "MZ", and so does any text file starting with
			// those two letters. Require the file to be executable as well,
			// which every real PE in a git tree would be.
			if m.kind == "PE" && !isExecutableMode(path) {
				continue
			}
			return m.kind, nil
		}
	}
	return "", nil
}

func isExecutableMode(path string) bool {
	info, err := os.Stat(filepath.Clean(path))
	return err == nil && info.Mode().Perm()&0o111 != 0
}

func le32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func be32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

type palette struct{ green, red, yellow, reset string }

func useColor(disabled bool) palette {
	if disabled || os.Getenv("NO_COLOR") != "" {
		return palette{}
	}
	return palette{green: "\033[32m", red: "\033[31m", yellow: "\033[33m", reset: "\033[0m"}
}

// printf writes the report. The destination is an os.File or a test buffer;
// neither has a failure this gate could act on.
func printf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}
