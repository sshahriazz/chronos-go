// Command checkchangelog enforces that a change a customer can observe arrives
// with the sentence the customer will read.
//
// # Why a gate and not a convention
//
// A changelog assembled at release time is written by whoever cuts the release,
// from commit subjects, weeks after the fact. That person did not make the
// change and cannot describe its effect, so the entries degrade into restated
// commit messages — which in this repository are deliberately written for
// engineers ("half of every API key minted could never authenticate") and are
// the wrong sentence for a customer. The only moment the right sentence is
// cheap to write is while the change is being made.
//
// So the rule is: a pull request that touches the wire contract, a module, a
// migration or a service binary must add a fragment under .changes/unreleased/,
// or state explicitly that it needs none with a `Changelog: none` trailer on
// one of its commits. Refactors, tests, docs, generated code and internal tools
// are exempt by path — padding a public changelog with work nobody outside can
// observe makes it useless.
//
// # It also validates what it finds
//
// Every fragment is checked against .changie.yaml itself, not against a copy of
// its rules: an unknown kind, an unknown domain, an empty body or a body that
// is obviously a pasted commit subject fails here rather than at release, when
// the author has moved on.
//
// Exits non-zero on any problem. Skips, loudly, only when there is no git
// repository or no base branch to compare against — never silently.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

func main() {
	base := flag.String("base", os.Getenv("CHANGELOG_BASE_REF"), "git ref to compare against; empty means autodetect")
	config := flag.String("config", ".changie.yaml", "the changie configuration the fragments must satisfy")
	dir := flag.String("dir", ".changes/unreleased", "where unreleased fragments live")
	noColor := flag.Bool("no-color", false, "never colourize the report")
	flag.Parse()

	if err := run(os.Stdout, *config, *dir, *base, useColor(*noColor)); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "checkchangelog:", err)
		os.Exit(1)
	}
}

// errProblems is returned when the tree is readable but wrong. The report has
// already been printed; main only needs the exit code.
var errProblems = errors.New("the changelog does not describe this change (see above)")

func run(w io.Writer, configPath, dir, base string, colour palette) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	fragments, err := readFragments(dir)
	if err != nil {
		return err
	}

	problems := validate(w, cfg, fragments, colour)

	missing, err := checkCoverage(w, dir, base, fragments, colour)
	if err != nil {
		return err
	}
	problems += missing

	printf(w, "\n")
	if problems == 0 {
		printf(w, "%schangelog OK%s (%d unreleased fragment(s))\n", colour.green, colour.reset, len(fragments))
		return nil
	}
	printf(w, "%s%d problem(s)%s\n", colour.red, problems, colour.reset)
	return errProblems
}

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------

// config is the subset of .changie.yaml this gate needs. Reading the real file
// rather than restating its rules is what keeps the two from drifting: adding a
// kind or a domain to the config is immediately accepted here, and removing one
// is immediately rejected.
type config struct {
	Kinds []struct {
		Label string `yaml:"label"`
	} `yaml:"kinds"`
	Custom []struct {
		Key         string   `yaml:"key"`
		EnumOptions []string `yaml:"enumOptions"`
	} `yaml:"custom"`
}

func (c config) kindLabels() []string {
	out := make([]string, 0, len(c.Kinds))
	for _, k := range c.Kinds {
		out = append(out, k.Label)
	}
	return out
}

func (c config) domains() []string {
	for _, f := range c.Custom {
		if f.Key == "Domain" {
			return f.EnumOptions
		}
	}
	return nil
}

func loadConfig(path string) (config, error) {
	// path is a flag defaulting to a file in this repository; this is a build
	// gate reading its own configuration, not a server serving user input.
	raw, err := os.ReadFile(path) //nolint:gosec // G304: see above
	if err != nil {
		return config{}, fmt.Errorf("reading %s: %w", path, err)
	}
	var cfg config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return config{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	// An empty rule set would accept everything, which is the failure mode this
	// whole tool exists to prevent elsewhere. Refuse it.
	if len(cfg.Kinds) == 0 {
		return config{}, fmt.Errorf("%s declares no kinds; every fragment would be accepted", path)
	}
	if len(cfg.domains()) == 0 {
		return config{}, fmt.Errorf("%s declares no Domain options; every fragment would be accepted", path)
	}
	return cfg, nil
}

// ---------------------------------------------------------------------------
// fragments
// ---------------------------------------------------------------------------

type fragment struct {
	Path   string
	Kind   string            `yaml:"kind"`
	Body   string            `yaml:"body"`
	Custom map[string]string `yaml:"custom"`
}

func readFragments(dir string) ([]fragment, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}

	var out []fragment
	for _, e := range entries {
		if e.IsDir() || !isFragmentName(e.Name()) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		// Every path comes from ReadDir on the fragment directory named by a
		// flag — a directory in this repository, not anything a request supplies.
		raw, err := os.ReadFile(path) //nolint:gosec // G304: see above
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		var f fragment
		if err := yaml.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		f.Path = path
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func isFragmentName(name string) bool {
	ext := filepath.Ext(name)
	return ext == ".yaml" || ext == ".yml"
}

// commitSubject matches the Conventional Commit prefix this repository uses in
// git. A body starting with one is a pasted commit subject, which is the exact
// substitution the fragment exists to prevent.
var commitSubject = regexp.MustCompile(`^(feat|fix|refactor|test|docs|chore|perf|build|ci)(\([^)]*\))?!?:`)

const (
	minBody = 20
	maxBody = 400
)

func validate(w io.Writer, cfg config, fragments []fragment, colour palette) int {
	kinds := set(cfg.kindLabels())
	domains := set(cfg.domains())
	problems := 0

	fail := func(path, msg, remedy string) {
		printf(w, "  %sFAIL%s  %s\n        %s\n", colour.red, colour.reset, path, msg)
		if remedy != "" {
			printf(w, "        %s\n", remedy)
		}
		problems++
	}

	for _, f := range fragments {
		switch {
		case f.Kind == "":
			fail(f.Path, "no kind", "one of: "+strings.Join(cfg.kindLabels(), ", "))
		case !kinds[f.Kind]:
			fail(f.Path, fmt.Sprintf("unknown kind %q", f.Kind), "one of: "+strings.Join(cfg.kindLabels(), ", "))
		}

		domain := f.Custom["Domain"]
		switch {
		case domain == "":
			fail(f.Path, "no Domain", "one of: "+strings.Join(cfg.domains(), ", "))
		case !domains[domain]:
			fail(f.Path, fmt.Sprintf("unknown Domain %q", domain), "one of: "+strings.Join(cfg.domains(), ", "))
		}

		body := strings.TrimSpace(f.Body)
		switch {
		case body == "":
			fail(f.Path, "empty body", "describe what a customer can now observe")
		case commitSubject.MatchString(body):
			fail(f.Path, "the body is a commit subject",
				"write the sentence a customer reads, not the one an engineer reads")
		case len(body) < minBody:
			fail(f.Path, fmt.Sprintf("body is %d characters; a customer cannot act on that", len(body)),
				fmt.Sprintf("at least %d characters", minBody))
		case len(body) > maxBody:
			fail(f.Path, fmt.Sprintf("body is %d characters; a changelog entry is not a release note", len(body)),
				fmt.Sprintf("at most %d characters — link to the docs for the rest", maxBody))
		case !strings.HasSuffix(body, "."):
			fail(f.Path, "the body is not a sentence", "end it with a full stop")
		default:
			printf(w, "  %sOK%s    %s\n", colour.green, colour.reset, f.Path)
		}
	}
	return problems
}

// ---------------------------------------------------------------------------
// coverage: did this change need a fragment, and did it get one?
// ---------------------------------------------------------------------------

// observable lists the prefixes whose contents a customer can perceive: the
// wire contract, the domain logic behind it, the schema it reads, and the
// binaries that serve it.
var observable = []string{
	"proto/chronos/",
	"internal/modules/",
	"internal/server/",
	"cmd/api/",
	"cmd/worker/",
	"cmd/projector/",
	"cmd/migrate/migrations/",
}

// exempt overrides observable. Order matters: a path is exempt if any of these
// matches, whatever else it looks like.
var exempt = []string{
	"internal/tools/",
	"gen/",
	"docs/",
	"infra/",
	"scripts/",
	".github/",
	".changes/",
	"third_party/",
	"proto-operator/",
	"internal/operator/",
	"cmd/operator/",
}

// needsFragment reports whether a changed path is one a customer can observe.
// The operator plane is deliberately absent from `observable`: it is
// back-office, and a customer changelog is not where its changes belong.
func needsFragment(path string) bool {
	if strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".md") {
		return false
	}
	for _, p := range exempt {
		if strings.HasPrefix(path, p) {
			return false
		}
	}
	for _, p := range observable {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func checkCoverage(w io.Writer, dir, base string, fragments []fragment, colour palette) (int, error) {
	if !inGitRepo() {
		printf(w, "  %sskip%s  not a git repository — coverage not checked\n", colour.yellow, colour.reset)
		return 0, nil
	}
	if base == "" {
		base = autodetectBase()
	}
	if base == "" {
		printf(w, "  %sskip%s  no base branch yet — coverage not checked\n", colour.yellow, colour.reset)
		return 0, nil
	}

	changed, err := changedFiles(base)
	if err != nil {
		return 0, err
	}

	var observed []string
	addedFragment := false
	for _, path := range changed {
		if strings.HasPrefix(path, dir+"/") && isFragmentName(path) {
			addedFragment = true
		}
		if needsFragment(path) {
			observed = append(observed, path)
		}
	}

	// An untracked fragment counts. Without this the gate would report a
	// missing changelog for the developer who has just written one and not yet
	// staged it, which teaches people to distrust it.
	if !addedFragment && len(fragments) > 0 {
		untracked, err := untrackedFiles(dir)
		if err != nil {
			return 0, err
		}
		addedFragment = len(untracked) > 0
	}

	switch {
	case len(observed) == 0:
		printf(w, "  %sOK%s    nothing customer-observable changed against %s\n", colour.green, colour.reset, base)
		return 0, nil
	case addedFragment:
		printf(w, "  %sOK%s    %d customer-observable file(s) changed, and a fragment describes them\n",
			colour.green, colour.reset, len(observed))
		return 0, nil
	}

	declined, err := declinedExplicitly(base)
	if err != nil {
		return 0, err
	}
	if declined {
		printf(w, "  %sOK%s    %d customer-observable file(s) changed; a commit declares `Changelog: none`\n",
			colour.green, colour.reset, len(observed))
		return 0, nil
	}

	printf(w, "  %sFAIL%s  %d customer-observable file(s) changed with no changelog fragment\n",
		colour.red, colour.reset, len(observed))
	for _, p := range observed[:min(len(observed), 10)] {
		printf(w, "          %s\n", p)
	}
	if len(observed) > 10 {
		printf(w, "          … and %d more\n", len(observed)-10)
	}
	printf(w, "        Describe it:  make changelog-new\n")
	printf(w, "        Or say it needs none, in a commit message trailer:  Changelog: none\n")
	return 1, nil
}

func inGitRepo() bool {
	return exec.CommandContext(context.Background(), "git", "rev-parse", "--git-dir").Run() == nil
}

func autodetectBase() string {
	// Each candidate is a literal from this list, so nothing here is attacker
	// controlled; git is invoked directly rather than through a shell.
	for _, candidate := range []string{"origin/main", "origin/master", "main", "master"} {
		cmd := exec.CommandContext(context.Background(), "git", "rev-parse", "--verify", candidate) //nolint:gosec // G204: see above
		if cmd.Run() == nil {
			return candidate
		}
	}
	return ""
}

// changedFiles lists paths that differ from the base, deletions excluded: a
// deleted file cannot need describing that a surviving one does not.
func changedFiles(base string) ([]string, error) {
	// base is a git ref from a flag or CI env; git is invoked directly, so it is
	// an argument and never reaches a shell.
	cmd := exec.CommandContext(context.Background(), "git", "diff", "--name-only", "--diff-filter=d", base) //nolint:gosec // G204: see above
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff against %s: %w", base, err)
	}
	return nonEmptyLines(string(out)), nil
}

func untrackedFiles(dir string) ([]string, error) {
	// dir names a directory in this repository and is passed after --, so it
	// cannot be read as an option and never reaches a shell.
	cmd := exec.CommandContext(context.Background(), "git", "ls-files", "--others", "--exclude-standard", "--", dir) //nolint:gosec // G204: see above
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files in %s: %w", dir, err)
	}
	var found []string
	for _, line := range nonEmptyLines(string(out)) {
		if isFragmentName(line) {
			found = append(found, line)
		}
	}
	return found, nil
}

// declinedExplicitly reports whether any commit in the range states that this
// change needs no entry. The trailer is the escape hatch, and it is deliberately
// a written statement rather than a silent path exclusion: the decision is
// recorded in the history next to the change it applies to.
func declinedExplicitly(base string) (bool, error) {
	// base is a git ref from a flag or CI env, passed as an argument.
	cmd := exec.CommandContext(context.Background(), "git", "log", "--format=%B", base+"..HEAD") //nolint:gosec // G204: see above
	out, err := cmd.Output()
	if err != nil {
		// A shallow clone can lack the merge base. That is not a violation.
		return false, nil //nolint:nilerr // an unreadable commit range is not a missing changelog
	}
	for _, line := range nonEmptyLines(string(out)) {
		if strings.EqualFold(strings.TrimSpace(line), "Changelog: none") {
			return true, nil
		}
	}
	return false, nil
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

func set(values []string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, v := range values {
		m[v] = true
	}
	return m
}

// ---------------------------------------------------------------------------
// output
// ---------------------------------------------------------------------------

type palette struct{ green, red, yellow, reset string }

func useColor(disabled bool) palette {
	if disabled || os.Getenv("NO_COLOR") != "" {
		return palette{}
	}
	return palette{green: "\033[32m", red: "\033[31m", yellow: "\033[33m", reset: "\033[0m"}
}

// printf writes the report. The destination is an os.File or a test buffer;
// neither has a failure this gate could act on, and the alternative is
// sixteen ignored error values.
func printf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}
