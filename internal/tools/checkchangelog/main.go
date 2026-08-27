// Command checkchangelog is the changelog's half of the release procedure: it
// says what happened since the last release tag, and it refuses to let a
// release describe none of it.
//
// # Where the entries come from
//
// They are written at release time, from the diffs, by whoever runs the
// release — in this repository, by Claude, following .claude/skills/release.
// That is a deliberate trade. Writing them at change time is more faithful to
// intent, and this tool used to enforce exactly that; it was traded away for a
// workflow where nobody has to think about the changelog until they want a
// release, at the cost of reconstructing intent from a diff later.
//
// The cost is real, so the procedure compensates: entries are written from the
// DIFFS, never from commit subjects. Commit subjects here are written for
// engineers on purpose — "half of every API key minted could never
// authenticate" is the right sentence for git log and the wrong one for a
// customer — and a changelog that restates them either leaks internal detail or
// reads as noise. This tool's -list mode prints the diffs to read, and its
// validation refuses a body that is a pasted commit subject.
//
// # Three modes
//
//	checkchangelog                    validate every fragment. `make check` runs this.
//	checkchangelog -list              the release input: every commit since the last
//	                                  tag, which touched something a customer can
//	                                  observe, and which declined an entry.
//	checkchangelog -coverage          refuse a release that describes nothing while
//	                                  observable work went into it. `make release` runs this.
//
// The range is `<last tag>..HEAD` unless -since says otherwise. A tag is
// therefore load-bearing: without one the range is the whole history.
//
// Exits non-zero on any problem. Skips, loudly, when there is no git repository
// — never silently.
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
	since := flag.String("since", os.Getenv("CHANGELOG_SINCE"), "git ref the release starts after; empty means the most recent tag")
	list := flag.Bool("list", false, "print the release input: every commit in the range and what it touched")
	coverage := flag.Bool("coverage", false, "fail if observable work in the range is described by no fragment")
	config := flag.String("config", ".changie.yaml", "the changie configuration the fragments must satisfy")
	dir := flag.String("dir", ".changes/unreleased", "where unreleased fragments live")
	noColor := flag.Bool("no-color", false, "never colourize the report")
	flag.Parse()

	opts := options{
		config:   *config,
		dir:      *dir,
		since:    *since,
		list:     *list,
		coverage: *coverage,
		colour:   useColor(*noColor),
	}
	if err := run(os.Stdout, opts); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "checkchangelog:", err)
		os.Exit(1)
	}
}

type options struct {
	config   string
	dir      string
	since    string
	list     bool
	coverage bool
	colour   palette
}

// errProblems is returned when the tree is readable but wrong. The report has
// already been printed; main only needs the exit code.
var errProblems = errors.New("the changelog does not describe this release (see above)")

func run(w io.Writer, o options) error {
	cfg, err := loadConfig(o.config)
	if err != nil {
		return err
	}

	fragments, err := readFragments(o.dir)
	if err != nil {
		return err
	}

	problems := validate(w, cfg, fragments, o.colour)

	if o.list || o.coverage {
		n, err := inspectRange(w, o, fragments)
		if err != nil {
			return err
		}
		problems += n
	}

	printf(w, "\n")
	if problems == 0 {
		printf(w, "%schangelog OK%s (%d unreleased fragment(s))\n", o.colour.green, o.colour.reset, len(fragments))
		return nil
	}
	printf(w, "%s%d problem(s)%s\n", o.colour.red, problems, o.colour.reset)
	return errProblems
}

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------

// config is the subset of .changie.yaml this tool needs. Reading the real file
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
// substitution entries written at release time are most likely to become.
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
// the release range
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

// commit is one entry in the release range.
type commit struct {
	SHA        string
	Subject    string
	Body       string
	Files      []string
	Observable []string
}

// Declined reports whether this commit states that it needs no entry. The
// trailer is the escape hatch, and it is deliberately a written statement
// rather than a silent path exclusion: the decision is recorded in the history
// next to the change it applies to.
func (c commit) Declined() bool {
	for _, line := range nonEmptyLines(c.Body) {
		if strings.EqualFold(strings.TrimSpace(line), "Changelog: none") {
			return true
		}
	}
	return false
}

func (c commit) Short() string {
	if len(c.SHA) <= 12 {
		return c.SHA
	}
	return c.SHA[:12]
}

func inspectRange(w io.Writer, o options, fragments []fragment) (int, error) {
	if !inGitRepo() {
		printf(w, "  %sskip%s  not a git repository — the release range was not read\n", o.colour.yellow, o.colour.reset)
		return 0, nil
	}

	since := o.since
	if since == "" {
		since = lastTag()
	}
	rangeName := "the whole history"
	if since != "" {
		rangeName = since + "..HEAD"
	}

	commits, err := commitsInRange(since)
	if err != nil {
		return 0, err
	}

	var described, declined []commit
	for _, c := range commits {
		if len(c.Observable) == 0 {
			continue
		}
		if c.Declined() {
			declined = append(declined, c)
			continue
		}
		described = append(described, c)
	}

	if o.list {
		printRange(w, o.colour, rangeName, commits, described, declined)
	}

	if !o.coverage {
		return 0, nil
	}
	return checkCoverage(w, o.colour, rangeName, described, fragments), nil
}

func printRange(w io.Writer, colour palette, rangeName string, all, described, declined []commit) {
	printf(w, "\n%srelease input%s — %s, %d commit(s)\n\n", colour.bold, colour.reset, rangeName, len(all))

	if len(described) > 0 {
		printf(w, "  %sNEEDS AN ENTRY%s — read the diff, write what a customer can observe:\n", colour.bold, colour.reset)
		for _, c := range described {
			printf(w, "    %s  %s\n", c.Short(), c.Subject)
			for _, f := range c.Observable {
				printf(w, "        %s\n", f)
			}
			printf(w, "        git show %s\n", c.Short())
		}
		printf(w, "\n")
	}

	if len(declined) > 0 {
		printf(w, "  %sDECLINED%s — the commit says `Changelog: none`:\n", colour.yellow, colour.reset)
		for _, c := range declined {
			printf(w, "    %s  %s\n", c.Short(), c.Subject)
		}
		printf(w, "\n")
	}

	invisible := len(all) - len(described) - len(declined)
	if invisible > 0 {
		printf(w, "  %s%d commit(s) touched nothing a customer can observe%s\n\n", colour.green, invisible, colour.reset)
	}
}

// checkCoverage refuses a release that describes nothing while observable work
// went into it.
//
// It cannot tie a fragment to the commit it describes — nothing records that
// link — so this is a floor, not a proof: it catches "the release was cut
// without anyone writing the changelog", which is the failure that actually
// happens, and it cannot catch "three changes shipped and one was described".
// The -list mode exists so that reading the range is cheap enough to do.
func checkCoverage(w io.Writer, colour palette, rangeName string, described []commit, fragments []fragment) int {
	switch {
	case len(described) == 0:
		printf(w, "  %sOK%s    nothing customer-observable in %s\n", colour.green, colour.reset, rangeName)
		return 0
	case len(fragments) > 0:
		printf(w, "  %sOK%s    %d commit(s) in %s changed something observable, and %d fragment(s) describe this release\n",
			colour.green, colour.reset, len(described), rangeName, len(fragments))
		return 0
	}

	printf(w, "  %sFAIL%s  %d commit(s) in %s changed something a customer can observe, and this release describes none of it\n",
		colour.red, colour.reset, len(described), rangeName)
	for _, c := range described[:min(len(described), 10)] {
		printf(w, "          %s  %s\n", c.Short(), c.Subject)
	}
	if len(described) > 10 {
		printf(w, "          … and %d more\n", len(described)-10)
	}
	printf(w, "        Read them:    make release-input\n")
	printf(w, "        Describe it:  make changelog-new\n")
	printf(w, "        Or, per commit that needs none, a `Changelog: none` trailer.\n")
	return 1
}

// ---------------------------------------------------------------------------
// git
// ---------------------------------------------------------------------------

func inGitRepo() bool {
	return exec.CommandContext(context.Background(), "git", "rev-parse", "--git-dir").Run() == nil
}

// lastTag is the most recent tag reachable from HEAD, which is the previous
// release. An empty result means this is the first one.
func lastTag() string {
	cmd := exec.CommandContext(context.Background(), "git", "describe", "--tags", "--abbrev=0")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// Record and field separators that cannot occur in a commit message.
const (
	recordSep = "\x01"
	fieldSep  = "\x1f"
	bodyEnd   = "\x1e"
)

// commitsInRange reads the range in one git invocation. Merges are excluded:
// their file lists are empty under --name-only, and the commits they merge are
// already in the range.
func commitsInRange(since string) ([]commit, error) {
	args := []string{
		"log", "--no-merges", "--name-only",
		"--format=" + recordSep + "%H" + fieldSep + "%s" + fieldSep + "%b" + bodyEnd,
	}
	if since != "" {
		args = append(args, since+"..HEAD")
	}
	// since is a git ref from a flag, an env var or `git describe`, passed as an
	// argument and never through a shell.
	cmd := exec.CommandContext(context.Background(), "git", args...) //nolint:gosec // G204: see above
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git log over %s..HEAD: %w", since, err)
	}
	return parseLog(string(out)), nil
}

// parseLog is separated from the git invocation so the parsing can be tested
// against shapes a repository is awkward to produce on demand — an empty body,
// a commit that touched nothing, a body containing blank lines.
func parseLog(out string) []commit {
	var commits []commit
	for _, record := range strings.Split(out, recordSep) {
		if strings.TrimSpace(record) == "" {
			continue
		}
		header, files, found := strings.Cut(record, bodyEnd)
		if !found {
			continue
		}
		parts := strings.SplitN(header, fieldSep, 3)
		if len(parts) < 3 {
			continue
		}
		c := commit{SHA: strings.TrimSpace(parts[0]), Subject: strings.TrimSpace(parts[1]), Body: parts[2]}
		for _, f := range nonEmptyLines(files) {
			c.Files = append(c.Files, f)
			if needsFragment(f) {
				c.Observable = append(c.Observable, f)
			}
		}
		commits = append(commits, c)
	}
	return commits
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

type palette struct{ green, red, yellow, bold, reset string }

func useColor(disabled bool) palette {
	if disabled || os.Getenv("NO_COLOR") != "" {
		return palette{}
	}
	return palette{
		green:  "\033[32m",
		red:    "\033[31m",
		yellow: "\033[33m",
		bold:   "\033[1m",
		reset:  "\033[0m",
	}
}

// printf writes the report. The destination is an os.File or a test buffer;
// neither has a failure this tool could act on, and the alternative is
// twenty ignored error values.
func printf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}
