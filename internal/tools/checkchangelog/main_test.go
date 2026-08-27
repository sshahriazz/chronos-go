package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNeedsFragment(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"proto/chronos/billing/v1/billing.proto", true},
		{"internal/modules/billing/app/subscribe.go", true},
		{"internal/server/interceptor/auth.go", true},
		{"cmd/api/deps.go", true},
		{"cmd/migrate/migrations/0035_add_widgets.sql", true},

		// Tests and prose describe nothing new to a customer.
		{"internal/modules/billing/app/subscribe_test.go", false},
		{"docs/domains/billing.md", false},
		{"CLAUDE.md", false},

		// Generated code follows the proto that produced it; the proto already
		// required a fragment, and requiring a second one for its output would
		// double-count every schema change.
		{"gen/proto/chronos/billing/v1/billing.pb.go", false},

		// The operator plane is back-office (ADR-024). Its changes are real,
		// and a customer changelog is not where they belong.
		{"internal/operator/session.go", false},
		{"cmd/operator/main.go", false},
		{"proto-operator/chronos/operator/v1/operator.proto", false},

		// Gates, generators and infrastructure.
		{"internal/tools/checkchangelog/main.go", false},
		{"infra/prometheus/prometheus.yml", false},
		{".github/workflows/ci.yml", false},
		{".changes/unreleased/Added-20260827-101500.yaml", false},
	}

	for _, tc := range cases {
		if got := needsFragment(tc.path); got != tc.want {
			t.Errorf("needsFragment(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// The real .changie.yaml is the input, so a change to the config that this gate
// could not read fails here rather than in CI.
func TestLoadsTheRealConfig(t *testing.T) {
	cfg, err := loadConfig("../../../.changie.yaml")
	if err != nil {
		t.Fatalf("loading the repository's own config: %v", err)
	}
	if len(cfg.kindLabels()) < 4 {
		t.Errorf("kinds: got %v", cfg.kindLabels())
	}
	for _, want := range []string{"identity", "billing", "compliance"} {
		if !set(cfg.domains())[want] {
			t.Errorf("domains %v does not contain %q", cfg.domains(), want)
		}
	}
}

func TestLoadConfigRefusesAnEmptyRuleSet(t *testing.T) {
	// A config with no kinds would accept every fragment, which is the silent
	// pass this repository has been bitten by before.
	path := filepath.Join(t.TempDir(), "empty.yaml")
	if err := os.WriteFile(path, []byte("changesDir: .changes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("a config declaring no kinds was accepted")
	}
}

func TestValidate(t *testing.T) {
	cfg := config{
		Kinds: []struct {
			Label string `yaml:"label"`
		}{{Label: "Added"}, {Label: "Fixed"}},
		Custom: []struct {
			Key         string   `yaml:"key"`
			EnumOptions []string `yaml:"enumOptions"`
		}{{Key: "Domain", EnumOptions: []string{"billing", "identity"}}},
	}

	good := fragment{
		Path:   "good.yaml",
		Kind:   "Added",
		Body:   "Export your organization's data as a signed bundle.",
		Custom: map[string]string{"Domain": "billing"},
	}

	cases := []struct {
		name     string
		mutate   func(fragment) fragment
		problems int
	}{
		{"a complete fragment passes", func(f fragment) fragment { return f }, 0},
		{"unknown kind", func(f fragment) fragment { f.Kind = "Improved"; return f }, 1},
		{"missing kind", func(f fragment) fragment { f.Kind = ""; return f }, 1},
		{"unknown domain", func(f fragment) fragment { f.Custom = map[string]string{"Domain": "drive"}; return f }, 1},
		{"missing domain", func(f fragment) fragment { f.Custom = nil; return f }, 1},
		{"empty body", func(f fragment) fragment { f.Body = "   "; return f }, 1},
		{"body too short", func(f fragment) fragment { f.Body = "Fixed a bug."; return f }, 1},
		{"no full stop", func(f fragment) fragment { f.Body = strings.TrimSuffix(f.Body, "."); return f }, 1},
		{
			// The substitution the whole gate exists to prevent.
			name: "a pasted commit subject",
			mutate: func(f fragment) fragment {
				f.Body = "fix(identity): half of every API key could not authenticate."
				return f
			},
			problems: 1,
		},
		{
			name: "body over the ceiling",
			mutate: func(f fragment) fragment {
				f.Body = strings.Repeat("a", maxBody) + "."
				return f
			},
			problems: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validate(io.Discard, cfg, []fragment{tc.mutate(good)}, palette{})
			if got != tc.problems {
				t.Errorf("problems: got %d want %d", got, tc.problems)
			}
		})
	}
}

// A gate that reports nothing to check must not report success by counting
// zero of something it never looked at.
func TestReadFragmentsIgnoresNonFragments(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		".gitkeep":                 "",
		"README.md":                "not a fragment",
		"Added-20260827-1015.yaml": "kind: Added\nbody: A body.\ncustom:\n    Domain: billing\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got, err := readFragments(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d fragments, want 1: %+v", len(got), got)
	}
	if got[0].Kind != "Added" || got[0].Custom["Domain"] != "billing" {
		t.Errorf("parsed wrong: %+v", got[0])
	}
}

func TestParseLog(t *testing.T) {
	// The shape `git log --no-merges --name-only --format=…` produces, including
	// a commit that touched nothing observable and one that declined an entry.
	rec := func(sha, subject, body string, files ...string) string {
		s := recordSep + sha + fieldSep + subject + fieldSep + body + bodyEnd
		for _, f := range files {
			s += "\n" + f
		}
		return s + "\n"
	}
	out := rec("aaaa111122223333", "feat(billing): seats", "Adds seats.\n",
		"internal/modules/billing/app/seat.go", "internal/modules/billing/app/seat_test.go") +
		rec("bbbb111122223333", "refactor(api): one registry", "Tidy.\n\nChangelog: none\n",
			"cmd/api/deps.go") +
		rec("cccc111122223333", "docs: worklist", "", "docs/WORKLIST.md")

	got := parseLog(out)
	if len(got) != 3 {
		t.Fatalf("got %d commits, want 3", len(got))
	}

	if got[0].Subject != "feat(billing): seats" {
		t.Errorf("subject: %q", got[0].Subject)
	}
	// The test file is not observable; the app file is.
	if len(got[0].Files) != 2 || len(got[0].Observable) != 1 {
		t.Errorf("files %v observable %v", got[0].Files, got[0].Observable)
	}
	if got[0].Declined() {
		t.Error("a commit with no trailer must not read as declined")
	}
	if got[0].Short() != "aaaa11112222" {
		t.Errorf("short: %q", got[0].Short())
	}

	if !got[1].Declined() {
		t.Error("`Changelog: none` in the body must be read as declining an entry")
	}
	if len(got[1].Observable) != 1 {
		t.Errorf("cmd/api/deps.go is observable: %v", got[1].Observable)
	}

	// An empty body must not swallow the record or the file list.
	if len(got[2].Files) != 1 || len(got[2].Observable) != 0 {
		t.Errorf("files %v observable %v", got[2].Files, got[2].Observable)
	}
}

func TestParseLogIgnoresJunk(t *testing.T) {
	for _, in := range []string{"", "\n\n", "no separators at all"} {
		if got := parseLog(in); len(got) != 0 {
			t.Errorf("parseLog(%q) = %v, want none", in, got)
		}
	}
}

// A release that describes nothing while observable work went into it is the
// failure this gate exists for; everything else must pass.
func TestCheckCoverage(t *testing.T) {
	observableCommit := commit{SHA: "aaaa111122223333", Subject: "feat: x", Observable: []string{"internal/modules/x.go"}}
	oneFragment := []fragment{{Path: "f.yaml", Kind: "Added", Body: "A body."}}

	cases := []struct {
		name      string
		described []commit
		fragments []fragment
		problems  int
	}{
		{"nothing observable, no fragments", nil, nil, 0},
		{"observable work described", []commit{observableCommit}, oneFragment, 0},
		{"observable work described by nothing", []commit{observableCommit}, nil, 1},
		{"fragments with no observable work is fine", nil, oneFragment, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := checkCoverage(io.Discard, palette{}, "v0.1.0..HEAD", tc.described, tc.fragments)
			if got != tc.problems {
				t.Errorf("problems: got %d want %d", got, tc.problems)
			}
		})
	}
}
