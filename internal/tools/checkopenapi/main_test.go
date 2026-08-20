package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunAcceptsTheCommittedSpec is the end-to-end pass: the tool, over the real
// document and the real .proto sources, exactly as `make api-validate` runs it.
func TestRunAcceptsTheCommittedSpec(t *testing.T) {
	t.Parallel()

	var out strings.Builder
	if err := run(&out, specPath, protoDir, false); err != nil {
		t.Errorf("run() = %v\n%s", err, out.String())
	}
}

// TestRunFailsRatherThanSkips covers every way this tool can fail to do its job.
//
// Its predecessor exited 0 when its YAML library was missing, so the gate passed
// without ever parsing the spec — on every developer machine and in CI. An
// unrun gate proves nothing, and treating it as a pass is how an empty spec
// ships. Each case here must return an error.
func TestRunFailsRatherThanSkips(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	notYAML := filepath.Join(dir, "not.yaml")
	if err := os.WriteFile(notYAML, []byte("\tthis: [is: not: yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	emptyDoc := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(emptyDoc, []byte("# nothing here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	emptyPaths := filepath.Join(dir, "emptypaths.yaml")
	if err := os.WriteFile(emptyPaths, []byte("openapi: 3.1.0\npaths: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		spec string
		want string
	}{
		{"the spec does not exist", filepath.Join(dir, "absent.yaml"), "cannot read"},
		{"the spec is not YAML", notYAML, "not parseable YAML"},
		{"the spec is empty", emptyDoc, "decoded to nothing"},
		{"the spec has no paths", emptyPaths, "does not satisfy its contract"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := run(io.Discard, tt.spec, protoDir, false)
			if err == nil {
				t.Fatalf("run() succeeded; a gate that cannot run has not been satisfied")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("run() = %q, want it to mention %q", err, tt.want)
			}
		})
	}
}
