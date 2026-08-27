package main

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, name string, content []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExecutableKind(t *testing.T) {
	cases := []struct {
		name    string
		content []byte
		mode    os.FileMode
		want    string
	}{
		{"elf", []byte{0x7f, 'E', 'L', 'F', 0x02}, 0o755, "ELF"},
		{"macho64", append(le32(0xFEEDFACF), 0x07), 0o755, "Mach-O 64-bit"},
		{"macho32", append(le32(0xFEEDFACE), 0x07), 0o755, "Mach-O 32-bit"},
		{"universal", append(be32(0xCAFEBABE), 0x00), 0o755, "Mach-O universal"},

		// The one ambiguous magic: "MZ" also begins plenty of prose. A Windows
		// executable is executable; a sentence is not.
		{"pe", []byte("MZ\x90\x00"), 0o755, "PE"},
		{"prose starting MZ", []byte("MZ is a rapper, not a binary.\n"), 0o644, ""},

		{"go source", []byte("package main\n"), 0o644, ""},
		{"shell script", []byte("#!/usr/bin/env bash\nset -e\n"), 0o755, ""},

		// Short files must not panic on a truncated header read.
		{"empty", nil, 0o644, ""},
		{"one byte", []byte{0x7f}, 0o644, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := executableKind(write(t, "f", tc.content, tc.mode))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestExecutableKindReportsAMissingFile(t *testing.T) {
	// A tracked path deleted in the working tree is somebody's in-flight
	// deletion; run() skips it, but only because this reports os.ErrNotExist
	// rather than swallowing it into "not an executable".
	if _, err := executableKind(filepath.Join(t.TempDir(), "gone")); !os.IsNotExist(err) {
		t.Fatalf("got %v, want a not-exist error", err)
	}
}

// The repository this runs in must itself be clean, so a binary committed while
// the gate is not wired into CI still fails somewhere.
func TestThisRepositoryTracksNoExecutables(t *testing.T) {
	paths, err := trackedFiles()
	if err != nil {
		t.Skipf("not a git repository: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("git listed no tracked files")
	}
	for _, p := range paths {
		kind, err := executableKind(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if kind != "" {
			t.Errorf("%s is a tracked %s executable", p, kind)
		}
	}
}
