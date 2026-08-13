package argon2id

import "io"

// SetRandForTest replaces the salt source.
//
// A real seam, not a documented intention: it is defined in an _test.go file, so
// it exists only under test and cannot be reached from production code, and the
// test that uses it drives the actual failure branch rather than asserting the
// branch is present.
//
// It exists because the alternative — trusting that a short read from
// crypto/rand is handled — is exactly the kind of "cannot happen" path that
// turns out to produce a partly-zero salt shared by every user who hits it.
func SetRandForTest(h *Hasher, r io.Reader) { h.rand = r }
