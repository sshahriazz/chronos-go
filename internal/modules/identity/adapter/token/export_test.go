package token

import "io"

// SetRandForTest replaces the entropy source.
//
// Defined in an _test.go file, so it exists only under test and cannot be
// reached from production code. It exists because the alternative — trusting
// that a short read from crypto/rand is handled — is exactly the "cannot happen"
// path that turns out to produce tokens with predictable tails.
func SetRandForTest(m *Minter, r io.Reader) { m.rand = r }
