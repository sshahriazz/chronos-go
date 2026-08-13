// Package blindindex derives the keyed lookup value for an email address.
//
// # The problem it solves
//
// Two questions have to be answerable without the address itself being anywhere
// outside the vault:
//
//   - "Is there already an account for this address?" — needed on registration
//     and on login, and answered from a projection, which may hold no personal
//     data at all (compliance.md §1).
//   - "Which stream owns the reservation for this address?" — needed before any
//     account exists, and answered by a stream NAME, which is permanent
//     (ADR-044).
//
// A plain hash would answer both and would also be an offline dictionary: the
// space of real email addresses is small enough to enumerate, so SHA-256(address)
// is reversible in practice for anyone holding the database. A KEYED hash is not,
// because the key is not in the database.
//
// # Why there is exactly one key, and why it is never rotated
//
// The index names a KurrentDB stream, and stream names are immutable. Rotating
// the key would orphan every reservation ever written — the new key produces a
// new name, the old stream still holds the claim, and uniqueness silently stops
// being enforced for every address registered before the rotation.
//
// So there is one key, k_res, and it is never rotated and never destroyed. That
// is the deliberate exception to erasure-by-key-destruction recorded in
// EVENT-SOURCING §5, and its blast radius is narrow and worth stating plainly:
// an attacker holding BOTH the key and the database can test whether a given
// address has an account. They cannot recover addresses they have not guessed,
// and they cannot read anything else about the person.
//
// A version column is deliberately NOT stored. IDENTITY-REVIEW C7 asked for one,
// and it would be dishonest here: a column that can never change advertises a
// rotation capability that does not exist, and the next reader would build a
// rotation job against it. The real fix C7 identified — full width, no
// truncation — is below.
package blindindex

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
)

// KeySize is the HMAC key length. 32 bytes: matching the hash's block-derived
// output size, which is where HMAC-SHA256's security argument tops out.
const KeySize = 32

// Category is the KurrentDB category for reservation streams.
//
// No dash, because KurrentDB derives the category from everything before the
// FIRST dash — a dash here would file every reservation under "reservation" and
// break the prefix-filtered subscription (EVENT-SOURCING §2).
const Category = "reservation_email"

// Index derives keyed lookup values for email addresses.
type Index struct {
	key []byte
}

// The compile-time binding to the port, and it is not ceremony. Structural typing
// means this type satisfied app.EmailIndexer without ever naming it, so a review
// of the use case could — and did — conclude that no implementation existed at
// all. Naming the port here makes the relationship greppable, and makes a change
// to either side a build failure rather than a discovery at wiring time.
var _ app.EmailIndexer = (*Index)(nil)

// New builds the deriver.
func New(key []byte) (*Index, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("blindindex: key is %d bytes, want %d", len(key), KeySize)
	}
	// Copied, not retained. A caller that zeroes its own buffer after wiring —
	// which is the correct thing for a caller to do — would otherwise silently
	// turn every future index into HMAC-under-a-zero-key.
	held := make([]byte, KeySize)
	copy(held, key)
	return &Index{key: held}, nil
}

// Of returns the blind index for an address.
//
// FULL WIDTH: all 32 bytes, hex-encoded to 64 characters. Truncating is the
// tempting optimisation and the one IDENTITY-REVIEW C7 named — a shortened index
// is smaller to store and index, and it introduces collisions. Under the UNIQUE
// constraint that enforces address uniqueness, a collision means one person's
// registration fails because an unrelated stranger's address happens to share a
// prefix. That failure is unreproducible, unexplainable to the user, and tells a
// determined attacker that some other address collides with theirs.
//
// 64 hex characters in a b-tree index is not a cost worth that.
func (i *Index) Of(email string) (contract.EmailIndex, error) {
	normalized, err := domain.NormalizeEmail(email)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, i.key)
	// hash.Hash never returns an error from Write; the interface has one only to
	// satisfy io.Writer.
	_, _ = mac.Write([]byte(normalized))
	return contract.EmailIndex(hex.EncodeToString(mac.Sum(nil))), nil
}

// StreamKey returns the reservation stream key for an address.
//
// The same value as Of, and deliberately so rather than a second derivation: two
// keyed values for one address would mean the stream that enforces uniqueness
// and the column that reports it could disagree, and the disagreement would look
// exactly like a projection lag.
//
// The caller composes it with Category through eventsourcing.NewStreamID, which
// is what rejects a key containing a dash. Hex output cannot contain one, so the
// composition always succeeds — but it is checked there rather than assumed here.
func (i *Index) StreamKey(email string) (string, error) {
	idx, err := i.Of(email)
	if err != nil {
		return "", err
	}
	return string(idx), nil
}

// Matches reports whether an address derives to a given index.
//
// Constant-time, and it matters for a reason that is easy to miss: this is how
// "does the token I was given belong to the address it claims?" is answered
// during verification, and a byte-wise comparison there leaks a prefix of the
// index for an address the caller supplied. Enough queries recover it, and the
// index is the thing the key exists to protect.
func (i *Index) Matches(email string, index contract.EmailIndex) bool {
	got, err := i.Of(email)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(got), []byte(index))
}
