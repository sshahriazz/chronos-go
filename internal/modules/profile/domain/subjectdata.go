package domain

import (
	"github.com/chronos/chronos-go/internal/platform/pii"
	"github.com/chronos/chronos-go/internal/platform/subjectdata"
)

// SubjectDataFragment is profile's contribution to the subject graph
// (compliance.md §4 step 4).
//
// # Objects, and nothing else
//
// Profile holds one kind of personal data the PII vault does not: avatar
// images, in the object store. The vault's key destruction makes every
// vault-held field unreadable at once (ADR-002), and it does not touch a byte
// in a bucket — so an avatar survives an erasure unless something deletes it,
// and a signed URL for it keeps resolving.
//
// It also WRITES three vault fields — the display name, the locale and the
// timezone. Erasure does not walk them (one key destruction takes every field of
// a subject at once, ADR-002); declaring them answers "who puts personal data in
// the vault", which a controller has to be able to answer and which nothing else
// in this codebase records.
//
// # The prefix rather than the keys
//
// Objects here are immutable — a new avatar is a new key plus a new event
// (ADR-013) — so a projection names the CURRENT one while every replaced
// version and every granted-but-abandoned upload sits under the same prefix
// with no row mentioning it. ADR-056 leaves both unreclaimed; for an erasure
// they are simply personal data that would survive. Enumerating the prefix
// finds all three kinds.
func SubjectDataFragment() subjectdata.Fragment {
	return subjectdata.Fragment{
		Module:         "profile",
		ObjectPrefixes: []subjectdata.PrefixFor{AvatarPrefix},
		VaultFields: []string{
			string(pii.FieldName),
			string(pii.FieldLocale),
			string(pii.FieldTimezone),
		},
	}
}
