package domain

import (
	"github.com/chronos/chronos-go/internal/platform/pii"
	"github.com/chronos/chronos-go/internal/platform/subjectdata"
)

// SubjectDataFragment is workspace's contribution to the subject graph
// (compliance.md §4 step 4).
//
// # Workspace writes to the PII vault, which is easy to miss
//
// Issuing an invitation to somebody who has no account stores THEIR address —
// under a `subj_` pseudonym workspace mints for a person who has never used
// this system. It is the only place in the product where personal data enters
// the vault for a non-user, and it is the reason this fragment exists.
//
// It matters for erasure in a way an account holder's data does not: the
// invitee never agreed to anything and may never accept, so the pseudonym they
// were given is the only handle a request from them could be matched to. The
// declaration is what makes that reachable rather than a fact somebody has to
// remember.
//
// It shares `email` with identity, which writes the same field at registration.
// Two writers is a fact, not a conflict — a subject's key destruction takes
// every field of theirs at once whoever wrote it (ADR-002).
//
// Workspace stores NO objects and holds no reservation of its own: the
// invitation's `email_index` is identity's blind index, computed under
// identity's key, and identity releases it.
func SubjectDataFragment() subjectdata.Fragment {
	return subjectdata.Fragment{
		Module:      "workspace",
		VaultFields: []string{string(pii.FieldEmail)},
	}
}
