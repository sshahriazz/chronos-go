// Package contract is the workspace module's published event vocabulary.
//
// Past-tense facts, carrying SubjectID pseudonyms and never personal data
// (ADR-002). `workspace` depends on `organization` and never the reverse
// (ADR-020) — nothing here is imported by that module.
package contract

import "time"

// WorkspaceCreated is a new collaboration space inside an organization.
//
// It carries the OrgID because every workspace-scoped row does: organization.md
// §5.4 requires both ids on the row and both in the RLS predicate, and the
// reason is not redundancy. It is what stops a forged or leaked workspace_id
// from ANOTHER organization resolving — the workspace-level policy alone would
// happily serve a row from a different tenant.
type WorkspaceCreated struct {
	WorkspaceID string
	OrgID       string
	Name        string
	CreatedBy   string // a SubjectID pseudonym
	CreatedAt   time.Time
}

func (*WorkspaceCreated) EventType() string { return "workspace.Created.v1" }

// WorkspaceRenamed changes the display name and nothing else.
type WorkspaceRenamed struct {
	WorkspaceID string
	OrgID       string
	Name        string
	RenamedAt   time.Time
}

func (*WorkspaceRenamed) EventType() string { return "workspace.Renamed.v1" }

// WorkspaceArchived makes a workspace read-only without destroying anything.
//
// Members are retained and SEATS ARE STILL CONSUMED (workspace.md §3). That is
// deliberate and is the difference from deletion: archiving is reversible, so
// the seats have to still be there to come back to.
type WorkspaceArchived struct {
	WorkspaceID string
	OrgID       string
	ArchivedAt  time.Time
}

func (*WorkspaceArchived) EventType() string { return "workspace.Archived.v1" }

// WorkspaceRestored returns an archived workspace to use.
type WorkspaceRestored struct {
	WorkspaceID string
	OrgID       string
	RestoredAt  time.Time
}

func (*WorkspaceRestored) EventType() string { return "workspace.Restored.v1" }

// WorkspaceAdminAdded grants workspace administration.
//
// Admins are INSIDE the Workspace aggregate, for the rule organization.md §2
// states and workspace.md §1 repeats: invariant-bearing sets go inside the
// aggregate, high-volume collections do not. "Never zero admins" must hold
// transactionally; ordinary members number thousands and live in their own
// aggregate.
type WorkspaceAdminAdded struct {
	WorkspaceID string
	OrgID       string
	AdminID     string
	AddedAt     time.Time
}

func (*WorkspaceAdminAdded) EventType() string { return "workspace.AdminAdded.v1" }

// WorkspaceAdminRemoved revokes workspace administration.
type WorkspaceAdminRemoved struct {
	WorkspaceID string
	OrgID       string
	AdminID     string
	RemovedAt   time.Time
}

func (*WorkspaceAdminRemoved) EventType() string { return "workspace.AdminRemoved.v1" }
