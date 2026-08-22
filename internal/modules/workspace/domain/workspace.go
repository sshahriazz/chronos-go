package domain

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// Status is a workspace's lifecycle position.
//
// Deliberately smaller than the organization's: a workspace has no subscription
// and no payment state, so it has none of the states those produce.
type Status string

const (
	// StatusUnknown is the zero value, and it denies.
	StatusUnknown Status = ""

	StatusActive Status = "active"

	// StatusArchived is read-only, members retained, SEATS STILL CONSUMED, and
	// reversible (workspace.md §3). Keeping the seats is what makes restoring
	// meaningful — releasing them would mean a restore could fail because
	// somebody else took them.
	StatusArchived Status = "archived"

	// StatusDeleted is terminal here. The saga that revokes tuples and
	// memberships is workspace.md §3's, and content retention is compliance's.
	StatusDeleted Status = "deleted"
)

// MaxNameLen bounds the display name. The published bound and the refused
// request are one number.
const MaxNameLen = 80

// NewName validates a workspace's display name.
func NewName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	switch {
	case name == "":
		return "", fmt.Errorf("workspace: a name is required")
	case len(name) > MaxNameLen:
		return "", fmt.Errorf("workspace: a name may not exceed %d characters", MaxNameLen)
	}
	return name, nil
}

// Workspace is the collaboration boundary beneath the commercial one.
type Workspace struct {
	eventsourcing.Base

	workspaceID string
	orgID       string
	name        string
	status      Status
	admins      []string
}

var _ eventsourcing.Root = (*Workspace)(nil)

// NewWorkspace returns an empty aggregate for the repository to rebuild into.
func NewWorkspace() *Workspace { return &Workspace{} }

func (w *Workspace) WorkspaceID() string { return w.workspaceID }
func (w *Workspace) OrgID() string       { return w.orgID }
func (w *Workspace) Name() string        { return w.name }
func (w *Workspace) Status() Status      { return w.status }
func (w *Workspace) Exists() bool        { return w.workspaceID != "" }

// Admins returns a copy, so the invariant-bearing set cannot be edited from
// outside the aggregate.
func (w *Workspace) Admins() []string { return slices.Clone(w.admins) }

// IsAdmin reports whether id administers this workspace DIRECTLY.
//
// Directly matters. The organization's owner and admins also administer every
// workspace, by inheritance in the access graph — one tuple, no fan-out
// (organization.md §5.1). That inheritance is OpenFGA's answer and is
// deliberately not duplicated here: this aggregate would have to be told every
// time an org admin changed, which is the fan-out the topology exists to avoid.
//
// The distinction has teeth for the never-zero-admins rule: an org admin does
// NOT count toward the minimum once inheritance is broken, because a workspace
// private to its own members must have a direct admin (ADR-027).
func (w *Workspace) IsAdmin(id string) bool {
	return id != "" && slices.Contains(w.admins, id)
}

// Apply replays one event. Pure, and it validates nothing.
func (w *Workspace) Apply(e eventsourcing.Event) {
	switch ev := e.(type) {
	case *contract.WorkspaceCreated:
		w.workspaceID = ev.WorkspaceID
		w.orgID = ev.OrgID
		w.name = ev.Name
		w.status = StatusActive
		// The creator is the first admin. A workspace created with none would
		// violate the never-zero rule from its first event.
		w.admins = []string{ev.CreatedBy}
	case *contract.WorkspaceRenamed:
		w.name = ev.Name
	case *contract.WorkspaceArchived:
		w.status = StatusArchived
	case *contract.WorkspaceRestored:
		w.status = StatusActive
	case *contract.WorkspaceAdminAdded:
		if !slices.Contains(w.admins, ev.AdminID) {
			w.admins = append(w.admins, ev.AdminID)
		}
	case *contract.WorkspaceAdminRemoved:
		w.admins = slices.DeleteFunc(w.admins, func(id string) bool { return id == ev.AdminID })
	}
}

// Create opens a workspace inside an organization.
func (w *Workspace) Create(workspaceID, orgID, name, createdBy string, at time.Time) error {
	if w.Exists() {
		return fmt.Errorf("workspace: %s already exists", w.workspaceID)
	}
	switch {
	case workspaceID == "":
		return fmt.Errorf("workspace: an id is required")
	case orgID == "":
		return fmt.Errorf("workspace: an organization is required; a workspace outside one " +
			"has no subscription, no quota and nothing for row security to key on")
	case createdBy == "":
		return fmt.Errorf("workspace: a creator is required; they are its first admin, and a " +
			"workspace with no admin cannot be administered by anyone")
	}
	validName, err := NewName(name)
	if err != nil {
		return err
	}
	eventsourcing.Record(w, &contract.WorkspaceCreated{
		WorkspaceID: workspaceID, OrgID: orgID, Name: validName,
		CreatedBy: createdBy, CreatedAt: at,
	})
	return nil
}

// Rename changes the display name.
func (w *Workspace) Rename(name string, at time.Time) error {
	if err := w.mutable(); err != nil {
		return err
	}
	validName, err := NewName(name)
	if err != nil {
		return err
	}
	if validName == w.name {
		return nil // not a change
	}
	eventsourcing.Record(w, &contract.WorkspaceRenamed{
		WorkspaceID: w.workspaceID, OrgID: w.orgID, Name: validName, RenamedAt: at,
	})
	return nil
}

// Archive makes the workspace read-only. Seats stay consumed.
func (w *Workspace) Archive(at time.Time) error {
	if !w.Exists() {
		return fmt.Errorf("workspace: does not exist")
	}
	switch w.status {
	case StatusArchived:
		return nil // already there
	case StatusDeleted:
		return fmt.Errorf("workspace: %s is deleted and cannot be archived", w.workspaceID)
	}
	eventsourcing.Record(w, &contract.WorkspaceArchived{
		WorkspaceID: w.workspaceID, OrgID: w.orgID, ArchivedAt: at,
	})
	return nil
}

// Restore returns an archived workspace to use.
func (w *Workspace) Restore(at time.Time) error {
	if !w.Exists() {
		return fmt.Errorf("workspace: does not exist")
	}
	if w.status != StatusArchived {
		return fmt.Errorf("workspace: %s is %s, not archived", w.workspaceID, w.status)
	}
	eventsourcing.Record(w, &contract.WorkspaceRestored{
		WorkspaceID: w.workspaceID, OrgID: w.orgID, RestoredAt: at,
	})
	return nil
}

// AddAdmin grants direct workspace administration.
func (w *Workspace) AddAdmin(adminID string, at time.Time) error {
	if err := w.mutable(); err != nil {
		return err
	}
	if adminID == "" {
		return fmt.Errorf("workspace: an admin id is required")
	}
	if slices.Contains(w.admins, adminID) {
		return nil
	}
	eventsourcing.Record(w, &contract.WorkspaceAdminAdded{
		WorkspaceID: w.workspaceID, OrgID: w.orgID, AdminID: adminID, AddedAt: at,
	})
	return nil
}

// RemoveAdmin revokes direct administration, and NEVER the last one.
//
// # Why the last admin cannot be removed
//
// workspace.md §4: "the last admin cannot be removed or demoted; the command
// fails with an actionable error naming who could be promoted first". A
// workspace with no direct admin cannot be administered by anyone inside it —
// and once inheritance is broken (ADR-027) there is no org admin to fall back
// on either, so the workspace becomes unmanageable with no event looking wrong.
//
// The error names the remaining admins, because "cannot remove the last admin"
// leaves the caller to work out what to do next.
func (w *Workspace) RemoveAdmin(adminID string, at time.Time) error {
	if err := w.mutable(); err != nil {
		return err
	}
	if !slices.Contains(w.admins, adminID) {
		return nil
	}
	if len(w.admins) == 1 {
		return fmt.Errorf("workspace: %s is the only admin of %s and cannot be removed; "+
			"promote somebody else first", adminID, w.workspaceID)
	}
	eventsourcing.Record(w, &contract.WorkspaceAdminRemoved{
		WorkspaceID: w.workspaceID, OrgID: w.orgID, AdminID: adminID, RemovedAt: at,
	})
	return nil
}

// mutable refuses a change to a workspace that cannot take one.
func (w *Workspace) mutable() error {
	switch {
	case !w.Exists():
		return fmt.Errorf("workspace: does not exist")
	case w.status == StatusArchived:
		return fmt.Errorf("workspace: %s is archived and read-only; restore it first",
			w.workspaceID)
	case w.status == StatusDeleted:
		return fmt.Errorf("workspace: %s is deleted", w.workspaceID)
	}
	return nil
}
