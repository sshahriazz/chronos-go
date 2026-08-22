package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
)

var at = time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

func created(t *testing.T) *domain.Workspace {
	t.Helper()
	w := domain.NewWorkspace()
	err := w.Create("ws_01ARZ3NDEKTSV4RRFFQ69G5FAV", "org_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		"Engineering", "sub_alice", at)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return w
}

// The LAST admin cannot be removed, and the error says what to do.
//
// # Why this is the invariant worth the aggregate boundary
//
// workspace.md §1 puts admins inside the aggregate for exactly this: the rule
// has to hold transactionally. A workspace with no direct admin cannot be
// administered from inside it, and once inheritance is broken (ADR-027) there is
// no org admin to fall back on either — so it becomes unmanageable, and no event
// anywhere looks wrong.
func TestTheLastAdminCannotBeRemoved(t *testing.T) {
	t.Parallel()

	w := created(t)
	if got := w.Admins(); len(got) != 1 || got[0] != "sub_alice" {
		t.Fatalf("the creator is not the first admin: %v", got)
	}

	err := w.RemoveAdmin("sub_alice", at)
	if err == nil {
		t.Fatal("the only admin was removed. The workspace can no longer be administered " +
			"from inside it, and with inheritance broken there is nobody left at all")
	}
	if !strings.Contains(err.Error(), "promote somebody else first") {
		t.Errorf("the refusal does not say what to do instead: %v", err)
	}
	if !w.IsAdmin("sub_alice") {
		t.Error("the refused removal changed the aggregate anyway")
	}
}

// With two admins, either may go.
func TestAnAdminCanBeRemovedWhenAnotherRemains(t *testing.T) {
	t.Parallel()

	w := created(t)
	if err := w.AddAdmin("sub_bob", at); err != nil {
		t.Fatalf("AddAdmin: %v", err)
	}
	if err := w.RemoveAdmin("sub_alice", at); err != nil {
		t.Fatalf("removing one of two admins: %v", err)
	}
	if w.IsAdmin("sub_alice") {
		t.Error("alice was removed and still administers")
	}
	if !w.IsAdmin("sub_bob") {
		t.Error("bob stopped administering when alice was removed")
	}
	// And now bob is the last one.
	if err := w.RemoveAdmin("sub_bob", at); err == nil {
		t.Error("the workspace was left with no admins by removing them one at a time")
	}
}

// The creator is an admin from the FIRST event.
//
// Not a second event, and not a later grant: a workspace that existed for even
// one event with no admin would violate the rule from birth, and a replay would
// reproduce that state.
func TestTheCreatorIsTheFirstAdmin(t *testing.T) {
	t.Parallel()

	w := created(t)
	if !w.IsAdmin("sub_alice") {
		t.Fatal("the creator does not administer the workspace they made")
	}
	if len(w.Uncommitted()) != 1 {
		t.Errorf("creation recorded %d events; the first admin rides the creation rather "+
			"than following it", len(w.Uncommitted()))
	}
}

// Inherited administration is deliberately NOT modelled here.
//
// The organization's owner and admins administer every workspace by inheritance
// in the access graph — one tuple, no fan-out. Duplicating that here would mean
// telling this aggregate every time an org admin changed, which is precisely the
// fan-out the topology was chosen to avoid.
func TestOrganizationAdminsAreNotDirectAdmins(t *testing.T) {
	t.Parallel()

	w := created(t)
	if w.IsAdmin("sub_org_owner") {
		t.Fatal("an organization owner reports as a DIRECT workspace admin. Inheritance is " +
			"OpenFGA's answer; modelling it here means this aggregate has to be told about " +
			"every org admin change, which is the fan-out the topology avoids")
	}
}

// An archived workspace is read-only, and restoring brings it back.
func TestArchivingIsReversibleAndReadOnly(t *testing.T) {
	t.Parallel()

	w := created(t)
	if err := w.Archive(at); err != nil {
		t.Fatalf("Archive: %v", err)
	}
	if w.Status() != domain.StatusArchived {
		t.Fatalf("status is %s, want archived", w.Status())
	}

	if err := w.Rename("Renamed", at); err == nil {
		t.Error("an archived workspace accepted a rename; archived is read-only")
	}
	if err := w.AddAdmin("sub_bob", at); err == nil {
		t.Error("an archived workspace accepted an admin change")
	}

	if err := w.Restore(at); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if w.Status() != domain.StatusActive {
		t.Errorf("after restore the status is %s, want active", w.Status())
	}
	if err := w.Rename("Renamed", at); err != nil {
		t.Errorf("a restored workspace still refuses changes: %v", err)
	}
}

// Archiving twice is a no-op rather than an error.
func TestArchivingIsIdempotent(t *testing.T) {
	t.Parallel()

	w := created(t)
	if err := w.Archive(at); err != nil {
		t.Fatalf("Archive: %v", err)
	}
	before := len(w.Uncommitted())
	if err := w.Archive(at); err != nil {
		t.Fatalf("archiving twice: %v", err)
	}
	if len(w.Uncommitted()) != before {
		t.Error("archiving an archived workspace recorded a second event")
	}
}

// A workspace outside an organization cannot exist.
func TestAWorkspaceRequiresAnOrganization(t *testing.T) {
	t.Parallel()

	w := domain.NewWorkspace()
	if err := w.Create("ws_1", "", "Engineering", "sub_alice", at); err == nil {
		t.Fatal("a workspace was created outside any organization; it would have no " +
			"subscription, no quota, and nothing for row security to key on")
	}
	if err := w.Create("ws_1", "org_1", "Engineering", "", at); err == nil {
		t.Fatal("a workspace was created with no creator, so it has no first admin")
	}
}

// The zero value denies.
func TestAnUnloadedWorkspaceIsNotUsable(t *testing.T) {
	t.Parallel()

	w := domain.NewWorkspace()
	if w.Exists() {
		t.Error("an empty aggregate reports that it exists")
	}
	if w.Status() != domain.StatusUnknown {
		t.Errorf("the zero status is %q, want unknown", w.Status())
	}
	if err := w.Rename("x", at); err == nil {
		t.Error("a workspace that does not exist was renamed")
	}
}

// Replay reaches the same state as the commands did.
func TestReplayReachesTheSameState(t *testing.T) {
	t.Parallel()

	live := created(t)
	if err := live.AddAdmin("sub_bob", at); err != nil {
		t.Fatalf("AddAdmin: %v", err)
	}
	if err := live.Rename("Platform", at); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if err := live.Archive(at); err != nil {
		t.Fatalf("Archive: %v", err)
	}

	replayed := domain.NewWorkspace()
	for _, e := range live.Uncommitted() {
		replayed.Apply(e)
	}

	if replayed.Status() != live.Status() {
		t.Errorf("replayed status %s, live %s", replayed.Status(), live.Status())
	}
	if replayed.Name() != live.Name() {
		t.Errorf("replayed name %q, live %q", replayed.Name(), live.Name())
	}
	if !replayed.IsAdmin("sub_bob") {
		t.Error("the admin grant did not survive replay")
	}
	if replayed.OrgID() != live.OrgID() {
		t.Error("the organization did not survive replay; every workspace row carries it " +
			"for row security")
	}
}

// Admins() hands out a copy.
func TestAdminsCannotBeMutatedThroughTheAccessor(t *testing.T) {
	t.Parallel()

	w := created(t)
	got := w.Admins()
	got[0] = "sub_mallory"
	if w.IsAdmin("sub_mallory") {
		t.Error("editing the slice returned by Admins() changed who administers the workspace")
	}
}
