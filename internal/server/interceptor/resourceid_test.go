package interceptor

import (
	"strings"
	"testing"

	workspacev1 "github.com/chronos/chronos-go/gen/proto/chronos/workspace/v1"
	"github.com/chronos/chronos-go/internal/server/policy"
)

// resourceIDFor decides WHICH object gate 2 asks about, and getting it wrong is
// silent in both directions.
//
// Reading the wrong field asks about the wrong object; falling back to the
// organization asks about a DIFFERENT object than the schema declared, and in
// the permissive direction — org `admin` is inherited by every workspace through
// the `parent` edge, so a fallback would grant an org admin everything the check
// was meant to scope.
//
// The declaration existed for months before this function could honour it: it
// returned ErrGateUnavailable for every method that named a field, so the three
// workspace member RPCs are the first that could ever have been gated at all.
func TestResourceIDFor(t *testing.T) {
	const workspaceID = "ws_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	const orgID = "org_01ARZ3NDEKTSV4RRFFQ69G5FAV"

	named := policy.Policy{
		Method:          "/chronos.workspace.v1.WorkspaceService/AddWorkspaceMember",
		ResourceType:    "workspace",
		ResourceIDField: "workspace_id",
	}
	scoped := policy.Policy{
		Method:       "/chronos.workspace.v1.WorkspaceService/CreateWorkspace",
		ResourceType: "organization",
	}

	tests := []struct {
		name    string
		policy  policy.Policy
		orgID   string
		msg     any
		want    string
		wantErr string
		why     string
	}{
		{
			name:   "a named field is read from the request",
			policy: named,
			orgID:  orgID,
			msg:    &workspacev1.AddWorkspaceMemberRequest{WorkspaceId: workspaceID},
			want:   workspaceID,
			why:    "the whole point of naming a field is that the object is the caller's choice",
		},
		{
			name:   "an unnamed field falls back to the resolved organization",
			policy: scoped,
			orgID:  orgID,
			msg:    &workspacev1.CreateWorkspaceRequest{Name: "Engineering"},
			want:   orgID,
			why:    "an org-scoped method asks about the org gate 1 resolved",
		},
		{
			name:    "an EMPTY named field is refused, never fallen back from",
			policy:  named,
			orgID:   orgID,
			msg:     &workspacev1.AddWorkspaceMemberRequest{},
			wantErr: "named no workspace",
			why: "protovalidate runs AFTER the gates, so an empty id reaches here; falling " +
				"back to the organization would check org admin instead, which every org " +
				"admin already holds",
		},
		{
			name:    "a field the message does not have is refused",
			policy:  policy.Policy{Method: "M", ResourceType: "workspace", ResourceIDField: "nope"},
			orgID:   orgID,
			msg:     &workspacev1.AddWorkspaceMemberRequest{WorkspaceId: workspaceID},
			wantErr: "does not have",
			why:     "a renamed field must fail loudly rather than silently widening the check",
		},
		{
			name:    "a non-string field is refused",
			policy:  policy.Policy{Method: "M", ResourceType: "workspace", ResourceIDField: "seat_consumed"},
			orgID:   orgID,
			msg:     &workspacev1.AddWorkspaceMemberResponse{SeatConsumed: true},
			wantErr: "not a string",
			why:     "an id read out of a bool would be the empty string, which is the case above",
		},
		{
			name:    "an org-scoped method with no organization is refused",
			policy:  scoped,
			orgID:   "",
			msg:     &workspacev1.CreateWorkspaceRequest{},
			wantErr: "gate 1 resolved none",
			why:     "checking against an empty org id asks about no object at all",
		},
		{
			name:    "a non-protobuf request is refused",
			policy:  named,
			orgID:   orgID,
			msg:     struct{ WorkspaceID string }{workspaceID},
			wantErr: "not a protobuf message",
			why:     "there is no field to read, and guessing one would be worse than refusing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resourceIDFor(tt.policy, tt.orgID, tt.msg)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("accepted %q, so nothing enforces this: %s", got, tt.why)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("refused for the wrong reason: got %q, want it to mention %q",
						err, tt.wantErr)
				}
				if got != "" {
					t.Errorf("returned %q alongside an error; a caller ignoring the error "+
						"would check against it", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("refused a valid request: %v (%s)", err, tt.why)
			}
			if got != tt.want {
				t.Errorf("asked about %q, want %q — %s", got, tt.want, tt.why)
			}
		})
	}
}
