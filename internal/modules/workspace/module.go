// Package workspace is the module's composition surface.
//
// The declarations every binary that touches workspace events must make, in one
// place — because a type registered in two of three binaries is a projector that
// stops on an event the API can happily write.
package workspace

import (
	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// RegisterEvents declares every workspace event this build can DECODE.
func RegisterEvents(codec *eventcodec.JSON) {
	eventcodec.Register[contract.WorkspaceCreated](codec)
	eventcodec.Register[contract.WorkspaceRenamed](codec)
	eventcodec.Register[contract.WorkspaceArchived](codec)
	eventcodec.Register[contract.WorkspaceRestored](codec)
	eventcodec.Register[contract.WorkspaceAdminAdded](codec)
	eventcodec.Register[contract.WorkspaceAdminRemoved](codec)
	eventcodec.Register[contract.MemberJoined](codec)
	eventcodec.Register[contract.MemberRoleChanged](codec)
	eventcodec.Register[contract.MemberRemoved](codec)
}

// RegisterSchemas declares the current schema version of every workspace event
// (ADR-029).
func RegisterSchemas(r *eventsourcing.UpcasterRegistry) {
	for _, t := range eventTypes() {
		r.Register(t, 1)
	}
}

// EventTypes is what this module declares, so a composition-root test can assert
// what a binary registers.
func EventTypes() []string { return eventTypes() }

func eventTypes() []string {
	return []string{
		(&contract.WorkspaceCreated{}).EventType(),
		(&contract.WorkspaceRenamed{}).EventType(),
		(&contract.WorkspaceArchived{}).EventType(),
		(&contract.WorkspaceRestored{}).EventType(),
		(&contract.WorkspaceAdminAdded{}).EventType(),
		(&contract.WorkspaceAdminRemoved{}).EventType(),
		(&contract.MemberJoined{}).EventType(),
		(&contract.MemberRoleChanged{}).EventType(),
		(&contract.MemberRemoved{}).EventType(),
	}
}
