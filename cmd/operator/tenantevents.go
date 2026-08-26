package main

import (
	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/modules/organization"
	"github.com/chronos/chronos-go/internal/modules/workspace"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// registerTenantEvents declares the TENANT types the customer directory is
// projected from.
//
// Two modules, and only two. That narrowness is deliberate and it is worth
// stating, because the obvious thing to write here is the same list
// cmd/projector has — every module, registered wholesale, "so nothing is
// missing".
//
// It would be wrong here in a way it is not there. This binary decodes an event
// only to build `operator_customer_list`, and that table's columns are
// org-level by design (operator.md §4). Registering identity, billing,
// notification and compliance would put every personal-data-adjacent event
// type this system has into the operator plane's decoder — reachable, decodable,
// one handler away from a column that should not exist.
//
// So the rule is: a module appears here when the directory projects one of its
// events, and adding one is the same reviewable step as adding a column.
func registerTenantEvents(codec *eventcodec.JSON, upcasters *eventsourcing.UpcasterRegistry) {
	organization.RegisterEvents(codec)
	organization.RegisterSchemas(upcasters)

	workspace.RegisterEvents(codec)
	workspace.RegisterSchemas(upcasters)
}
