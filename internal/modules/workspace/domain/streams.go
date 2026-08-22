package domain

import "github.com/chronos/chronos-go/internal/platform/eventsourcing"

// Category is the stream category every workspace stream lives under.
const Category eventsourcing.Category = "workspace"

// StreamKey names the stream holding one workspace's history.
//
// The workspace id itself. A workspace is not a data subject, so there is no
// pseudonym to protect and nothing for erasure to destroy — the same reasoning
// organization's StreamKey records.
func StreamKey(workspaceID string) string { return workspaceID }
