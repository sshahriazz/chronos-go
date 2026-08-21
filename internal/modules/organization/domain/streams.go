package domain

import "github.com/chronos/chronos-go/internal/platform/eventsourcing"

// Category is the stream category every organization stream lives under.
//
// One category for the module, so a projector reads `$ce-organization` instead
// of scanning the whole log on every rebuild (ADR-042).
const Category eventsourcing.Category = "organization"

// StreamKey names the stream holding one organization's history.
//
// The org id itself. Unlike a person, an organization is not a data subject —
// there is no pseudonym to protect and nothing for erasure to destroy — so
// there is no reason to key it by a digest and every reason to keep the log
// readable while debugging.
//
// A prefixed public id separates its prefix with '_' and never '-' (ADR-030),
// which is what makes it safe as a stream key: KurrentDB derives a stream's
// category from everything before the FIRST dash, so a key containing one files
// the stream under the wrong category and breaks every prefix-filtered
// subscription. eventsourcing.NewStreamID enforces it.
func StreamKey(orgID string) string { return orgID }
