package main

// WHAT USED TO BE HERE: TestTheExportAndTheErasureWalkTheSamePrefixes.
//
// It could not do what its name said. The export's prefix list lived in this
// binary and the erasure's lived in cmd/worker, and a `main` package is
// importable by nothing — so the test could not see the other list. What it
// actually did was compare THIS binary's copy against a third hand-written
// literal inside itself, and cmd/worker had a second test comparing its copy
// against the same literal. Two copies held equal by agreeing with a third that
// nobody would remember to update.
//
// That is the same failure the projection registry had, twice, before it was
// collapsed into internal/projections: a consistency check between copies is
// only ever as good as the copy nobody updates.
//
// Both lists are gone. `internal/subjectgraph` holds the one graph, assembled
// from per-module declarations, and every process that erases or exports calls
// `Prefixes` on it — so "export and erasure traverse the same subject graph"
// (compliance.md §16) is true by construction and there is nothing left for a
// test to compare.
//
// What replaced it is in internal/subjectgraph: the graph assembles or the
// process does not start, every vault field has a declared writer or a named
// reason, and the traversal covers profile's avatars.
