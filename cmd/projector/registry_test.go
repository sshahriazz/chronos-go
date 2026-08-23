package main

import (
	"slices"
	"testing"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// EVERY PROJECTION IS NAMED, AND THE NAMES ARE UNIQUE.
//
// # The failure this catches
//
// A projection's name keys its checkpoint row AND its single-writer lease. Two
// projections sharing one would fight over the lease and overwrite each other's
// position — so one of them silently stops advancing, and the table it builds
// stops being rebuildable from the log.
//
// It is checked here rather than trusted because the names are string constants
// in eleven files, and nothing but this compares them.
func TestEveryProjectionHasAUniqueName(t *testing.T) {
	views := projections(eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry()))
	if len(views) == 0 {
		t.Fatal("the projector runs no projections; every read model is permanently empty")
	}

	seen := map[string]bool{}
	for _, v := range views {
		name := v.Name()
		if name == "" {
			t.Errorf("%T has no name; its checkpoint and its lease are keyed on nothing", v)
			continue
		}
		if seen[name] {
			t.Errorf("two projections are called %q. They share a checkpoint row and a "+
				"single-writer lease, so one of them silently stops advancing and its "+
				"table stops being rebuildable", name)
		}
		seen[name] = true
	}
}

// COMPLIANCE'S PROJECTIONS ARE AMONG THEM.
//
// Named explicitly rather than counted, because both were absent from a
// different registry — protocolit's — while its comment claimed to run every
// projection this one runs. The failure is silent in the direction that matters:
// a data-subject request is accepted, the log agrees, and the person's poll
// answers "not found" forever, while Article 15's one-month clock runs out.
//
// Adding a module that projects and forgetting it here fails this test rather
// than a subject access request.
func TestTheProjectorRunsCompliancesProjections(t *testing.T) {
	var names []string
	for _, v := range projections(eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())) {
		names = append(names, v.Name())
	}
	for _, want := range []string{"processing_restriction_view", "data_export_view"} {
		if !slices.Contains(names, want) {
			t.Errorf("the projector does not run %q. Whatever reads that table sees an "+
				"empty one forever, with no error anywhere", want)
		}
	}
}
