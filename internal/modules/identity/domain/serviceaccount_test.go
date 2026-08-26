package domain_test

import (
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// A service account's name refuses free text, and this is an ADR-002 control
// rather than a formatting preference.
//
// The rejected values are the ones somebody would actually type. "alice's deploy
// bot" is the case that matters: the name goes into an event in cleartext, the
// log is append-only, and a colleague's name written there can never be erased.
func TestAServiceAccountNameCannotCarryFreeText(t *testing.T) {
	refused := map[string]string{
		"a person's name":       "alices_bot", // allowed by shape — see the note below
		"an apostrophe":         "alice's bot",
		"a sentence":            "deploy bot for the payments team",
		"an address":            "alice@example.com",
		"upper case":            "DeployBot",
		"a leading digit":       "1bot",
		"a leading underscore":  "_bot",
		"punctuation":           "deploy-bot",
		"empty":                 "",
		"over the length bound": strings.Repeat("a", domain.MaxServiceAccountNameLen+1),
	}
	for name, value := range refused {
		if name == "a person's name" {
			// Deliberately NOT asserted as refused. The pattern cannot recognise a
			// name, and claiming it could would be a false promise: what it removes
			// is the SHAPE free text arrives in — spaces, punctuation, sentences —
			// which is what turns a label field into a place people write about
			// each other. It is recorded here so the limit of the control is
			// visible in the test rather than only in a comment.
			continue
		}
		t.Run(name, func(t *testing.T) {
			s := eventsourcing.NewAggregate(domain.NewServiceAccount)
			err := s.Create(newID[ids.ServiceAccount](t), testOrg, value, "subj_actor", at)
			if err == nil {
				t.Fatalf("%q was accepted as a service account name; free text here reaches "+
					"an append-only log, which erasure cannot touch (ADR-002)", value)
			}
			if len(s.Uncommitted()) != 0 {
				t.Fatalf("a refused creation recorded %d events", len(s.Uncommitted()))
			}
		})
	}
}

// A service account records who created it, because the event has no data
// subject and the notification is addressed to the ACTOR.
//
// Without an actor, `notify.SubjectAudiences` refuses the audience and the
// reactor parks the message — a security alert silently not delivered, which is
// the failure mode this repository has already shipped three times in
// notification adapters.
func TestAServiceAccountRecordsItsCreator(t *testing.T) {
	s := eventsourcing.NewAggregate(domain.NewServiceAccount)
	err := s.Create(newID[ids.ServiceAccount](t), testOrg, "deploy_bot", "", at)
	if err == nil {
		t.Fatal("a service account with no creator was accepted; an event with no actor is " +
			"one AudienceActor cannot resolve, so the alert about a new non-human " +
			"principal is parked rather than sent")
	}
}

// A service account belongs to exactly one organization, and creation refuses
// one with none.
func TestAServiceAccountBelongsToOneOrganization(t *testing.T) {
	s := eventsourcing.NewAggregate(domain.NewServiceAccount)
	if err := s.Create(newID[ids.ServiceAccount](t), "", "deploy_bot", "subj_actor", at); err == nil {
		t.Fatal("a service account with no organization was created; there is nothing for " +
			"row-level security to scope it by and no revocation path can find it")
	}
}

// Creating a service account gives it NOTHING to authenticate with.
//
// The split is the design: creating a principal and giving it a way in are two
// decisions, the second is the one that changes what can happen, and an incident
// timeline has to tell them apart. A creation event that carried a credential —
// or a second event minting one — would collapse them.
func TestCreatingAServiceAccountMintsNoCredential(t *testing.T) {
	s := eventsourcing.NewAggregate(domain.NewServiceAccount)
	if err := s.Create(newID[ids.ServiceAccount](t), testOrg, "deploy_bot", "subj_actor", at); err != nil {
		t.Fatalf("create: %v", err)
	}

	pending := s.Uncommitted()
	if len(pending) != 1 {
		t.Fatalf("creation recorded %d events, want exactly 1; a second event here would be "+
			"a credential minted by the same call that created the principal", len(pending))
	}
	if _, ok := pending[0].(*contract.ServiceAccountCreated); !ok {
		t.Fatalf("creation recorded a %T, want *contract.ServiceAccountCreated", pending[0])
	}
}

// A second creation on the same aggregate is a conflict.
//
// The stream's expected-revision precondition is what really enforces this; the
// aggregate refuses it too so a caller that reached the command another way gets
// an error rather than a second creation event on one stream.
func TestAServiceAccountCannotBeCreatedTwice(t *testing.T) {
	s := eventsourcing.NewAggregate(domain.NewServiceAccount)
	id := newID[ids.ServiceAccount](t)
	if err := s.Create(id, testOrg, "deploy_bot", "subj_actor", at); err != nil {
		t.Fatalf("create: %v", err)
	}
	s.ClearUncommitted()

	if err := s.Create(id, testOrg, "other_bot", "subj_actor", at); err == nil {
		t.Fatal("a service account was created twice on one stream; the second creation " +
			"would rename the principal with no rename event in the log")
	}
}
