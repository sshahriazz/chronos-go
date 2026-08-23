//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	orgpg "github.com/chronos/chronos-go/internal/modules/organization/adapter/postgres"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

func memberAudience(t *testing.T) *orgpg.MemberAudience {
	t.Helper()
	a, err := orgpg.NewMemberAudience(pgadapter.New(pool(t)))
	if err != nil {
		t.Fatalf("NewMemberAudience: %v", err)
	}
	return a
}

func freshOrg() string {
	return "org_" + ids.New[ids.Org](time.Now(), ids.Entropy()).String()[4:]
}

// seedMembers writes rows into org_member_index.
//
// A SYSTEM transaction, because the table carries row security and the
// projection that owns it writes under one. Seeding through a tenant scope would
// work too, and would prove less: the resolver reads unscoped, so the test data
// has to exist independently of any scope.
func seedMembers(t *testing.T, orgID string, n int) []string {
	t.Helper()
	pool := pool(t)
	ctx := context.Background()
	subjects := make([]string, 0, n)

	for i := range n {
		subject := "subj_" + ids.New[ids.Subject](time.Now(), ids.Entropy()).String()[5:]
		role := "member"
		if i == 0 {
			role = "owner"
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO org_member_index (org_id, subject_id, role, joined_at)
			 VALUES ($1, $2, $3, now())`, orgID, subject, role); err != nil {
			t.Fatalf("seeding member %d: %v", i, err)
		}
		subjects = append(subjects, subject)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM org_member_index WHERE org_id = $1`, orgID)
	})
	return subjects
}

func envelopeFor(orgID string) eventsourcing.Envelope {
	return eventsourcing.Envelope{Meta: eventsourcing.Metadata{OrgID: orgID}}
}

// EVERY MEMBER IS RESOLVED, NOT JUST THE OWNER.
//
// The whole point of the audience: suspension ends access for all of them, and
// telling only the person who can fix it tells nobody who is affected.
func TestEveryMemberOfTheOrganizationIsResolved(t *testing.T) {
	orgID := freshOrg()
	want := seedMembers(t, orgID, 4)

	got, err := memberAudience(t).Resolve(
		context.Background(), notify.AudienceOrgMembers, envelopeFor(orgID))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("resolved %d recipients, want %d; the members left out have no way to "+
			"notice they were not told", len(got), len(want))
	}

	seen := map[string]bool{}
	for _, r := range got {
		seen[r.SubjectID] = true
		if r.OrgID != orgID {
			t.Errorf("recipient %s carries org %q, want %q; the dispatcher compares this "+
				"against the event's own org and would refuse the mismatch",
				r.SubjectID, r.OrgID, orgID)
		}
	}
	for _, subject := range want {
		if !seen[subject] {
			t.Errorf("member %s was not resolved", subject)
		}
	}
}

// ANOTHER ORGANIZATION'S MEMBERS ARE NOT INCLUDED.
//
// The failure this prevents is a cross-tenant one: a resolver that dropped the
// org filter would tell every customer about somebody else's suspension.
func TestAnotherOrganizationsMembersAreNotResolved(t *testing.T) {
	mine, theirs := freshOrg(), freshOrg()
	want := seedMembers(t, mine, 2)
	seedMembers(t, theirs, 3)

	got, err := memberAudience(t).Resolve(
		context.Background(), notify.AudienceOrgMembers, envelopeFor(mine))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("resolved %d recipients for an organization with %d members; another "+
			"tenant's people are being told about this suspension", len(got), len(want))
	}
}

// AN ORGANIZATION WITH NO MEMBERS IS AN EMPTY ANSWER HERE, AND A FAILURE ABOVE.
//
// The resolver reports what the table says. notify's cardinality rule is what
// turns zero into a refusal — AtLeastOne, because an organization always
// contains at least its owner, so zero means the read model is wrong.
func TestAnOrganizationWithNoMembersResolvesToNobody(t *testing.T) {
	got, err := memberAudience(t).Resolve(
		context.Background(), notify.AudienceOrgMembers, envelopeFor(freshOrg()))
	if err != nil {
		t.Fatalf("an unknown organization errored: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("resolved %d recipients for an organization with no rows", len(got))
	}
}

// AN OVERSIZED ORGANIZATION IS REFUSED, NOT TRUNCATED.
//
// A notification that reaches the first N and silently omits the rest is worse
// than one that fails: the omission is invisible from every side — the sender
// saw a success, and the people left out have nothing to notice.
func TestAnOversizedOrganizationIsRefusedRatherThanTruncated(t *testing.T) {
	orgID := freshOrg()
	pool := pool(t)
	ctx := context.Background()

	// One over the cap, inserted in bulk: seeding 5001 rows one statement at a
	// time is the difference between a fast test and a minute of round trips.
	if _, err := pool.Exec(ctx,
		`INSERT INTO org_member_index (org_id, subject_id, role, joined_at)
		 SELECT $1, 'subj_bulk_' || g, 'member', now()
		 FROM generate_series(1, $2) g`,
		orgID, orgpg.MaxOrgAudience+1); err != nil {
		t.Fatalf("bulk seeding: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM org_member_index WHERE org_id = $1`, orgID)
	})

	_, err := memberAudience(t).Resolve(
		context.Background(), notify.AudienceOrgMembers, envelopeFor(orgID))
	if err == nil {
		t.Fatalf("an organization with %d members resolved without complaint; the fan-out "+
			"was silently truncated and the rest were never told", orgpg.MaxOrgAudience+1)
	}
	if !errors.Is(err, notify.ErrAudienceUnsupported) {
		t.Errorf("returned %v, want ErrAudienceUnsupported so the notification parks", err)
	}
}

// THE RESOLVER ANSWERS ONE AUDIENCE AND REFUSES THE REST.
//
// Registered for AudienceOrgMembers and asked for something else, answering
// would make every audience it was not written for resolve to "everyone in the
// organization" — the widest possible wrong answer.
func TestTheMemberAudienceRefusesOtherAudiences(t *testing.T) {
	orgID := freshOrg()
	seedMembers(t, orgID, 2)

	for _, a := range []notify.Audience{
		notify.AudienceSubject, notify.AudienceActor,
		notify.AudienceOrgOwner, notify.AudienceOrgAdmins, notify.AudienceOperator,
	} {
		t.Run(fmt.Sprint(a), func(t *testing.T) {
			if _, err := memberAudience(t).Resolve(
				context.Background(), a, envelopeFor(orgID)); !errors.Is(
				err, notify.ErrAudienceUnsupported) {
				t.Errorf("%s resolved to every member of the organization", a)
			}
		})
	}
}

// AN EVENT WITH NO ORGANIZATION CANNOT NAME AN AUDIENCE.
//
// An empty org id reaching the query would match rows whose column happens to
// be empty, rather than none.
func TestAnEventWithNoOrganizationIsRefused(t *testing.T) {
	if _, err := memberAudience(t).Resolve(context.Background(),
		notify.AudienceOrgMembers, eventsourcing.Envelope{}); !errors.Is(
		err, notify.ErrAudienceUnsupported) {
		t.Fatal("an event with no organization resolved an audience")
	}
}

// AN INCOMPLETE WIRING IS REFUSED.
func TestTheMemberAudienceRefusesAnIncompleteWiring(t *testing.T) {
	if _, err := orgpg.NewMemberAudience(nil); err == nil {
		t.Error("a resolver with no transaction source was accepted")
	}
}
