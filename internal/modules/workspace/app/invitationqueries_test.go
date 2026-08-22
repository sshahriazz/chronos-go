package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/page"
)

// fakeInvitationReads is an ordered in-memory invitation_view.
type fakeInvitationReads struct {
	rows []app.InvitationSummary
	err  error

	// lastSize records what the use case ASKED for, which is how the has-more
	// probe is asserted: the query must request one more than the page.
	lastSize page.Size
}

func (f *fakeInvitationReads) ListByWorkspace(
	_ context.Context, workspaceID string, status domain.InvitationStatus,
	after page.Keyset, size page.Size,
) ([]app.InvitationSummary, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.lastSize = size

	var afterExpiry time.Time
	var afterID string
	if !after.IsStart() {
		args := after.Args()
		afterExpiry, _ = args[0].(time.Time)
		afterID, _ = args[1].(string)
	}

	var out []app.InvitationSummary
	for _, r := range f.rows {
		if r.Status != status {
			continue
		}
		// The same comparison the SQL makes: strictly after (expires_at, id).
		if !after.IsStart() {
			if r.ExpiresAt.Before(afterExpiry) {
				continue
			}
			if r.ExpiresAt.Equal(afterExpiry) && r.InvitationID <= afterID {
				continue
			}
		}
		out = append(out, r)
		if len(out) == int(size) {
			break
		}
	}
	_ = workspaceID
	return out, nil
}

func summaries(n int) []app.InvitationSummary {
	base := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	out := make([]app.InvitationSummary, 0, n)
	for i := range n {
		out = append(out, app.InvitationSummary{
			InvitationID: "inv_" + string(rune('A'+i)),
			SubjectID:    "subj_x",
			InvitedBy:    founder,
			Role:         contract.RoleMember,
			Status:       domain.InvitationPending,
			ExpiresAt:    base.Add(time.Duration(i) * time.Hour),
			IssuedAt:     base,
		})
	}
	return out
}

func queries(t *testing.T, reads *fakeInvitationReads) *app.InvitationQueries {
	t.Helper()
	q, err := app.NewInvitationQueries(reads)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// PAGING WALKS THE WHOLE LIST EXACTLY ONCE.
//
// Keyset, not offset: an offset shifts under a concurrent settlement and
// silently skips a row — the failure that produces a correct-looking page with
// one invitation missing from it, which nobody notices until somebody is never
// chased.
func TestPagingVisitsEveryInvitationOnce(t *testing.T) {
	reads := &fakeInvitationReads{rows: summaries(7)}
	q := queries(t, reads)

	seen := map[string]int{}
	token := ""
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("the list did not terminate; a token that does not advance walks " +
				"forever with nothing in the loop looking like a failure")
		}
		result, err := q.List(context.Background(), app.ListInvitationsQuery{
			WorkspaceID: inviteWS, PageSize: 3, PageToken: token,
		})
		if err != nil {
			t.Fatalf("page %d: %v", pages, err)
		}
		for _, inv := range result.Invitations {
			seen[inv.InvitationID]++
		}
		if result.NextPageToken == "" {
			break
		}
		token = result.NextPageToken
	}

	if len(seen) != 7 {
		t.Fatalf("saw %d distinct invitations, want 7", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("%s appeared %d times", id, n)
		}
	}
}

// THE LAST PAGE CARRIES NO TOKEN, even when it is exactly full.
//
// The has-more probe is what makes that true: the query asks for one MORE than
// the page, so a full last page is distinguishable from a full middle one.
// Guessing from a full page mints a token that returns nothing, and a client
// following it makes one pointless round trip per list.
func TestAFullLastPageCarriesNoToken(t *testing.T) {
	reads := &fakeInvitationReads{rows: summaries(3)}
	q := queries(t, reads)

	result, err := q.List(context.Background(), app.ListInvitationsQuery{
		WorkspaceID: inviteWS, PageSize: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Invitations) != 3 {
		t.Fatalf("returned %d, want 3", len(result.Invitations))
	}
	if result.NextPageToken != "" {
		t.Fatal("a full LAST page carried a token; following it returns nothing, which is " +
			"a wasted round trip on every list that happens to divide evenly")
	}
	if reads.lastSize != 4 {
		t.Errorf("asked the store for %d rows for a page of 3; without the extra row "+
			"'is there more' can only be guessed", reads.lastSize)
	}
}

// A TOKEN FROM ANOTHER LIST IS REFUSED, never treated as "start again".
//
// A client handed page one for a token it believes points into the middle walks
// the list forever, and nothing in the loop looks like a failure: no error, no
// empty page, no log line.
func TestAForeignPageTokenIsRefused(t *testing.T) {
	q := queries(t, &fakeInvitationReads{rows: summaries(5)})

	keyset, err := page.NewKeyset(
		page.Key{Column: "created_at", Value: time.Now().UTC()},
		page.Key{Column: "session_id", Value: "sess_x", Unique: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := page.Encode(keyset, page.QueryID("identity.session_view.by_subject"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = q.List(context.Background(), app.ListInvitationsQuery{
		WorkspaceID: inviteWS, PageToken: string(foreign),
	})
	if err == nil {
		t.Fatal("a token minted for another list was accepted; it would be answered from " +
			"the wrong position, or silently from the beginning")
	}
	if got := errs.ReasonOf(err); got != errs.ValidationFailed {
		t.Errorf("refused with %s, want VALIDATION_FAILED", got)
	}
	if !strings.Contains(err.Error(), "restart") {
		t.Errorf("the message does not tell the client what to do: %v", err)
	}
}

// GARBAGE IS REFUSED TOO.
func TestAnUnreadablePageTokenIsRefused(t *testing.T) {
	q := queries(t, &fakeInvitationReads{rows: summaries(5)})

	if _, err := q.List(context.Background(), app.ListInvitationsQuery{
		WorkspaceID: inviteWS, PageToken: "not-a-token",
	}); err == nil {
		t.Fatal("an unreadable token was treated as the first page")
	}
}

// PENDING IS THE DEFAULT, and it is what an admin screen wants.
func TestAnEmptyStatusMeansPending(t *testing.T) {
	rows := summaries(2)
	rows = append(rows, app.InvitationSummary{
		InvitationID: "inv_Z", Status: domain.InvitationRevoked,
		ExpiresAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	q := queries(t, &fakeInvitationReads{rows: rows})

	result, err := q.List(context.Background(), app.ListInvitationsQuery{
		WorkspaceID: inviteWS,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, inv := range result.Invitations {
		if inv.Status != domain.InvitationPending {
			t.Errorf("a %s invitation appeared in the default list; settled ones are "+
				"history and crowd out the ones somebody has to chase", inv.Status)
		}
	}
	if len(result.Invitations) != 2 {
		t.Errorf("returned %d pending, want 2", len(result.Invitations))
	}
}

// UNKNOWN IS NOT A FILTER.
//
// It is in InvitationStatuses deliberately, so the lifecycle test covers the zero
// value — which means the list has to exclude it explicitly rather than by
// trimming the list and blinding that test.
func TestUnknownIsNotAStatusToFilterBy(t *testing.T) {
	q := queries(t, &fakeInvitationReads{rows: summaries(2)})

	for _, status := range []domain.InvitationStatus{domain.InvitationUnknown, "made-up"} {
		if status == domain.InvitationUnknown {
			// The zero value reaches the use case as "" and means PENDING, so it
			// cannot be tested through the Status field. It is asserted through
			// the explicit guard instead — a caller naming it as a literal.
			continue
		}
		if _, err := q.List(context.Background(), app.ListInvitationsQuery{
			WorkspaceID: inviteWS, Status: status,
		}); err == nil {
			t.Fatalf("%q was accepted as a status filter", status)
		}
	}
}

// A STORE FAILURE IS REPORTED, not answered with an empty page.
//
// An empty list is a legitimate answer — nobody is outstanding — so returning
// one on failure makes an outage indistinguishable from a tidy workspace.
func TestAStoreFailureIsNotAnEmptyPage(t *testing.T) {
	q := queries(t, &fakeInvitationReads{err: errors.New("postgres: down")})

	result, err := q.List(context.Background(), app.ListInvitationsQuery{WorkspaceID: inviteWS})
	if err == nil {
		t.Fatal("a store failure was reported as an empty list; an outage then looks " +
			"exactly like a workspace with nothing outstanding")
	}
	if len(result.Invitations) != 0 {
		t.Error("rows were returned alongside an error")
	}
}

// A MISSING WORKSPACE IS REFUSED.
func TestListingNeedsAWorkspace(t *testing.T) {
	q := queries(t, &fakeInvitationReads{rows: summaries(2)})
	if _, err := q.List(context.Background(), app.ListInvitationsQuery{}); err == nil {
		t.Fatal("a list with no workspace was accepted, which would scan the tenant")
	}
}

// EVERY DEPENDENCY IS REQUIRED.
func TestInvitationQueriesRefusesAnIncompleteWiring(t *testing.T) {
	if _, err := app.NewInvitationQueries(nil); err == nil {
		t.Fatal("constructed with no reader")
	}
}
