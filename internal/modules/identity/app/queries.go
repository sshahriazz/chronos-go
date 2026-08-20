package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/page"
)

// ---------------------------------------------------------------------------
// Results
//
// Every shape below is what the SETTINGS SCREENS need and nothing else. The two
// omissions are deliberate and are the point of the file:
//
//  1. No email address, anywhere. This layer holds a SubjectID pseudonym; the
//     vault resolves an address at render time, and erasure is the destruction
//     of a key rather than a migration (ADR-002, compliance.md §1). A read model
//     that returned an address would be a second copy of the personal data with
//     its own lifetime, and erasure would silently stop being complete.
//  2. No secret, in any form. Not a verifier, not a sealed TOTP secret, not a
//     digest, not a recovery code. Those columns exist in `credential` and in
//     `session_token`, and the statements this file uses do not select them —
//     but the STRUCTS are the durable guarantee, because a struct with no field
//     for a verifier cannot acquire one by a query being edited.
// ---------------------------------------------------------------------------

// AccountView is the account, its lifecycle state, and whether the address on it
// has been proven.
//
// It carries the SubjectID because the SubjectID is what the caller hands to the
// vault to render an address. It does NOT carry the email index: the index is a
// lookup key over an address, and an actor who holds the blind-index key and a
// candidate address can confirm a match from it. It has no use on a screen, so
// it does not leave the adapter.
type AccountView struct {
	// SubjectID is the pseudonym. Whoever renders this resolves it.
	SubjectID string

	UserID ids.UserID

	// State is the lifecycle position, as a domain type rather than the
	// projected string. An unrecognised string is an error in the adapter, not
	// StateNone here — StateNone means "does not exist", so a state this build
	// cannot parse would render as a missing account.
	State domain.State

	// EmailVerified answers "did they ever prove the address", which is a
	// different question from State: an account can be verified and still
	// Pending, because a second factor is also required before it activates
	// (identity.md §2).
	EmailVerified bool

	// RegisteredAt is always set. The other three are zero unless the account has
	// been through that transition — a zero time here means "never", not
	// "unknown", because the projector writes each one at the moment it happens.
	RegisteredAt  time.Time
	ActivatedAt   time.Time
	DeactivatedAt time.Time
	SuspendedAt   time.Time
}

// SessionSummary is one entry in the device list.
//
// No token, no digest. The digest lives in session_token, which this list joins
// for the idle deadline and last-seen time and never selects the secret from —
// a device list that returned anything derived from the bearer token would put a
// credential on a screen whose whole purpose is to let a user revoke one.
type SessionSummary struct {
	SessionID ids.SessionID

	// DeviceID is an opaque client-supplied handle, empty when the client sent
	// none. It is NOT a device NAME: a name is personal data the user typed, and
	// it may not enter a projection.
	DeviceID string

	// AAL is the assurance level the session was established at, so a screen can
	// mark a session that has only ever presented one factor.
	AAL contract.AssuranceLevel

	// IdleExpiresAt is the deadline that moves; AbsoluteExpiresAt is the one that
	// does not. Both are shown because they answer different questions: when this
	// device will be signed out for inactivity, and when it will be signed out
	// regardless.
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time

	// CreatedAt is the first half of the sort key, which is why it is here rather
	// than merely useful: a caller cannot page this list without the server
	// having ordered by it.
	CreatedAt time.Time

	// LastSeenAt is zero for a session that has made no request since it was
	// issued.
	LastSeenAt time.Time
}

// AuthMethod is one enrolled authentication method, for the security-settings
// screen.
//
// domain.Method is EMBEDDED rather than copied field by field so that "is this
// usable" has exactly one definition in the system. Usability is a rule —
// enabled and not locked out — and a read model that re-implemented it would
// eventually disagree with the aggregate that enforces it, which is how a screen
// comes to show a factor the login refuses or hide one it accepts.
//
// What is absent is the reason this type exists: no verifier, no sealed secret,
// no pepper version, no failure count. The failure count is left out on its own
// merits — it is a lockout counter, and exposing it tells anyone who reaches the
// screen how many attempts remain before a factor locks.
type AuthMethod struct {
	domain.Method

	// AddedAt is when the method was first provisioned, which is not EnabledAt: a
	// TOTP secret is scanned before it is proven, and the gap between the two is
	// exactly the enrollment the user may have abandoned.
	AddedAt time.Time

	// LastUsedAt is zero for a method that has never taken part in an
	// authentication. "Never used" is the interesting value on this screen, so it
	// is a zero time rather than an omitted field.
	LastUsedAt time.Time
}

// LoginRecord is one entry in "recent activity".
//
// The screen exists to answer one question — "was that me?" — and it can only
// answer it if FAILURES appear too. A history of successes shows a compromised
// account as a quiet, ordinary list.
type LoginRecord struct {
	// ID is the row's sequence number. It is here because it is the UNIQUE tail
	// of the sort key, without which a page boundary between two attempts
	// recorded in the same instant would skip or repeat one.
	//
	// It is a server-side sequence, not a public identifier, and the API layer
	// should not render it: it is global across accounts, so its gaps leak how
	// much authentication traffic the whole system carries.
	ID int64

	Succeeded bool

	// Reason classifies a failure and is empty on success. It is recorded in full
	// here and is NOT what the failing caller was told — an attempt is refused
	// with one undifferentiated answer, because naming which factor was wrong
	// hands an attacker an oracle for the other (ADR-036). Showing it to the
	// account HOLDER, after the fact, is the opposite situation.
	Reason contract.FailureReason

	// Methods are the factors presented. Empty for an attempt refused before any
	// credential was checked.
	Methods []contract.MethodKind

	// AAL is the level the attempt established, and is AAL0 for a failure —
	// nothing was established.
	AAL contract.AssuranceLevel

	DeviceID   string
	OccurredAt time.Time
}

// ---------------------------------------------------------------------------
// Ports
//
// Declared here, by the consumer (ADR-001, CONVENTIONS §2). Four ports rather
// than one because they answer four different questions and one of them reads a
// table that is not a projection at all — a single wide port would let a future
// caller that only needs the device list acquire the ability to read credential
// metadata.
//
// Every one of them is READ-ONLY, and that is a property of identity's read side
// rather than of these interfaces: writes go to KurrentDB and projectors fill
// PostgreSQL (ADR-019). A port here that could write would let a screen change
// state with nothing in the log saying so.
// ---------------------------------------------------------------------------

// AccountReader reads the account projection.
//
// Eventually consistent, and safe here for a reason worth stating: nothing
// DECIDES from this. It renders. A decision taken from a projection can be taken
// twice with two different answers, because the projection is behind the log by
// construction — which is why AccountByEmailIndex deliberately discards the same
// columns this port returns.
type AccountReader interface {
	// Account returns the projected account for a pseudonym.
	//
	// Returns ErrNoSuchSubject when nothing is projected for it. That is the same
	// sentinel UserDirectory uses, and deliberately so: there is one answer for
	// "no such account", and the caller must not be able to tell it apart from
	// any other reason it cannot see one.
	Account(ctx context.Context, subjectID string) (AccountView, error)
}

// SessionReader lists a subject's live sessions, newest first.
//
// The cursor is a page.Keyset rather than a pair of arguments so the adapter
// cannot invent its own ordering: the keyset carries the sort columns in ORDER
// BY order, and a keyset whose last column is not unique cannot be constructed
// at all (platform/page).
type SessionReader interface {
	// Sessions returns at most limit rows strictly after the cursor. A cursor
	// that IsStart means the first page.
	//
	// limit is Size.Limit() — one MORE than the page size. The extra row exists
	// to prove another page follows and is trimmed by page.Of before anything is
	// returned to a caller.
	Sessions(ctx context.Context, subjectID string, after page.Keyset, limit int32) ([]SessionSummary, error)
}

// MethodReader lists the authentication methods on an account.
//
// It reads `credential`, which is the one identity table that is NOT a
// projection: verifiers and sealed TOTP secrets can never enter an event, so no
// replay could restore them (identity.md, migration 00009). Reading it here is
// therefore a read of a system of record, and the discipline that follows is
// that the port returns METADATA — what exists, whether it works, when it was
// last used — and never the columns that make the table authoritative.
type MethodReader interface {
	// Methods returns every method on the account, usable or not, newest first.
	//
	// Unpaginated, and bounded by enrollment rather than by a LIMIT: an account
	// holds at most one usable credential per kind, and there are five kinds. A
	// long tail of disabled rows is possible in principle and has never been
	// observed; if it becomes real this port gains a cursor like the other two.
	Methods(ctx context.Context, subjectID string) ([]AuthMethod, error)
}

// LoginHistoryReader lists authentication attempts against an account.
type LoginHistoryReader interface {
	// LoginHistory returns at most limit rows strictly after the cursor, newest
	// first. As with Sessions, limit is one more than the page size.
	LoginHistory(ctx context.Context, subjectID string, after page.Keyset, limit int32) ([]LoginRecord, error)
}

// ---------------------------------------------------------------------------
// Cursors
// ---------------------------------------------------------------------------

// The sort keys, in ORDER BY order. Each ENDS IN A UNIQUE COLUMN, which is the
// property the whole pagination scheme rests on: `session_id` and the login
// history's `id` identify at most one row each, so no two rows share a complete
// cursor and no page boundary can fall in the middle of a group.
//
// A tie-less tail would fail loudly — page.NewKeyset refuses a key whose last
// column is not marked unique — but the failure that matters is the one it
// prevents, which has no error and no log line: rows sharing `created_at`
// straddling a boundary, some skipped and some returned twice.
var (
	sessionSortColumns      = []string{"created_at", "session_id"}
	loginHistorySortColumns = []string{"occurred_at", "id"}
)

// sessionsQueryID names the query a session cursor belongs to.
//
// It includes the SUBJECT, because the subject is a filter value and a cursor is
// a position in one specific filter and sort (platform/page). Binding it means a
// token minted for one account is a decode failure against another rather than a
// position in a list it was never taken from. S1-24 will refuse the request
// before it reaches here; this makes the token itself unusable, so the two
// controls fail independently.
//
// The QueryID is hashed into the token rather than stored, so the pseudonym does
// not travel in a cursor that ends up in an access log.
func sessionsQueryID(subjectID string) page.QueryID {
	return page.QueryID("identity.sessions:subject=" + subjectID + ":created_at desc,session_id desc")
}

// loginHistoryQueryID names the query a login-history cursor belongs to.
//
// A different string from sessionsQueryID for the same subject, which is what
// makes a device-list token unusable against the activity list. The two orderings
// are over different columns, so a cursor reused between them would compare a
// session id against a bigint and return whatever the driver made of it.
func loginHistoryQueryID(subjectID string) page.QueryID {
	return page.QueryID("identity.login_history:subject=" + subjectID + ":occurred_at desc,id desc")
}

// sessionCursor is the position of a session row in the device list.
//
// It is called on the LAST row of a trimmed page, never on the peeked one —
// page.Of enforces that ordering, and keying the peeked row would resume one row
// late and skip it.
//
// The error is swallowed into a zero Keyset because page.Of's signature takes no
// error, and a zero Keyset is not silently harmless: Encode refuses to write a
// token for the start position, so the failure surfaces as an error from
// ListSessions rather than as a token that lies about where it points. It cannot
// actually happen for a time.Time and a string — both are types the cursor
// encoding accepts — which is why this is a guard and not a branch with a test.
func sessionCursor(s SessionSummary) page.Keyset {
	k, err := page.NewKeyset(
		page.Key{Column: sessionSortColumns[0], Value: s.CreatedAt.UTC()},
		page.Key{Column: sessionSortColumns[1], Value: s.SessionID.String(), Unique: true},
	)
	if err != nil {
		return page.Keyset{}
	}
	return k
}

// loginCursor is the position of a login-history row. See sessionCursor.
func loginCursor(r LoginRecord) page.Keyset {
	k, err := page.NewKeyset(
		page.Key{Column: loginHistorySortColumns[0], Value: r.OccurredAt.UTC()},
		page.Key{Column: loginHistorySortColumns[1], Value: r.ID, Unique: true},
	)
	if err != nil {
		return page.Keyset{}
	}
	return k
}

// resumeAt decodes a request's page token for one specific query.
//
// Every failure is an ERROR and none of them is "start from the beginning". A
// client handed page one for a token it believes points into the middle of a list
// walks that list forever, and nothing in the loop looks like a failure — no
// error, no empty page, no log line (platform/page).
//
// The column check is a second lock on the same door. page.Decode already refuses
// a token whose query fingerprint does not match, so a mismatched column list can
// only arrive through a collision in a 64-bit FNV hash; the check costs a slice
// compare and turns that from "the wrong rows, silently" into a refusal.
//
// It SURVIVES its mutation, and that is recorded rather than hidden: no test here
// can reach it, because reaching it needs two QueryIDs that hash alike and this
// file cannot construct such a pair. Removing it passes the whole suite. It is
// kept because the failure it covers produces rows rather than an error, and
// because it is what caught a mutation that gave both lists the same QueryID.
func resumeAt(tok page.Token, q page.QueryID, columns []string) (page.Keyset, error) {
	cursor, err := page.Resume(tok, q)
	if err != nil {
		return page.Keyset{}, errs.ValidationFailedf(
			"this page token cannot be used for this list; restart from the first page").Wrap(err)
	}
	if cursor.IsStart() {
		return cursor, nil
	}
	if got := cursor.Columns(); !slices.Equal(got, columns) {
		return page.Keyset{}, errs.ValidationFailedf(
			"this page token names the columns %v, but this list is sorted by %v", got, columns)
	}
	return cursor, nil
}

// pageSize resolves a requested page size.
//
// A size over the maximum is capped rather than refused, which is page.Clamp's
// decision and not this file's: a client asking for too much still gets a correct
// answer plus a token, so capping costs it a round trip where refusing costs it
// the feature. A NEGATIVE size is a caller bug and is refused.
func pageSize(requested int) (page.Size, error) {
	size, err := page.Clamp(requested)
	if err != nil {
		return 0, errs.ValidationFailedf("page size: %v", err).Wrap(err)
	}
	return size, nil
}

// ---------------------------------------------------------------------------
// The read side
// ---------------------------------------------------------------------------

// Queries is identity's read side: the account screen and the security-settings
// screen.
//
// It WRITES NOTHING, and that is structural rather than a convention it happens
// to follow — every port it holds is a read, so there is no write for a bug to
// reach. Identity's state changes are events appended to KurrentDB and projected
// into these tables by cmd/projector; a query handler that wrote a row would put
// state in PostgreSQL that no replay could reproduce, and the next rebuild would
// delete it (ADR-019).
//
// Everything here is scoped to ONE subject, always supplied by the caller. There
// is deliberately no "list all users": identity's tables carry no row-level
// security — a user exists before any organization, so there is no workspace_id
// to scope by — and the whole tenant boundary on this path is therefore the
// subject the caller passes plus the check that it is theirs.
//
// # The authorization seam
//
// THIS TYPE DOES NOT AUTHORIZE. It answers for whatever subject it is handed,
// and S1-24 is what establishes that the subject IS the authenticated caller.
// Until that lands, calling any method here with somebody else's pseudonym
// returns their sessions and their method list.
//
// The consequence for error handling is already honoured below: an unknown
// subject is NotFound with no detail, and it must stay indistinguishable from
// "that account is not yours" once the check exists. Two different answers would
// make this an account-existence oracle for anyone holding a pseudonym.
type Queries struct {
	accounts AccountReader
	sessions SessionReader
	methods  MethodReader
	history  LoginHistoryReader
}

// QueriesDeps is what the read side needs.
type QueriesDeps struct {
	Accounts AccountReader
	Sessions SessionReader
	Methods  MethodReader
	History  LoginHistoryReader
}

// NewQueries builds the read side, refusing a partial one.
//
// Every port is required. A nil one would panic on the first request to the
// screen that uses it — after the composition root reported a healthy start —
// which is the failure mode a compile-time-wired application exists to avoid.
func NewQueries(deps QueriesDeps) (*Queries, error) {
	missing := func(name string) error {
		return fmt.Errorf("identity/app: the read side needs %s", name)
	}
	switch {
	case deps.Accounts == nil:
		return nil, missing("an account reader")
	case deps.Sessions == nil:
		return nil, missing("a session reader")
	case deps.Methods == nil:
		return nil, missing("a method reader")
	case deps.History == nil:
		return nil, missing("a login-history reader")
	}
	return &Queries{
		accounts: deps.Accounts,
		sessions: deps.Sessions,
		methods:  deps.Methods,
		history:  deps.History,
	}, nil
}

// GetUser returns the account for a pseudonym: what it is, where it is in its
// lifecycle, and whether its address has been proven.
//
// No address comes back. The caller holds a SubjectID and asks the vault, which
// is what keeps erasure a key destruction rather than a sweep across every
// projection that ever copied an address (ADR-002).
//
// An unknown subject is NotFound with no detail, and the detail is withheld on
// purpose. Once S1-24 checks that the subject is the caller's own, "no such
// account" and "not your account" must produce the identical answer — a caller
// able to tell them apart can test pseudonyms for existence.
func (q *Queries) GetUser(ctx context.Context, subjectID string) (AccountView, error) {
	if subjectID == "" {
		// Refused rather than answered with "not found". An empty subject is a
		// caller that failed to propagate the authenticated principal, and every
		// query below would filter on '' and return an empty list — a bug that
		// looks exactly like an account with nothing on it.
		return AccountView{}, errs.ValidationFailedf("reading an account needs a subject")
	}

	account, err := q.accounts.Account(ctx, subjectID)
	switch {
	case errors.Is(err, ErrNoSuchSubject):
		return AccountView{}, errs.NotFoundf("no such account")
	case err != nil:
		return AccountView{}, errs.Internalf("reading an account").Wrap(err)
	}
	return account, nil
}

// ListSessions returns the device list, newest first, one page at a time.
//
// Keyset paginated over (created_at DESC, session_id DESC). Offsets are banned:
// a session created or revoked between two requests shifts every later OFFSET
// page, so a user walking their device list would silently miss a device — which
// on this particular screen means missing the one they are looking for.
func (q *Queries) ListSessions(
	ctx context.Context, subjectID string, pageToken page.Token, pageSizeRequested int,
) (page.Page[SessionSummary], error) {
	if subjectID == "" {
		return page.Page[SessionSummary]{}, errs.ValidationFailedf("listing sessions needs a subject")
	}
	size, err := pageSize(pageSizeRequested)
	if err != nil {
		return page.Page[SessionSummary]{}, err
	}
	queryID := sessionsQueryID(subjectID)
	cursor, err := resumeAt(pageToken, queryID, sessionSortColumns)
	if err != nil {
		return page.Page[SessionSummary]{}, err
	}

	// Limit(), not size: one extra row is asked for, and page.Of trims it. The
	// extra row is how "is there another page" is answered without a COUNT(*)
	// whose answer was true a moment ago.
	rows, err := q.sessions.Sessions(ctx, subjectID, cursor, size.Limit())
	if err != nil {
		return page.Page[SessionSummary]{}, errs.Internalf("listing sessions").Wrap(err)
	}

	out, err := page.Of(rows, size, queryID, sessionCursor)
	if err != nil {
		return page.Page[SessionSummary]{}, errs.Internalf("building a session page token").Wrap(err)
	}
	return out, nil
}

// ListMethods returns the authentication methods on an account: which exist,
// what kind each is, whether it can be used now, and when it last was.
//
// The last of those is what makes the screen useful for the question it is
// really asked — "is there something enrolled here that I did not enrol" — and
// the answer is only credible if a method that has never been used says so.
//
// Nothing that verifies anything comes back. The verifier column, the sealed
// TOTP secret and the recovery-code digests never leave the adapter, and the
// result type has no field that could hold one.
func (q *Queries) ListMethods(ctx context.Context, subjectID string) ([]AuthMethod, error) {
	if subjectID == "" {
		return nil, errs.ValidationFailedf("listing methods needs a subject")
	}
	methods, err := q.methods.Methods(ctx, subjectID)
	if err != nil {
		return nil, errs.Internalf("listing authentication methods").Wrap(err)
	}
	return methods, nil
}

// ListLoginHistory returns recent authentication attempts, newest first, one
// page at a time.
//
// Keyset paginated over (occurred_at DESC, id DESC). The `id` tail is doing real
// work here rather than satisfying a rule: attempts arrive in bursts and several
// genuinely share an `occurred_at`, so a boundary that fell inside such a group
// would drop attempts from the one screen whose purpose is to show every attempt.
func (q *Queries) ListLoginHistory(
	ctx context.Context, subjectID string, pageToken page.Token, pageSizeRequested int,
) (page.Page[LoginRecord], error) {
	if subjectID == "" {
		return page.Page[LoginRecord]{}, errs.ValidationFailedf("listing login history needs a subject")
	}
	size, err := pageSize(pageSizeRequested)
	if err != nil {
		return page.Page[LoginRecord]{}, err
	}
	queryID := loginHistoryQueryID(subjectID)
	cursor, err := resumeAt(pageToken, queryID, loginHistorySortColumns)
	if err != nil {
		return page.Page[LoginRecord]{}, err
	}

	rows, err := q.history.LoginHistory(ctx, subjectID, cursor, size.Limit())
	if err != nil {
		return page.Page[LoginRecord]{}, errs.Internalf("listing login history").Wrap(err)
	}

	out, err := page.Of(rows, size, queryID, loginCursor)
	if err != nil {
		return page.Page[LoginRecord]{}, errs.Internalf("building a login-history page token").Wrap(err)
	}
	return out, nil
}
