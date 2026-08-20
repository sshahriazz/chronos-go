package interceptor_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/server/interceptor"
	"github.com/chronos/chronos-go/internal/server/policy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// ---- the fake database ----
//
// It is a fake and not a mock: it answers the ONE statement the authenticator is
// allowed to run and fails loudly on anything else, so a change of query is a
// test failure rather than a silent pass.

type fakeDB struct {
	row      identitydb.GetSessionByTokenRow
	found    bool
	beginErr error // "could not tell": the transaction itself failed
	execErr  error // the touch failed

	queries []fakeCall
	execs   []fakeCall
}

type fakeCall struct {
	sql  string
	args []any
}

func (f *fakeDB) InSystemTx(ctx context.Context, fn func(context.Context, db.Querier) error) error {
	if f.beginErr != nil {
		return f.beginErr
	}
	return fn(ctx, fakeQuerier{f})
}

type fakeQuerier struct{ f *fakeDB }

func (q fakeQuerier) Exec(_ context.Context, sql string, args ...any) (int64, error) {
	q.f.execs = append(q.f.execs, fakeCall{sql: sql, args: args})
	if q.f.execErr != nil {
		return 0, q.f.execErr
	}
	return 1, nil
}

func (q fakeQuerier) Query(context.Context, string, ...any) (db.Rows, error) {
	return nil, errors.New("the authenticator must not run a multi-row query")
}

func (q fakeQuerier) QueryRow(_ context.Context, sql string, args ...any) db.Row {
	q.f.queries = append(q.f.queries, fakeCall{sql: sql, args: args})
	if !q.f.found {
		return errRow{pgx.ErrNoRows}
	}
	return rowOf(q.f.row)
}

type errRow struct{ err error }

func (r errRow) Scan(...any) error { return r.err }

type valuesRow struct{ values []any }

func rowOf(r identitydb.GetSessionByTokenRow) valuesRow {
	return valuesRow{values: []any{
		r.SessionID, r.SubjectID, r.DeviceID, r.Aal, r.IdleExpiresAt, r.AbsoluteExpiresAt,
		r.RequiresCredentialRotation, r.ElevatedScope, r.ElevatedUntil, r.CreatedAt, r.LastSeenAt,
		r.Enrolment,
	}}
}

// Scan refuses a destination list of the wrong length, exactly as pgx does. That
// is what makes a scan which drifted by one column — subject id landing where
// the session id belongs — a failure here rather than a silent authentication as
// somebody else.
func (r valuesRow) Scan(dest ...any) error {
	if len(dest) != len(r.values) {
		return fmt.Errorf("scanned %d destinations for %d columns", len(dest), len(r.values))
	}
	for i, d := range dest {
		var err error
		switch p := d.(type) {
		case *string:
			*p, err = as[string](r.values[i])
		case *int32:
			*p, err = as[int32](r.values[i])
		case *bool:
			*p, err = as[bool](r.values[i])
		case *pgtype.Text:
			*p, err = as[pgtype.Text](r.values[i])
		case *pgtype.Timestamptz:
			*p, err = as[pgtype.Timestamptz](r.values[i])
		default:
			err = fmt.Errorf("column %d: no scan support for %T", i, d)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func as[T any](v any) (T, error) {
	t, ok := v.(T)
	if !ok {
		var zero T
		return zero, fmt.Errorf("column holds %T, scanned into %T", v, zero)
	}
	return t, nil
}

// ---- fixtures ----

var testNow = time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)

func liveRow(t *testing.T) identitydb.GetSessionByTokenRow {
	t.Helper()
	return identitydb.GetSessionByTokenRow{
		SessionID:         ids.New[ids.Session](testNow, nil).String(),
		SubjectID:         ids.New[ids.Subject](testNow, nil).String(),
		Aal:               2,
		IdleExpiresAt:     stamp(testNow.Add(14 * 24 * time.Hour)),
		AbsoluteExpiresAt: stamp(testNow.Add(30 * 24 * time.Hour)),
		CreatedAt:         stamp(testNow.Add(-time.Hour)),
		LastSeenAt:        stamp(testNow.Add(-time.Minute)),
		// An AAL2 session belongs to an account that presented a second factor, so
		// the enrolment state the statement would report for it is "established".
		// The fixture says so explicitly rather than leaving the field empty,
		// because an empty string is the value this build does not recognise and
		// every test using this row would then be exercising the fallback.
		Enrolment: "established",
	}
}

func stamp(at time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: at, Valid: true}
}

func authenticator(t *testing.T, f *fakeDB) *interceptor.SessionAuthenticator {
	t.Helper()
	a, err := interceptor.NewSessionAuthenticator(interceptor.SessionAuthenticatorDeps{
		TX:  f,
		Now: func() time.Time { return testNow },
		Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("NewSessionAuthenticator: %v", err)
	}
	return a
}

// header is the minimal Header the gate passes in.
type header map[string]string

func (h header) Get(k string) string { return h[k] }

func bearer(token string) header { return header{"Authorization": "Bearer " + token} }

// ---- the digest contract ----

// The authenticator reduces the presented token with the SAME function
// CreateSession used on the issued one.
//
// This is the failure that takes the whole system down at once: two reductions
// that disagree over the domain separator or the length prefix means every
// session resolves to nothing, for everybody, at deploy time.
func TestThePresentedTokenIsReducedExactlyAsTheIssuedOneWas(t *testing.T) {
	f := &fakeDB{row: liveRow(t), found: true}
	if _, err := authenticator(t, f).Authenticate(context.Background(), bearer("a-token")); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if len(f.queries) != 1 {
		t.Fatalf("the authenticator ran %d queries, want exactly one", len(f.queries))
	}
	digest, ok := f.queries[0].args[0].([]byte)
	if !ok {
		t.Fatalf("the lookup key is a %T, not a digest", f.queries[0].args[0])
	}
	want := app.SessionTokenDigest("a-token")
	if string(digest) != string(want) {
		t.Fatalf("the token was reduced to %x, but CreateSession stores %x", digest, want)
	}
}

// The token itself never reaches the database, and never reaches a log.
func TestTheTokenItselfIsNeverSent(t *testing.T) {
	f := &fakeDB{row: liveRow(t), found: true}
	if _, err := authenticator(t, f).Authenticate(context.Background(), bearer("a-token")); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	for _, arg := range f.queries[0].args {
		if s, ok := arg.(string); ok && s == "a-token" {
			t.Fatal("the plaintext token was sent to the database")
		}
	}
}

// The resolving query is the generated one, unmodified.
func TestTheResolvingQueryIsTheGeneratedStatement(t *testing.T) {
	f := &fakeDB{row: liveRow(t), found: true}
	if _, err := authenticator(t, f).Authenticate(context.Background(), bearer("a-token")); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if f.queries[0].sql != identitydb.GetSessionByToken {
		t.Fatalf("the authenticator ran a statement other than GetSessionByToken:\n%s",
			f.queries[0].sql)
	}
}

// The statement it depends on is the one that refuses a revoked or expired
// session.
//
// The Go code deliberately re-checks NONE of this, so these three predicates are
// the entire enforcement. Asserted here because a widening of the query — a
// dropped revocation check during a refactor of the SQL — would otherwise be
// invisible: every Go test would still pass while revoked sessions authenticated.
func TestTheResolvingStatementRefusesRevokedAndExpiredSessionsItself(t *testing.T) {
	for _, want := range []string{
		"v.revoked_at IS NULL",
		"v.absolute_expires_at > $2",
		"t.idle_expires_at > $2",
		"JOIN session_view v ON v.session_id = t.session_id",
	} {
		if !strings.Contains(identitydb.GetSessionByToken, want) {
			t.Errorf("GetSessionByToken no longer contains %q, so the authenticator no longer "+
				"refuses what it believes the statement refuses", want)
		}
	}
}

// Both deadlines are judged at the instant of the REQUEST.
//
// The statement compares both deadlines against $2. A zero or stale value there
// makes every expired session resolve, and no Go-side check exists to catch it.
func TestBothDeadlinesAreJudgedAtTheRequestInstant(t *testing.T) {
	f := &fakeDB{row: liveRow(t), found: true}
	if _, err := authenticator(t, f).Authenticate(context.Background(), bearer("a-token")); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	at, ok := f.queries[0].args[1].(time.Time)
	if !ok {
		t.Fatalf("the deadline parameter is a %T, not a time", f.queries[0].args[1])
	}
	if !at.Equal(testNow) {
		t.Fatalf("deadlines were judged at %s, but the request happened at %s", at, testNow)
	}
	if at.Location() != time.UTC {
		t.Fatalf("the deadline parameter is in %s; storage is always UTC", at.Location())
	}
}

// ---- what the caller is told ----

// Missing, malformed and unknown are ONE outcome, and none of them is the
// "unavailable" outcome.
func TestEveryUnresolvableTokenIsTheSameUndifferentiatedRefusal(t *testing.T) {
	tests := []struct {
		name   string
		header interceptor.Header
		found  bool
		// queries is how many statements the request may cost. A request
		// carrying no syntactically valid credential must cost ZERO: an
		// unauthenticated flood is the cheapest traffic to send, and turning each
		// of those into a database round trip hands an attacker an amplifier.
		queries int
	}{
		{name: "no header at all", header: header{}},
		{name: "empty authorization", header: header{"Authorization": ""}},
		{name: "another scheme", header: header{"Authorization": "Basic abc"}},
		{name: "scheme with no credential", header: header{"Authorization": "Bearer   "}},
		{name: "unknown token", header: bearer("a-token"), found: false, queries: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeDB{row: liveRow(t), found: tt.found}
			p, err := authenticator(t, f).Authenticate(context.Background(), tt.header)
			if err == nil {
				t.Fatal("an unresolvable token authenticated")
			}
			if errors.Is(err, interceptor.ErrAuthenticationUnavailable) {
				t.Fatal("an unresolvable token was reported as an outage; the client would " +
					"retry a credential that will never work")
			}
			if p.Subject.ID != "" {
				t.Fatalf("a refusal still produced a principal: %+v", p)
			}
			if len(f.queries) != tt.queries {
				t.Fatalf("the request cost %d queries, want %d", len(f.queries), tt.queries)
			}
		})
	}
}

// The instant both deadlines are judged at is UTC whatever zone the clock
// reports in.
//
// Storage is always UTC; APP_TIMEZONE is presentation only. A local-zone
// parameter here does not fail — it compares correctly against a timestamptz —
// right up until it is read back in a log or a test and means something else.
func TestTheRequestInstantIsNormalisedToUTC(t *testing.T) {
	zone := time.FixedZone("UTC+9", 9*60*60)
	f := &fakeDB{row: liveRow(t), found: true}
	a, err := interceptor.NewSessionAuthenticator(interceptor.SessionAuthenticatorDeps{
		TX:  f,
		Now: func() time.Time { return testNow.In(zone) },
		Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("NewSessionAuthenticator: %v", err)
	}
	if _, err := a.Authenticate(context.Background(), bearer("a-token")); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	at := f.queries[0].args[1].(time.Time)
	if at.Location() != time.UTC {
		t.Fatalf("the deadline parameter is in %s, want UTC", at.Location())
	}
	if !at.Equal(testNow) {
		t.Fatalf("normalising the zone moved the instant to %s", at)
	}
}

// A nil Header is refused rather than dereferenced.
func TestANilHeaderIsRefused(t *testing.T) {
	f := &fakeDB{row: liveRow(t), found: true}
	if _, err := authenticator(t, f).Authenticate(context.Background(), nil); err == nil {
		t.Fatal("a request with no headers authenticated")
	}
	if len(f.queries) != 0 {
		t.Fatal("a request with no headers reached the database")
	}
}

// The scheme is case-insensitive, per RFC 7235.
func TestTheBearerSchemeIsCaseInsensitive(t *testing.T) {
	for _, scheme := range []string{"Bearer", "bearer", "BEARER"} {
		t.Run(scheme, func(t *testing.T) {
			f := &fakeDB{row: liveRow(t), found: true}
			_, err := authenticator(t, f).Authenticate(context.Background(),
				header{"Authorization": scheme + " a-token"})
			if err != nil {
				t.Fatalf("a spec-compliant %q scheme was refused: %v", scheme, err)
			}
		})
	}
}

// A database that cannot answer is an OUTAGE, not a bad credential.
//
// The request is refused either way. What differs is what the client does next:
// told UNAUTHENTICATED, every client in the fleet signs its user out during a
// blip and then re-authenticates against the database that is already
// struggling.
func TestADatabaseOutageIsNotReportedAsABadCredential(t *testing.T) {
	f := &fakeDB{beginErr: errors.New("connection refused")}
	p, err := authenticator(t, f).Authenticate(context.Background(), bearer("a-token"))
	if err == nil {
		t.Fatal("a request was ADMITTED while the database was unreachable")
	}
	if !errors.Is(err, interceptor.ErrAuthenticationUnavailable) {
		t.Fatalf("an outage was reported as a credential failure: %v", err)
	}
	if p.Subject.ID != "" {
		t.Fatalf("an outage produced a principal: %+v", p)
	}
}

// ---- the principal ----

func TestThePrincipalCarriesWhatTheSessionEstablished(t *testing.T) {
	row := liveRow(t)
	row.RequiresCredentialRotation = true
	f := &fakeDB{row: row, found: true}

	p, err := authenticator(t, f).Authenticate(context.Background(), bearer("a-token"))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.Subject.Kind != authz.KindUser {
		t.Errorf("principal kind is %q, want %q", p.Subject.Kind, authz.KindUser)
	}
	if p.Subject.ID != row.SubjectID {
		t.Errorf("principal is %q, but the session belongs to %q", p.Subject.ID, row.SubjectID)
	}
	if p.Context.SessionID != row.SessionID {
		t.Errorf("session id is %q, want %q", p.Context.SessionID, row.SessionID)
	}
	if p.AAL != optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2 {
		t.Errorf("assurance level is %v, want AAL2", p.AAL)
	}
	if p.Context.AAL != 2 {
		t.Errorf("the authz context carries AAL %d, want 2", p.Context.AAL)
	}
	if !p.RequiresCredentialRotation {
		t.Error("the session requires credential rotation and the principal does not say so")
	}
	if err := (authz.Query{
		Principal: p.Subject, Relation: "self",
		Resource: authz.ResourceRef{Type: "user", ID: p.Subject.ID},
	}).Validate(); err != nil {
		t.Errorf("the principal cannot be used in a check: %v", err)
	}
}

// Nothing forgeable is trusted. A client cannot choose the values a conditional
// authorization rule evaluates.
func TestNoClientSuppliedContextIsTrusted(t *testing.T) {
	f := &fakeDB{row: liveRow(t), found: true}
	p, err := authenticator(t, f).Authenticate(context.Background(), header{
		"Authorization":   "Bearer a-token",
		"X-Forwarded-For": "10.0.0.1",
		"X-Org-Id":        "org_01H8XG5N2QK7VB3C9WPYZR4TFM",
		"X-Device-Trust":  "trusted",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if p.Context.IP != "" {
		t.Errorf("an IP was taken from a header: %q", p.Context.IP)
	}
	if p.Context.DeviceTrusted {
		t.Error("device trust was taken from a header")
	}
	if p.Context.ActiveOrg != "" {
		t.Errorf("an active organization was taken from a header: %q; any member of any org "+
			"could then name any other", p.Context.ActiveOrg)
	}
}

// A row this build cannot interpret is an outage, not a bad credential: it was
// written by something that is not this application, and answering "your
// credential is bad" hides that.
func TestAnUninterpretableSessionRowIsNotACredentialFailure(t *testing.T) {
	tests := []struct {
		name    string
		corrupt func(*identitydb.GetSessionByTokenRow)
	}{
		{"unreadable subject", func(r *identitydb.GetSessionByTokenRow) { r.SubjectID = "alice" }},
		{"empty subject", func(r *identitydb.GetSessionByTokenRow) { r.SubjectID = "" }},
		{"unreadable session id", func(r *identitydb.GetSessionByTokenRow) { r.SessionID = "42" }},
		{"a subject id of the wrong kind", func(r *identitydb.GetSessionByTokenRow) {
			r.SubjectID = ids.New[ids.User](testNow, nil).String()
		}},
		{"an assurance level of zero", func(r *identitydb.GetSessionByTokenRow) { r.Aal = 0 }},
		{"an assurance level out of range", func(r *identitydb.GetSessionByTokenRow) { r.Aal = 9 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row := liveRow(t)
			tt.corrupt(&row)
			f := &fakeDB{row: row, found: true}
			p, err := authenticator(t, f).Authenticate(context.Background(), bearer("a-token"))
			if err == nil {
				t.Fatalf("an uninterpretable session row authenticated as %+v", p)
			}
			if !errors.Is(err, interceptor.ErrAuthenticationUnavailable) {
				t.Fatalf("a corrupt row was reported to the caller as a bad credential: %v", err)
			}
		})
	}
}

// ---- the enrolment signal ----

// The principal carries the enrolment state the STATEMENT reported, and every
// value it could report maps to exactly one meaning.
//
// This is the half of the bootstrap mechanism the gate cannot check for itself:
// policy.AALFloor relaxes the assurance requirement when it is told the account
// has never held a second factor, and it has no way to notice that it was told
// wrong. So the mapping is pinned here, value by value, including the ones that
// must NOT produce a relaxation.
func TestThePrincipalCarriesTheAccountsEnrolmentState(t *testing.T) {
	tests := []struct {
		name   string
		stored string
		want   policy.Enrolment
	}{
		{"an account that has proven a factor", "established", policy.EnrolmentEstablished},
		{"an account that never has", "bootstrap", policy.EnrolmentBootstrap},
		{"an account row the statement could not find", "unknown", policy.EnrolmentUnknown},
		// Everything below is a value this build has no reading for, and each one
		// must land on the state that relaxes nothing. A default that fell through
		// to Bootstrap would hand the exemption to exactly the rows nobody
		// understands.
		{"an empty column", "", policy.EnrolmentUnknown},
		{"a value from a newer schema", "provisional", policy.EnrolmentUnknown},
		{"a value that differs only in case", "Bootstrap", policy.EnrolmentUnknown},
		{"a value with surrounding space", " bootstrap ", policy.EnrolmentUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row := liveRow(t)
			row.Enrolment = tt.stored
			f := &fakeDB{row: row, found: true}

			p, err := authenticator(t, f).Authenticate(context.Background(), bearer("a-token"))
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if p.Enrolment != tt.want {
				t.Fatalf("the column %q produced enrolment %v, want %v",
					tt.stored, p.Enrolment, tt.want)
			}
		})
	}
}

// An unreadable enrolment column does not sign anybody out.
//
// The two failure directions are not symmetric. Refusing the exemption costs a
// user their first enrolment; refusing the SESSION costs every user in the fleet
// their session, over a column no gate had needed until today. So an
// uninterpretable value is the one row defect above that is NOT
// ErrAuthenticationUnavailable — it is already safe by being Unknown.
func TestAnUnreadableEnrolmentStateDoesNotRefuseTheSession(t *testing.T) {
	row := liveRow(t)
	row.Enrolment = "not-a-state"
	f := &fakeDB{row: row, found: true}

	p, err := authenticator(t, f).Authenticate(context.Background(), bearer("a-token"))
	if err != nil {
		t.Fatalf("an unreadable enrolment state refused an otherwise live session: %v", err)
	}
	if p.Subject.ID != row.SubjectID {
		t.Fatalf("principal is %q, want %q", p.Subject.ID, row.SubjectID)
	}
	if p.AAL != optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2 {
		t.Fatalf("the session's assurance level was altered: %v", p.AAL)
	}
}

// Only a value nobody expected is reported; an absent account row is not.
//
// The two produce the same principal, so the log line is the whole difference
// between them — and it matters in both directions. A build that cannot read its
// own enrolment column has an unusable first-enrolment flow and nothing else
// would say so; a warning on every request whose account row is legitimately
// missing is noise that makes the first signal unfindable.
func TestOnlyAnUnrecognisedEnrolmentStateIsReported(t *testing.T) {
	tests := []struct {
		name     string
		stored   string
		wantWarn bool
	}{
		{"an absent account row", "unknown", false},
		{"an account that has proven a factor", "established", false},
		{"a first enrolment", "bootstrap", false},
		{"a value from a newer schema", "provisional", true},
		{"an empty column", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row := liveRow(t)
			row.Enrolment = tt.stored
			f := &fakeDB{row: row, found: true}

			var logs bytes.Buffer
			a, err := interceptor.NewSessionAuthenticator(interceptor.SessionAuthenticatorDeps{
				TX:  f,
				Now: func() time.Time { return testNow },
				Log: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
			})
			if err != nil {
				t.Fatalf("NewSessionAuthenticator: %v", err)
			}
			if _, err := a.Authenticate(context.Background(), bearer("a-token")); err != nil {
				t.Fatalf("Authenticate: %v", err)
			}

			reported := strings.Contains(logs.String(), "enrolment state this build does not")
			if reported != tt.wantWarn {
				t.Fatalf("the enrolment state %q was reported=%v, want %v; log:\n%s",
					tt.stored, reported, tt.wantWarn, logs.String())
			}
			if strings.Contains(logs.String(), "a-token") {
				t.Error("the bearer token reached the log")
			}
		})
	}
}

// The zero Principal denies the exemption.
//
// Every gate reads Enrolment from the principal, and a principal built by a test
// double, by a future authenticator, or by a struct literal written before this
// field existed carries the zero value. It must be the strict one.
func TestAPrincipalNobodyFilledInGrantsNoExemption(t *testing.T) {
	var p interceptor.Principal
	if p.Enrolment != policy.EnrolmentUnknown {
		t.Fatalf("the zero principal reports enrolment %v, want unknown", p.Enrolment)
	}
}

// The derivation of the enrolment state lives in the STATEMENT, and these are
// the four clauses it is made of.
//
// Asserted the same way the revocation and deadline predicates are, and for the
// same reason: the Go code re-derives none of this, so a rewrite of the SQL that
// dropped a clause would leave every Go test passing while the answer changed.
//
// Each clause below fails in a different, specific way if it goes:
//
//   - activated_at is the DURABLE half. Without it, an account that lost its
//     factor — disabled, locked out, or re-enrolling — reports bootstrap again,
//     which is the stolen-password attack.
//   - enabled_at is what makes the credential half mean PROVEN. Without it, an
//     enrolment in progress reads as established and ConfirmTotp becomes
//     unreachable: the deadlock returns one step later.
//   - the kind exclusion is what keeps a recovery-code sheet from counting as a
//     second factor, mirroring domain.maybeActivate.
//   - the LEFT JOIN plus the NULL arm is what keeps a missing account row from
//     collapsing into "no factor".
func TestTheEnrolmentStateIsDerivedByTheStatement(t *testing.T) {
	for _, want := range []string{
		"u.activated_at IS NOT NULL",
		"c.enabled_at IS NOT NULL",
		"c.kind NOT IN ('password', 'passkey', 'federated', 'recovery_code')",
		"LEFT JOIN user_view u ON u.subject_id = v.subject_id",
		"WHEN u.subject_id IS NULL THEN 'unknown'",
	} {
		if !strings.Contains(identitydb.GetSessionByToken, want) {
			t.Errorf("GetSessionByToken no longer contains %q, so the enrolment state it "+
				"reports is not the one the authenticator believes it is", want)
		}
	}
}

// ---- the idle deadline ----

// A session used again within the threshold is NOT written to.
func TestARecentlySeenSessionIsNotWrittenTo(t *testing.T) {
	row := liveRow(t)
	row.LastSeenAt = stamp(testNow.Add(-time.Minute))
	f := &fakeDB{row: row, found: true}
	if _, err := authenticator(t, f).Authenticate(context.Background(), bearer("a-token")); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if len(f.execs) != 0 {
		t.Fatalf("an authenticated read performed %d writes; at scale that is the entire read "+
			"traffic of the API arriving as row updates", len(f.execs))
	}
}

// A session past the threshold has its idle deadline pushed forward, or the idle
// window stops meaning anything and becomes a second absolute deadline.
func TestAStaleSessionHasItsIdleDeadlinePushedForward(t *testing.T) {
	row := liveRow(t)
	row.LastSeenAt = stamp(testNow.Add(-2 * interceptor.DefaultTouchAfter))
	f := &fakeDB{row: row, found: true}
	if _, err := authenticator(t, f).Authenticate(context.Background(), bearer("a-token")); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if len(f.execs) != 1 {
		t.Fatalf("a stale session produced %d writes, want exactly one", len(f.execs))
	}
	if f.execs[0].sql != identitydb.TouchSession {
		t.Fatalf("the refresh ran a statement other than TouchSession:\n%s", f.execs[0].sql)
	}
	if got := f.execs[0].args[0]; got != row.SessionID {
		t.Fatalf("the refresh touched session %v, not %v", got, row.SessionID)
	}
	deadline, ok := f.execs[0].args[1].(time.Time)
	if !ok {
		t.Fatalf("the new deadline is a %T", f.execs[0].args[1])
	}
	if want := testNow.Add(app.DefaultIdleWindow); !deadline.Equal(want) {
		t.Fatalf("the idle deadline was pushed to %s, want %s — the window must keep the "+
			"length CreateSession gave it", deadline, want)
	}
}

// A session with no last_seen_at is due by definition.
func TestASessionNeverSeenBeforeIsTouched(t *testing.T) {
	row := liveRow(t)
	row.LastSeenAt = pgtype.Timestamptz{} // NULL
	f := &fakeDB{row: row, found: true}
	if _, err := authenticator(t, f).Authenticate(context.Background(), bearer("a-token")); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if len(f.execs) != 1 {
		t.Fatalf("a session with no last_seen_at produced %d writes, want one", len(f.execs))
	}
}

// The clamp to the absolute deadline lives in the STATEMENT. Without it a
// session in constant use pushes its idle deadline past the absolute one, and
// the idle deadline quietly stops existing.
func TestTheRefreshIsClampedByTheStatement(t *testing.T) {
	for _, want := range []string{"LEAST($2::timestamptz, v.absolute_expires_at)", "v.revoked_at IS NULL"} {
		if !strings.Contains(identitydb.TouchSession, want) {
			t.Errorf("TouchSession no longer contains %q", want)
		}
	}
}

// A failed refresh does not fail the request.
//
// The session already resolved; the request is authentic whether or not the
// bookkeeping landed, and the lost touch leaves the deadline where it was — the
// session expires EARLIER than it might have, which is the safe direction.
func TestAFailedRefreshDoesNotSignTheUserOut(t *testing.T) {
	row := liveRow(t)
	row.LastSeenAt = stamp(testNow.Add(-2 * interceptor.DefaultTouchAfter))
	f := &fakeDB{row: row, found: true, execErr: errors.New("write failed")}
	p, err := authenticator(t, f).Authenticate(context.Background(), bearer("a-token"))
	if err != nil {
		t.Fatalf("a failed idle-deadline refresh signed the user out: %v", err)
	}
	if p.Subject.ID != row.SubjectID {
		t.Fatal("the principal was lost with the failed refresh")
	}
}

// ---- construction ----

func TestTheAuthenticatorRefusesAnUnusableConfiguration(t *testing.T) {
	tests := []struct {
		name string
		deps interceptor.SessionAuthenticatorDeps
	}{
		{name: "no transaction helper", deps: interceptor.SessionAuthenticatorDeps{}},
		{name: "a touch threshold longer than the idle window", deps: interceptor.SessionAuthenticatorDeps{
			TX: &fakeDB{}, IdleWindow: time.Hour, TouchAfter: 2 * time.Hour,
		}},
		{name: "a touch threshold equal to the idle window", deps: interceptor.SessionAuthenticatorDeps{
			TX: &fakeDB{}, IdleWindow: time.Hour, TouchAfter: time.Hour,
		}},
		{name: "a negative idle window", deps: interceptor.SessionAuthenticatorDeps{
			TX: &fakeDB{}, IdleWindow: -time.Hour,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := interceptor.NewSessionAuthenticator(tt.deps); err == nil {
				t.Fatal("an unusable authenticator was constructed")
			}
		})
	}
}

// The defaults are the same constants the login path used, so a session's window
// does not change length the first time it is used.
func TestTheDefaultIdleWindowMatchesTheOneSessionsAreIssuedWith(t *testing.T) {
	row := liveRow(t)
	row.LastSeenAt = pgtype.Timestamptz{}
	f := &fakeDB{row: row, found: true}
	a, err := interceptor.NewSessionAuthenticator(interceptor.SessionAuthenticatorDeps{
		TX: f, Now: func() time.Time { return testNow }, Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("NewSessionAuthenticator: %v", err)
	}
	if _, err := a.Authenticate(context.Background(), bearer("a-token")); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if want := testNow.Add(app.DefaultIdleWindow); !f.execs[0].args[1].(time.Time).Equal(want) {
		t.Fatalf("the default refresh window is not app.DefaultIdleWindow")
	}
}

var _ interceptor.Authenticator = (*interceptor.SessionAuthenticator)(nil)
