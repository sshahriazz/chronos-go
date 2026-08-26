//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// These are operator.md §11's structural tests. Every one of them asserts
// against a REAL database, because every one of them is about a grant or a
// column — facts that live in PostgreSQL and that no amount of Go can prove.
//
// The four here map one-to-one onto the test plan:
//
//	"Grants"        → TestTheOperatorRoleCannotReachTenantTables
//	"Minimisation"  → TestOperatorProjectionsHoldNoPersonalData
//	"Isolation"     → TestTheTenantRoleCannotReachOperatorTables
//	                  (and cmd/api's own linking test, which is in Go)
//
// The remaining two — audit completeness and break-glass — live with the code
// they constrain: the first in internal/operator/policy, the second in slice 2
// with the elevation it tests.

func operatorPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return poolAs(t, envOr("POSTGRES_OPERATOR_USER", "chronos_operator"),
		envOr("POSTGRES_OPERATOR_PASSWORD", "chronos_operator_dev_password"))
}

func appPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return poolAs(t, envOr("POSTGRES_APP_USER", "chronos_app"),
		envOr("POSTGRES_APP_PASSWORD", "chronos_app_dev_password"))
}

func poolAs(t *testing.T, user, password string) *pgxpool.Pool {
	t.Helper()
	host := envOr("POSTGRES_HOST", "localhost")
	port := envOr("POSTGRES_PORT", "5432")
	name := envOr("POSTGRES_DB", "chronos")

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		user, password, host, port, name)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connecting as %s: %v", user, err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("connecting as %s: %v", user, err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// tenantTables is the set the operator role must not reach.
//
// A hand-written list rather than "everything not named operator_*", and the
// reason is that the second form would pass vacuously if the naming convention
// ever changed. These are the tables that hold what operator.md §4 calls
// customer content and what ADR-002 calls personal data — the ones whose
// disclosure is the outcome the separate role exists to make impossible.
var tenantTables = []string{
	"user_view",
	"session_view",
	"credential",
	"passkey_credential",
	"webauthn_challenge",
	"organization_view",
	"workspace_view",
	"membership_view",
	"invitation_view",
	"team_view",
	"notification_view",
	"idempotency_record",
}

// TestTheOperatorRoleCannotReachTenantTables is operator.md §11's "Grants".
//
// "The operator DB role cannot read tenant content tables — asserted against a
// real database, not assumed."
//
// It asserts on the REFUSAL, not on the absence of a query. A test that merely
// checked no operator code SELECTs from user_view would pass forever while the
// grant sat there waiting for the first person to write one.
func TestTheOperatorRoleCannotReachTenantTables(t *testing.T) {
	pool := operatorPool(t)
	ctx := t.Context()

	for _, table := range tenantTables {
		t.Run(table, func(t *testing.T) {
			if !tableExists(t, appPool(t), table) {
				t.Skipf("%s does not exist in this schema", table)
			}
			//nolint:gosec // the table name comes from the list above, never from input
			_, err := pool.Exec(ctx, "SELECT 1 FROM "+table+" LIMIT 1")
			if err == nil {
				t.Fatalf("the operator role can read %s; migration 00037's isolation is not in effect", table)
			}
			if !strings.Contains(err.Error(), "permission denied") {
				t.Fatalf("reading %s failed for the WRONG reason: %v\n"+
					"the test asserts the grant is absent, and any other failure means it "+
					"was not the grant that stopped this", table, err)
			}
		})
	}
}

// TestTheTenantRoleCannotReachOperatorTables is the same boundary from the
// other side.
//
// It is the half that is easy to omit, and omitting it would leave the
// separation half-built: chronos_app is granted every future table by the
// DEFAULT PRIVILEGES in infra/postgres/init/02-app-role.sql, so without
// migration 00037's explicit REVOKEs the tenant API would hold read and write
// on the entire operator plane — including the audit log that records what
// operators did.
func TestTheTenantRoleCannotReachOperatorTables(t *testing.T) {
	pool := appPool(t)
	ctx := t.Context()

	operatorTables := []string{
		"operator_account",
		"operator_credential",
		"operator_session",
		"operator_ceremony",
		"operator_audit_log",
		"operator_customer_list",
	}

	for _, table := range operatorTables {
		t.Run(table, func(t *testing.T) {
			//nolint:gosec // the table name comes from the list above
			_, err := pool.Exec(ctx, "SELECT 1 FROM "+table+" LIMIT 1")
			if err == nil {
				t.Fatalf("the tenant role can read %s; the REVOKEs in migration 00037 are not in effect", table)
			}
			if !strings.Contains(err.Error(), "permission denied") {
				t.Fatalf("reading %s failed for the WRONG reason: %v", table, err)
			}
		})
	}
}

// TestTheOperatorRoleReadsTheVaultAndCannotWriteIt is migration 00038's
// crossing, asserted in both directions.
//
// The grant has to exist — RevealPersonalData is operator.md §4's justified
// access and without it the back office cannot answer a ticket. What must NOT
// exist is anything more: an operator plane that could write the vault could
// change somebody's address, and one that could delete from it could erase a
// person without the request that makes erasure lawful.
func TestTheOperatorRoleReadsTheVaultAndCannotWriteIt(t *testing.T) {
	pool := operatorPool(t)
	ctx := t.Context()

	if _, err := pool.Exec(ctx, "SELECT 1 FROM pii_value LIMIT 1"); err != nil {
		t.Fatalf("the operator role cannot read the vault, so RevealPersonalData cannot work: %v", err)
	}

	for _, stmt := range []struct{ name, sql string }{
		{"insert", "INSERT INTO pii_value (subject_id, field, ciphertext) VALUES ('x', 'email', '\\x00')"},
		{"update", "UPDATE pii_value SET ciphertext = '\\x00' WHERE false"},
		{"delete", "DELETE FROM pii_value WHERE false"},
	} {
		t.Run(stmt.name, func(t *testing.T) {
			_, err := pool.Exec(ctx, stmt.sql)
			if err == nil {
				t.Fatalf("the operator role can %s the vault; it holds SELECT only (migration 00038)", stmt.name)
			}
			if !strings.Contains(err.Error(), "permission denied") {
				t.Fatalf("the %s failed for the WRONG reason: %v", stmt.name, err)
			}
		})
	}
}

// forbiddenColumns are the column names an operator projection may never have.
//
// Names rather than types, because that is what a later migration would
// actually add — somebody wanting "just the owner's email on the customer row"
// writes `owner_email`, and this is the test that stops them before the column
// exists to hold it.
//
// The list is deliberately broader than the vault's own field set. `avatar_url`
// is not in the vault and is still personal data (a photograph of a person);
// `content` and `body` are not personal data at all and are customer content,
// which operator.md §2 excludes just as firmly.
var forbiddenColumns = []string{
	"email", "email_index", "pending_email", "previous_email",
	"name", "full_name", "display_name", "first_name", "last_name",
	"phone", "address", "avatar", "avatar_url", "avatar_key",
	"password", "verifier", "secret", "token", "token_digest",
	"content", "body", "document", "file", "attachment",
	"ip", "ip_address", "user_agent",
}

// operatorProjections are the tables minimisation applies to.
//
// The AUTHORITATIVE tables are deliberately absent. operator_session holds a
// token_digest and a from_ip, and operator_ceremony holds a payload — all three
// would trip the list above, and all three are correct: a session table without
// a digest cannot authenticate anybody. Minimisation is a rule about what
// operators can SEE of a customer, not about what the plane needs to run.
var operatorProjections = []string{
	"operator_customer_list",
	"operator_account",
}

// TestOperatorProjectionsHoldNoPersonalData is operator.md §11's
// "Minimisation".
//
// "Operator projections contain no content columns, asserted on the schema so a
// later migration cannot quietly add one."
//
// The word that carries the test is QUIETLY. Nothing stops somebody adding a
// column; what this does is make the addition loud — the suite fails, and
// whoever wrote the migration has to argue for it in review rather than
// discover afterwards that the operator plane now holds a second copy of
// everybody's address, outside the vault, where erasure cannot reach it.
func TestOperatorProjectionsHoldNoPersonalData(t *testing.T) {
	// The OPERATOR pool, and the reason is a real trap.
	//
	// information_schema.columns is filtered by PRIVILEGE: it shows a role only
	// the columns of tables that role can touch. chronos_app is revoked from
	// every operator table, so running this as the tenant role returns ZERO
	// columns — and a naive version of this test would then find no forbidden
	// column and report PASS while inspecting nothing at all.
	//
	// The `len(columns) == 0` check below is what turns that into a failure
	// rather than a false pass, and it is the reason it exists.
	pool := operatorPool(t)
	ctx := t.Context()

	for _, table := range operatorProjections {
		t.Run(table, func(t *testing.T) {
			rows, err := pool.Query(ctx, `
				SELECT column_name
				FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = $1`, table)
			if err != nil {
				t.Fatalf("reading the schema: %v", err)
			}
			defer rows.Close()

			var columns []string
			for rows.Next() {
				var c string
				if err := rows.Scan(&c); err != nil {
					t.Fatalf("scanning: %v", err)
				}
				columns = append(columns, c)
			}
			if err := rows.Err(); err != nil {
				t.Fatalf("reading the schema: %v", err)
			}
			if len(columns) == 0 {
				t.Fatalf("%s has no columns, which means it does not exist — "+
					"a minimisation test that inspects a missing table passes vacuously", table)
			}

			for _, col := range columns {
				for _, banned := range forbiddenColumns {
					if col == banned {
						t.Errorf("%s.%s is a personal-data or content column.\n\n"+
							"operator.md §4: the operator read models are built to contain only "+
							"what operators may see, so there is no query that COULD return "+
							"customer content — the columns do not exist in the projection.\n\n"+
							"If this column is genuinely needed, the answer is RevealPersonalData: "+
							"one subject, a justification, and an audit entry written before the "+
							"read. A column here is the same disclosure with none of that.",
							table, col)
					}
				}
			}
		})
	}
}

// TestTheAuditLogRefusesAnUnjustifiedPersonalDataRow asserts the CHECK
// constraint, which is the third of the three places the justification rule is
// enforced.
//
// The other two are protovalidate at the edge and the audit aggregate in the
// domain. This is the one that holds if a PROJECTOR bug ever tried to write the
// row directly — which is the only path that skips both others.
func TestTheAuditLogRefusesAnUnjustifiedPersonalDataRow(t *testing.T) {
	pool := operatorPool(t)
	ctx := t.Context()

	_, err := pool.Exec(ctx, `
		INSERT INTO operator_audit_log
			(entry_id, operator_id, operator_subject_id, action, method,
			 org_id, target_subject_id, fields, reason, occurred_at)
		VALUES ($1, 'opr_x', 'subj_x', 'viewed_personal_data', 'test',
			NULL, 'subj_y', ARRAY['email'], NULL, now())`,
		"audit_test_"+t.Name())
	if err == nil {
		t.Fatal("an unjustified personal-data access was recorded; " +
			"operator_audit_personal_data_justified is not in effect")
	}
	if !strings.Contains(err.Error(), "operator_audit_personal_data_justified") {
		t.Fatalf("the insert failed for the WRONG reason: %v", err)
	}
}

func tableExists(t *testing.T, pool *pgxpool.Pool, name string) bool {
	t.Helper()
	var n int
	err := pool.QueryRow(t.Context(), `
		SELECT count(*) FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name = $1`, name).Scan(&n)
	if err != nil {
		t.Fatalf("checking whether %s exists: %v", name, err)
	}
	return n > 0
}
