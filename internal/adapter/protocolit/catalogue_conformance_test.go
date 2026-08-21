//go:build integration

package protocolit_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/errs"
)

// TestThePublishedErrorCatalogueMatchesTheWire compares docs/api/errors.md
// against what the server actually sends.
//
// The catalogue is a generated artefact and CONVENTIONS §7.1 makes it part of
// the API contract:
//
// > **Reason-code catalogue generated from the server's own enum** — docs and
// > behaviour cannot disagree.
//
// "Cannot disagree" is a claim about the reason column. The catalogue also
// publishes a Connect code and an HTTP status per reason, and those come from
// `errs.Catalogue()`, which is a hand-maintained table in the kernel — while the
// code a caller receives comes from `server/connect.codeFor`, a switch in a
// different package. Two tables, one contract, and nothing compares them. This
// does, for every reason the suite can actually provoke over the wire.
//
// # What it cannot cover, and why
//
// Four reasons have no reachable producer in this build:
// `PLAN_UPGRADE_REQUIRED`, `QUOTA_EXCEEDED` and `ORG_SUSPENDED` are raised by
// the entitlement and subscription gates, which belong to modules that do not
// exist (cmd/api logs "gates are declared by some methods and implemented by
// none" at startup); `ACCESS_DENIED` is raised only by the ADR-036 parent-
// visibility check, which interceptor/gates.go documents as not implemented
// yet. `RATE_LIMITED` and `INTERNAL` are reachable only by breaking something.
//
// Those are named in the log rather than skipped silently, because a
// conformance suite that does not say what it did not cover is a suite whose
// green is the wrong shape.
func TestThePublishedErrorCatalogueMatchesTheWire(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("locating the repository root: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "docs", "api", "errors.md"))
	if err != nil {
		t.Fatalf("reading the published error catalogue: %v", err)
	}
	published := parseCatalogue(string(raw))
	if len(published) == 0 {
		t.Fatalf("docs/api/errors.md carries no reason rows; the parser or the generated "+
			"format has changed:\n%s", string(raw[:min(len(raw), 400)]))
	}

	bearer := h.activeBearer(t)
	bootBearer := h.bootstrapBearer(t)

	provokable := []struct {
		reason errs.Reason
		how    string
		call   func(ctx context.Context) (int, string, error)
	}{
		{
			reason: errs.Unauthenticated,
			how:    "GetUser with no bearer token",
			call: func(ctx context.Context) (int, string, error) {
				return rawPost(ctx, "/chronos.identity.v1.IdentityService/GetUser",
					"application/json", `{}`, "", "", nil)
			},
		},
		{
			reason: errs.StepUpRequired,
			how:    "GenerateRecoveryCodes from a password-only AAL1 session",
			call: func(ctx context.Context) (int, string, error) {
				return rawPost(ctx, "/chronos.identity.v1.IdentityService/GenerateRecoveryCodes",
					"application/json", `{}`, bootBearer, newIdempotencyKey(), nil)
			},
		},
		{
			reason: errs.NotFound,
			how:    "RevokeSession naming a session that does not exist",
			call: func(ctx context.Context) (int, string, error) {
				return rawPost(ctx, "/chronos.identity.v1.IdentityService/RevokeSession",
					"application/json", `{"sessionId":"sess_01ARZ3NDEKTSV4RRFFQ69G5FAV"}`,
					bearer, newIdempotencyKey(), nil)
			},
		},
		{
			reason: errs.ValidationFailed,
			how:    "a mutation with no Idempotency-Key",
			call: func(ctx context.Context) (int, string, error) {
				return rawPost(ctx, "/chronos.profile.v1.ProfileService/CreateAvatarUpload",
					"application/json", `{"contentType":"image/png","sizeBytes":"1024"}`,
					bearer, "", nil)
			},
		},
		{
			reason: errs.Conflict,
			how:    "an Idempotency-Key reused with a different body",
			call: func(ctx context.Context) (int, string, error) {
				key := newIdempotencyKey()
				if _, _, err := rawPost(ctx, "/chronos.profile.v1.ProfileService/CreateAvatarUpload",
					"application/json", `{"contentType":"image/png","sizeBytes":"1024"}`,
					bearer, key, nil); err != nil {
					return 0, "", err
				}
				return rawPost(ctx, "/chronos.profile.v1.ProfileService/CreateAvatarUpload",
					"application/json", `{"contentType":"image/jpeg","sizeBytes":"2048"}`,
					bearer, key, nil)
			},
		},
	}

	covered := map[errs.Reason]bool{}
	for _, p := range provokable {
		t.Run(string(p.reason), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			status, body, err := p.call(ctx)
			if err != nil {
				t.Fatalf("%s: %v", p.how, err)
			}
			env, derr := decodeWireError(body)
			if derr != nil {
				t.Fatalf("%s did not produce a Connect error envelope: %v\nbody: %s",
					p.how, derr, strings.TrimSpace(body))
			}
			if got := reasonFromJSON(body); got != string(p.reason) {
				t.Fatalf("%s produced reason %q, not %q, so this row measures the wrong "+
					"thing\n%s", p.how, got, p.reason, describeRaw(status, body))
			}
			covered[p.reason] = true

			row, ok := published[p.reason]
			if !ok {
				t.Fatalf("BUG: the server raises %s over the wire and docs/api/errors.md has "+
					"no row for it. CONVENTIONS §7.1 makes the catalogue part of the API "+
					"contract: an unpublished code is one every client hardcodes from a live "+
					"response.", p.reason)
			}
			if env.Code != row.code {
				t.Errorf("BUG: %s answers Connect code %q and the published catalogue says "+
					"%q. A gRPC client branches on the code, and the two tables that produce "+
					"it — errs.Catalogue() and server/connect.codeFor — are in different "+
					"packages with nothing comparing them.\n  provoked by: %s\n  %s",
					p.reason, env.Code, row.code, p.how, describeRaw(status, body))
			}
			if status != row.status {
				t.Errorf("BUG: %s answers HTTP %d and the published catalogue says %d.\n"+
					"  provoked by: %s\n  %s",
					p.reason, status, row.status, p.how, describeRaw(status, body))
			}
			t.Logf("%s: wire code=%q status=%d; catalogue code=%q status=%d",
				p.reason, env.Code, status, row.code, row.status)
		})
	}

	var uncovered []string
	for reason := range published {
		if !covered[reason] {
			uncovered = append(uncovered, string(reason))
		}
	}
	t.Logf("reasons this suite cannot provoke against this build, so their published "+
		"code and status are UNVERIFIED here: %s", strings.Join(uncovered, ", "))
}

// catalogueRow is one published reason.
type catalogueRow struct {
	code   string
	status int
}

// parseCatalogue reads the generated Markdown table.
//
// Markdown rather than the enum, deliberately. The point is to compare the
// PUBLISHED document — the thing a client author reads — against the wire.
// Reading `errs.Catalogue()` in Go would compare the kernel against the
// transport and skip the artefact entirely, which is where a generation bug
// would live.
func parseCatalogue(md string) map[errs.Reason]catalogueRow {
	out := map[errs.Reason]catalogueRow{}
	for line := range strings.SplitSeq(md, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		cols := strings.Split(line, "|")
		if len(cols) < 5 {
			continue
		}
		reason := strings.Trim(strings.TrimSpace(cols[1]), "`")
		code := strings.Trim(strings.TrimSpace(cols[2]), "`")
		var status int
		if _, err := fmt.Sscanf(strings.TrimSpace(cols[3]), "%d", &status); err != nil {
			continue
		}
		out[errs.Reason(reason)] = catalogueRow{code: code, status: status}
	}
	return out
}

// TestTheOpenAPISpecNamesEveryPublicRPC checks the machine-readable half of the
// authentication contract in the published spec.
//
// proto/openapi.base.yaml renders a `security: []` override onto every method
// that declares `(chronos.options.v1.public) = true`, which is what tells a
// generated client not to attach a bearer token. A method missing the override
// makes the client demand a token the user does not have yet — for `Register`
// and `CreateSession` that is the whole onboarding flow — and a NON-public
// method carrying the override advertises an open endpoint.
//
// Both directions are checked against what the SERVER does, which this package
// already knows from TestEveryAuthenticatedRPCRefusesAnAnonymousCaller.
func TestTheOpenAPISpecNamesEveryPublicRPC(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("locating the repository root: %v", err)
	}
	spec, err := os.ReadFile(filepath.Join(root, "docs", "api", "chronos-openapi.yaml"))
	if err != nil {
		t.Fatalf("reading the published OpenAPI spec: %v", err)
	}
	open := operationsDocumenting(string(spec), "security:")

	for _, rpc := range authenticatedProcedures() {
		if open[specPath(rpc.path)] {
			t.Errorf("BUG: %s refuses an anonymous caller with UNAUTHENTICATED, and the "+
				"published spec gives it a `security:` override — which is how a public "+
				"method is marked. A generated client will call it without a token.",
				rpc.name)
		}
	}

	// The other direction: every method the suite has driven WITHOUT a token
	// must carry the override, or a generated client attaches a bearer it does
	// not have.
	publicOnes := []string{
		"chronos.identity.v1.IdentityService/Register",
		"chronos.identity.v1.IdentityService/VerifyEmail",
		"chronos.identity.v1.IdentityService/ResendEmailVerification",
		"chronos.identity.v1.IdentityService/CheckUsernameAvailability",
		"chronos.identity.v1.IdentityService/RequestPasswordReset",
		"chronos.identity.v1.IdentityService/ResetPassword",
		"chronos.identity.v1.IdentityService/Authenticate",
		"chronos.identity.v1.IdentityService/CreateSession",
		"chronos.system.v1.SystemService/GetStatus",
	}
	for _, p := range publicOnes {
		if !open[p] {
			t.Errorf("BUG: %s is served without a bearer token — this suite calls it that "+
				"way — and the published spec gives it no `security:` override, so a "+
				"generated client will demand a token before onboarding can begin.", p)
		}
	}
	t.Logf("%d operations carry a `security:` override", len(open))
}

// TestGetStatusAnswersWhileUnauthenticated is the one availability promise the
// published documentation makes about a specific method.
//
// proto/openapi.base.yaml: "`GetStatus` must additionally answer while the
// system is degraded, including when authentication itself is unavailable."
// Checked here at its weaker, always-true half — no session at all — because
// that is the half a status page relies on and it costs one call.
func TestGetStatusAnswersWhileUnauthenticated(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	status, body, err := rawPost(ctx, "/chronos.system.v1.SystemService/GetStatus",
		"application/json", `{}`, "", "", nil)
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("BUG: GetStatus is `public: true` and answered %d to an anonymous "+
			"caller.\n%s", status, describeRaw(status, body))
	}
	if !strings.Contains(body, `"dependencies"`) {
		t.Errorf("GetStatus answered 200 with no dependency list; a status page has "+
			"nothing to render: %s", strings.TrimSpace(body))
	}
}
