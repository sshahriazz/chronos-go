package interceptor_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/identity/v1/identityv1connect"
	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/obs"
	srvconnect "github.com/chronos/chronos-go/internal/server/connect"
	"github.com/chronos/chronos-go/internal/server/interceptor"
	"github.com/prometheus/client_golang/prometheus/testutil"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// This file is the regression test for the outage that produced ErrorLog.
//
// `VerifyEmail` returned `fmt.Errorf("loading the account…: %w", err)`. The
// mapping turned it — correctly — into a bare INTERNAL, and the cause then
// reached nobody: `internal: internal error` on the wire and silence in the log.
// So every test below drives a REAL error through a REAL Connect server carrying
// the REAL interceptor and asserts on what an operator and a caller each end up
// holding. Calling record() directly would prove nothing about a gate that has
// to be wired to work, and this repository has shipped six seams that were fully
// built, fully tested and constructed by no binary.

// verifyFailure is the handler under test: one RPC, one configurable failure.
type verifyFailure struct {
	identityv1connect.UnimplementedIdentityServiceHandler
	err error
}

func (v *verifyFailure) VerifyEmail(
	context.Context, *connect.Request[identityv1.VerifyEmailRequest],
) (*connect.Response[identityv1.VerifyEmailResponse], error) {
	if v.err != nil {
		return nil, v.err
	}
	return connect.NewResponse(&identityv1.VerifyEmailResponse{SubjectId: "sub_ok"}), nil
}

// logLine is one JSON record, decoded so assertions are about FIELDS rather than
// about substrings of a formatted line — a substring match would pass on a line
// that happened to mention the procedure in its message.
type logLine map[string]any

// newLoggedServer starts a server carrying the error gate and nothing else, and
// returns the client, the captured log and the metrics the gate wrote to.
//
// The logger is assembled exactly as cmd/api assembles it, TraceHandler and all:
// the trace correlation is a property of that stack, not of ErrorLog, and a test
// that built a bare JSONHandler would assert a correlation production does not
// have.
func newLoggedServer(t *testing.T, svc *verifyFailure) (
	identityv1connect.IdentityServiceClient, *bytes.Buffer, *obs.Metrics,
) {
	t.Helper()

	var captured bytes.Buffer
	log := slog.New(obs.NewTraceHandler(
		slog.NewJSONHandler(&captured, &slog.HandlerOptions{Level: slog.LevelInfo})))
	metrics := obs.New()

	_, handler := identityv1connect.NewIdentityServiceHandler(svc,
		connect.WithInterceptors(interceptor.NewErrorLog(log, metrics.RPC())))

	// A span around the request, which is what otelhttp does in cmd/api. Without
	// it there is no trace in the context and the log line cannot carry one.
	provider := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	traced := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := provider.Tracer("errorlog_test").Start(r.Context(), "request")
		defer span.End()
		handler.ServeHTTP(w, r.WithContext(ctx))
	})

	srv := httptest.NewServer(traced)
	t.Cleanup(srv.Close)

	return identityv1connect.NewIdentityServiceClient(srv.Client(), srv.URL), &captured, metrics
}

// verify sends one VerifyEmail carrying an idempotency key.
func verify(t *testing.T, client identityv1connect.IdentityServiceClient) error {
	t.Helper()

	req := connect.NewRequest(&identityv1.VerifyEmailRequest{
		Token: strings.Repeat("t", 43),
	})
	req.Header().Set(interceptor.IdempotencyHeader, "idem-verify-1")
	_, err := client.VerifyEmail(t.Context(), req)
	return err
}

// records decodes every captured log line.
func records(t *testing.T, captured *bytes.Buffer) []logLine {
	t.Helper()

	var out []logLine
	for raw := range strings.SplitSeq(strings.TrimSpace(captured.String()), "\n") {
		if raw == "" {
			continue
		}
		line, err := codec.Tolerant[logLine]([]byte(raw))
		if err != nil {
			t.Fatalf("log line is not JSON: %q (%v)", raw, err)
		}
		out = append(out, line)
	}
	return out
}

// only returns the single record, failing if there is not exactly one. Silence
// is the failure this whole gate exists to prevent, so it is asserted loudly.
func only(t *testing.T, lines []logLine) logLine {
	t.Helper()

	if len(lines) != 1 {
		t.Fatalf("got %d log lines, want exactly 1: %v", len(lines), lines)
	}
	return lines[0]
}

func str(t *testing.T, line logLine, key string) string {
	t.Helper()

	v, ok := line[key]
	if !ok {
		t.Fatalf("the log line has no %q field: %v", key, line)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("log field %q = %v, want a string", key, v)
	}
	return s
}

// THE REGRESSION. An unclassified error reaches the operator in full and the
// caller not at all.
func TestAnUnclassifiedErrorIsLoggedWithItsCauseAndCountedOnce(t *testing.T) {
	t.Parallel()

	// The original failure, verbatim in shape, with an address formatted into it
	// — which is the ADR-002 hazard this gate has to survive rather than assume
	// away.
	cause := fmt.Errorf("loading the account for ada@example.com: %w",
		errors.New("dial tcp 127.0.0.1:5432: connection refused"))
	client, captured, metrics := newLoggedServer(t, &verifyFailure{
		err: srvconnect.Error(cause),
	})

	err := verify(t, client)

	// 1. The caller learns nothing. This is the half that was already correct.
	if got := connect.CodeOf(err); got != connect.CodeInternal {
		t.Fatalf("code = %v, want internal", got)
	}
	var wire *connect.Error
	if !errors.As(err, &wire) {
		t.Fatalf("client error is not a *connect.Error: %v", err)
	}
	if wire.Message() != "internal error" {
		t.Errorf("wire message = %q, want %q", wire.Message(), "internal error")
	}
	for _, leak := range []string{"ada@example.com", "5432", "connection refused", "loading"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("the response leaked %q: %q", leak, err.Error())
		}
	}

	// 2. The operator learns everything. This is the half that was missing.
	line := only(t, records(t, captured))
	if got := str(t, line, "level"); got != "ERROR" {
		t.Errorf("level = %q, want ERROR", got)
	}
	if got := str(t, line, "procedure"); got != identityv1connect.IdentityServiceVerifyEmailProcedure {
		t.Errorf("procedure = %q, want %q",
			got, identityv1connect.IdentityServiceVerifyEmailProcedure)
	}
	if got := str(t, line, "code"); got != "internal" {
		t.Errorf("code = %q, want internal", got)
	}
	if got, ok := line["classified"].(bool); !ok || got {
		t.Errorf("classified = %v, want false", line["classified"])
	}
	logged := str(t, line, "cause")
	for _, want := range []string{"loading the account", "connection refused", "5432"} {
		if !strings.Contains(logged, want) {
			t.Errorf("the logged cause is missing %q: %q", want, logged)
		}
	}

	// 3. And nothing personal went into a durable log (ADR-002).
	if strings.Contains(logged, "ada@example.com") {
		t.Errorf("the log line carries an address: %q", logged)
	}
	if !strings.Contains(logged, "[redacted-email]") {
		t.Errorf("the address was removed without a marker: %q", logged)
	}

	// 4. Correlation the request already carried, and none invented here.
	if got := str(t, line, "idempotency_key"); got != "idem-verify-1" {
		t.Errorf("idempotency_key = %q, want %q", got, "idem-verify-1")
	}
	if got := str(t, line, "trace_id"); got == "" || strings.Trim(got, "0") == "" {
		t.Errorf("trace_id = %q, want the id of the span the request ran under", got)
	}

	// 5. And it is alertable.
	if got := testutil.ToFloat64(metrics.RPCInternal.WithLabelValues(
		identityv1connect.IdentityServiceVerifyEmailProcedure, "internal")); got != 1 {
		t.Errorf("chronos_rpc_internal_total = %v, want 1", got)
	}
}

// A classified INTERNAL is logged too — it maps to a code that discloses nothing
// — but it is marked as one we named, because an unclassified INTERNAL is a
// defect in the handler on top of being an incident.
func TestAClassifiedInternalIsLoggedAndMarkedClassified(t *testing.T) {
	t.Parallel()

	client, captured, metrics := newLoggedServer(t, &verifyFailure{
		err: srvconnect.Error(errs.Internalf("the user directory is unavailable").
			Wrap(errors.New("no route to host"))),
	})

	err := verify(t, client)
	if got := connect.CodeOf(err); got != connect.CodeInternal {
		t.Fatalf("code = %v, want internal", got)
	}

	line := only(t, records(t, captured))
	if got, ok := line["classified"].(bool); !ok || !got {
		t.Errorf("classified = %v, want true", line["classified"])
	}
	if got := str(t, line, "cause"); !strings.Contains(got, "no route to host") {
		t.Errorf("the logged cause is missing the wrapped error: %q", got)
	}
	if got := testutil.ToFloat64(metrics.RPCInternal.WithLabelValues(
		identityv1connect.IdentityServiceVerifyEmailProcedure, "internal")); got != 1 {
		t.Errorf("chronos_rpc_internal_total = %v, want 1", got)
	}
}

// A classified refusal is the system working. It must not appear in the log at
// all: a client can generate these at will, and a gate that logged them would
// bury the faults it exists to surface under whatever a bad client sends.
func TestAClassifiedRefusalIsNeitherLoggedNorCounted(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		err  error
		want connect.Code
	}{
		{"not found", errs.NotFoundf("no such session"), connect.CodeNotFound},
		{"validation", errs.ValidationFailedf("token is required"), connect.CodeInvalidArgument},
		{"unauthenticated", errs.Unauthenticatedf("no session"), connect.CodeUnauthenticated},
		{"quota", errs.QuotaExceededf("seat limit reached"), connect.CodeResourceExhausted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client, captured, metrics := newLoggedServer(t, &verifyFailure{
				err: srvconnect.Error(tc.err),
			})

			err := verify(t, client)
			if got := connect.CodeOf(err); got != tc.want {
				t.Fatalf("code = %v, want %v", got, tc.want)
			}
			if lines := records(t, captured); len(lines) != 0 {
				t.Errorf("a classified refusal was logged: %v", lines)
			}
			if got := testutil.CollectAndCount(metrics.RPCInternal); got != 0 {
				t.Errorf("chronos_rpc_internal_total has %d series, want 0", got)
			}
		})
	}
}

// An error that reached the transport through no mapping at all is the strictly
// worse version of the same bug: connect stamps it UNKNOWN and puts its TEXT on
// the wire. The gate cannot un-send that, but it must not let it go unrecorded
// as well.
func TestAnErrorThatSkippedTheMappingIsStillRecorded(t *testing.T) {
	t.Parallel()

	client, captured, metrics := newLoggedServer(t, &verifyFailure{
		err: errors.New("a handler returned this without mapping it"),
	})

	err := verify(t, client)
	if got := connect.CodeOf(err); got != connect.CodeUnknown {
		t.Fatalf("code = %v, want unknown", got)
	}

	line := only(t, records(t, captured))
	if got := str(t, line, "code"); got != "unknown" {
		t.Errorf("code = %q, want unknown", got)
	}
	if got := str(t, line, "cause"); !strings.Contains(got, "without mapping it") {
		t.Errorf("cause = %q, want the unmapped error's own text", got)
	}
	if got := testutil.ToFloat64(metrics.RPCInternal.WithLabelValues(
		identityv1connect.IdentityServiceVerifyEmailProcedure, "unknown")); got != 1 {
		t.Errorf("chronos_rpc_internal_total{code=\"unknown\"} = %v, want 1", got)
	}
}

// A request that succeeds writes nothing. Stated because the cheapest way to
// pass every test above is to log unconditionally.
func TestASuccessfulRequestLogsNothing(t *testing.T) {
	t.Parallel()

	client, captured, metrics := newLoggedServer(t, &verifyFailure{})

	if err := verify(t, client); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if lines := records(t, captured); len(lines) != 0 {
		t.Errorf("a successful request was logged: %v", lines)
	}
	if got := testutil.CollectAndCount(metrics.RPCInternal); got != 0 {
		t.Errorf("chronos_rpc_internal_total has %d series, want 0", got)
	}
}

// The response is unchanged, proven by comparison rather than by assertion:
// the same failures are served by two servers that differ only in whether the
// gate is present, and the client cannot tell them apart.
func TestTheResponseIsIdenticalWithAndWithoutTheGate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"unclassified", srvconnect.Error(errors.New("loading the account: refused"))},
		{"classified internal", srvconnect.Error(errs.Internalf("directory unavailable"))},
		{"refusal with a detail", srvconnect.Error(errs.PlanUpgradeRequiredf("not on this plan"))},
		{"unmapped", errors.New("no mapping at all")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gated, _, _ := newLoggedServer(t, &verifyFailure{err: tc.err})

			// The control: the same handler, no interceptors whatsoever.
			_, plain := identityv1connect.NewIdentityServiceHandler(&verifyFailure{err: tc.err})
			srv := httptest.NewServer(plain)
			t.Cleanup(srv.Close)
			ungated := identityv1connect.NewIdentityServiceClient(srv.Client(), srv.URL)

			withGate, withoutGate := verify(t, gated), verify(t, ungated)

			if a, b := connect.CodeOf(withGate), connect.CodeOf(withoutGate); a != b {
				t.Errorf("code %v with the gate, %v without it", a, b)
			}
			if a, b := withGate.Error(), withoutGate.Error(); a != b {
				t.Errorf("message %q with the gate, %q without it", a, b)
			}
			if a, b := details(t, withGate), details(t, withoutGate); a != b {
				t.Errorf("details %q with the gate, %q without it", a, b)
			}
		})
	}
}

// details renders an error's Connect details as a comparable string.
func details(t *testing.T, err error) string {
	t.Helper()

	var wire *connect.Error
	if !errors.As(err, &wire) {
		return "<not a connect error>"
	}
	var out []string
	for _, d := range wire.Details() {
		value, verr := d.Value()
		if verr != nil {
			t.Fatalf("decoding a detail: %v", verr)
		}
		out = append(out, fmt.Sprintf("%v", value))
	}
	return strings.Join(out, "|")
}

// NewErrorLog must not be the reason a request fails. A composition root that
// wired neither a logger nor an observer still serves.
func TestTheGateToleratesNoLoggerAndNoObserver(t *testing.T) {
	t.Parallel()

	_, handler := identityv1connect.NewIdentityServiceHandler(
		&verifyFailure{err: srvconnect.Error(errors.New("boom"))},
		connect.WithInterceptors(interceptor.NewErrorLog(nil, nil)))
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	err := verify(t, identityv1connect.NewIdentityServiceClient(srv.Client(), srv.URL))
	if got := connect.CodeOf(err); got != connect.CodeInternal {
		t.Errorf("code = %v, want internal", got)
	}
}
