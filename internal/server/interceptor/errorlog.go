package interceptor

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"connectrpc.com/connect"
	"github.com/chronos/chronos-go/internal/platform/errs"
	srvconnect "github.com/chronos/chronos-go/internal/server/connect"
)

// ErrorObserver counts the failures this gate reports.
//
// Declared here, by the consumer, and satisfied structurally by
// obs.Metrics.RPC() — so neither package imports the other and this one carries
// no dependency on Prometheus (CONVENTIONS §2).
type ErrorObserver interface {
	// Internal records one request answered with a code that tells the caller
	// nothing. Both arguments are closed sets: a registered procedure name and a
	// Connect code.
	Internal(procedure, code string)
}

// ErrorLog is the last thing that sees a failed request, and the only thing that
// records why it failed.
//
// # Why this exists
//
// `srvconnect.Error` maps an error that never passed through `errs` to a bare
// INTERNAL with no message and no detail. That mapping is correct and is not
// negotiable — an unclassified error has not been through the disclosure ladder,
// so nothing is known about what it is safe to say, and ADR-036 puts the
// disclosure boundary at the authz gate. The defect it left is that the cause
// then reached NOBODY. The first end-to-end run of the identity slice produced
// `internal: internal error` on the wire and not one line in the log; a
// five-minute diagnosis took an hour.
//
// # Why an interceptor and not the mapping function
//
// `srvconnect.Error` has the cause in hand but nothing else. It takes no
// context, so it cannot name the procedure or the trace, and it is called from
// nine places including two gates — passing a context to all of them would put
// the same three arguments at every call site and make forgetting one the new
// failure mode. An interceptor has the opposite problem and the better trade: it
// has the context, the procedure and one place to be wrong, and it sees EVERY
// failed request exactly once, including the errors that never reached
// `srvconnect.Error` at all. The cause travels the one hop between them attached
// to the wire error (see srvconnect.Cause).
//
// # What it does not do
//
// It does not touch the response. The error it was handed is the error it
// returns, byte for byte, and the log line is written beside it rather than
// derived from it.
//
// It does not log a classified failure. A NOT_FOUND, a QUOTA_EXCEEDED or a
// VALIDATION_FAILED has already told the caller what happened and needs no
// operator; logging them would bury the ones that do under everything a
// misbehaving client can generate at will. Only the codes that disclose nothing
// are recorded.
type ErrorLog struct {
	log      *slog.Logger
	observer ErrorObserver
}

// NewErrorLog builds the gate. A nil logger falls back to slog.Default, and a
// nil observer to a counter that discards — this gate must never be the reason a
// request fails, and a composition root that has not wired metrics is still
// better served by log lines than by a panic.
func NewErrorLog(log *slog.Logger, observer ErrorObserver) *ErrorLog {
	if log == nil {
		log = slog.Default()
	}
	if observer == nil {
		observer = discardObserver{}
	}
	return &ErrorLog{log: log, observer: observer}
}

type discardObserver struct{}

func (discardObserver) Internal(string, string) {}

// WrapUnary records the cause of every unary failure that discloses nothing.
func (l *ErrorLog) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		res, err := next(ctx, req)
		if err != nil {
			l.record(ctx, req.Spec().Procedure, req.Header(), err)
		}
		return res, err
	}
}

// WrapStreamingHandler does the same for streaming methods.
//
// Every streaming method is currently refused by Gates with an INTERNAL, which
// is exactly the shape of failure this gate exists to make visible: the refusal
// says "not gated" server-side and "internal error" on the wire.
func (l *ErrorLog) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		err := next(ctx, conn)
		if err != nil {
			l.record(ctx, conn.Spec().Procedure, conn.RequestHeader(), err)
		}
		return err
	}
}

// WrapStreamingClient is required by the interface. This server makes no
// outbound calls through it, and a client failure is the caller's to report.
func (l *ErrorLog) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// record writes the one log line and the one metric.
//
// The two uninformative codes are INTERNAL and UNKNOWN. UNKNOWN is included
// deliberately: it is what connect assigns an error that reached the transport
// having passed through no mapping at all, which is a strictly worse version of
// the same bug and the one shape `srvconnect.Error` cannot have produced.
func (l *ErrorLog) record(
	ctx context.Context, procedure string, header http.Header, err error,
) {
	code := connect.CodeOf(err)
	if code != connect.CodeInternal && code != connect.CodeUnknown {
		return
	}

	l.observer.Internal(procedure, code.String())

	// The cause is what srvconnect.Error pinned to the wire error. When there is
	// none the error never went through the mapping, so the error itself is the
	// most that is known.
	cause := srvconnect.Cause(err)
	if cause == nil {
		cause = err
	}

	// Whether the failure was classified is worth saying explicitly. An INTERNAL
	// that came from `errs.Internalf` is a fault we named; one that came from a
	// bare `fmt.Errorf` is a fault nobody classified, and the second is a defect
	// in the handler as well as an incident.
	attrs := []any{
		slog.String("procedure", procedure),
		slog.String("code", code.String()),
		slog.Bool("classified", classified(cause)),
		slog.String("cause", scrub(cause.Error())),
	}
	// The correlation the request already carries, and nothing invented here.
	//
	// The trace id arrives on its own: obs.TraceHandler stamps trace_id and
	// span_id onto every *Context record, which is why this line is ErrorContext
	// and why there is no trace attribute below. When tracing is off, or a client
	// propagates no trace context, the idempotency key is what remains — and for
	// the four PUBLIC identity RPCs it is the only correlation there has ever
	// been, because they skip the gate pipeline that would otherwise open a
	// causation chain. It is not personal data: client-generated opaque text,
	// documented as such by the header's own contract.
	if key := header.Get(IdempotencyHeader); key != "" {
		attrs = append(attrs, slog.String("idempotency_key", key))
	}

	// A fixed message, because it is the grouping key in every log backend. The
	// variable half is in the attributes.
	l.log.ErrorContext(ctx, "rpc failed with a cause the caller was not told", attrs...)
}

// classified reports whether the cause was ever given a Reason.
func classified(cause error) bool {
	_, ok := errs.As(cause)
	return ok
}

// emailPattern is deliberately loose: it matches more than RFC 5322 does,
// because a false positive costs a redacted fragment of a log line and a false
// negative costs an address in a durable log (ADR-002).
var emailPattern = regexp.MustCompile(`[\w.+-]+@[\w-]+\.[\w.-]+`)

// maxCauseBytes caps one logged chain. A driver error can carry a whole
// statement, and a log line that has to be truncated by the shipper is one
// nobody can read at 3am.
const maxCauseBytes = 2048

// scrub is the last defence against personal data in a log line.
//
// The rule is that nothing personal enters an event or a log (ADR-002), and the
// error chains this gate prints are the one place that rule is enforced by
// nobody upstream: `errs` keeps its unsafe detail in a wrapped error precisely
// so it can be logged, and a handler that formatted an address into a
// `fmt.Errorf` — "loading the account for alice@example.com" — has already
// broken the rule by the time the text arrives here. So addresses are removed
// from the TEXT rather than trusted not to be in it.
//
// This is a mitigation and not a proof. It catches the shape that actually
// appears in this codebase's error strings (identity's errors are about
// addresses) and it does not catch a name, a phone number or a postal address.
// The primary control is still that handlers format `SubjectID` pseudonyms and
// never people; this makes the commonest breach of it non-durable.
func scrub(s string) string {
	s = emailPattern.ReplaceAllString(s, "[redacted-email]")
	if len(s) > maxCauseBytes {
		// Cut on a rune boundary, and say that it was cut: a silently truncated
		// error reads as a complete one.
		s = strings.ToValidUTF8(s[:maxCauseBytes], "") + "…[truncated]"
	}
	return s
}

var _ connect.Interceptor = (*ErrorLog)(nil)
