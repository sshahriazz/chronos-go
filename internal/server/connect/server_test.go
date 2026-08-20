package connect_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	connectrpc "connectrpc.com/connect"
	systemv1 "github.com/chronos/chronos-go/gen/proto/chronos/system/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/system/v1/systemv1connect"
	"github.com/chronos/chronos-go/internal/server/connect"
)

// stubSystem is the smallest real Connect service. Real matters: the point of
// these tests is what the PROTOCOL puts on the wire, and a bare http.Handler
// would measure the wrong thing.
type stubSystem struct{}

func (stubSystem) GetStatus(
	context.Context, *connectrpc.Request[systemv1.GetStatusRequest],
) (*connectrpc.Response[systemv1.GetStatusResponse], error) {
	return connectrpc.NewResponse(&systemv1.GetStatusResponse{}), nil
}

// transport is one of the five protocol/version pairs this single port carries.
type transport struct {
	name string
	h2   bool
	opts []connectrpc.ClientOption
}

func transports() []transport {
	return []transport{
		{"connect/http1.1", false, nil},
		{"connect/h2c", true, nil},
		{"grpc/h2c", true, []connectrpc.ClientOption{connectrpc.WithGRPC()}},
		{"grpc-web/http1.1", false, []connectrpc.ClientOption{connectrpc.WithGRPCWeb()}},
		{"grpc-web/h2c", true, []connectrpc.ClientOption{connectrpc.WithGRPCWeb()}},
	}
}

// serveWithLimits builds a server carrying THIS package's protocol set at the
// given header limits.
func serveWithLimits(t *testing.T, maxValues, maxBytes int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(systemv1connect.NewSystemServiceHandler(stubSystem{}))

	srv := httptest.NewUnstartedServer(mux)
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(true)
	srv.Config.Protocols = &protocols
	srv.Config.MaxHeaderValueCount = maxValues
	srv.Config.MaxHeaderBytes = maxBytes
	// Refusing an oversized header block is what several of these tests ASK for,
	// and the h2 server logs each refusal as a connection error. Discarded so a
	// passing run does not read like a failing one.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func clientFor(tr transport) *http.Client {
	t := &http.Transport{}
	var p http.Protocols
	if tr.h2 {
		p.SetUnencryptedHTTP2(true)
	} else {
		p.SetHTTP1(true)
	}
	t.Protocols = &p
	return &http.Client{Transport: t}
}

func callWith(t *testing.T, srv *httptest.Server, tr transport, extra http.Header) error {
	t.Helper()
	c := systemv1connect.NewSystemServiceClient(clientFor(tr), srv.URL, tr.opts...)
	req := connectrpc.NewRequest(&systemv1.GetStatusRequest{})
	for name, values := range extra {
		for _, v := range values {
			req.Header().Add(name, v)
		}
	}
	_, err := c.GetStatus(t.Context(), req)
	return err
}

// applicationHeaders is every header this codebase actually reads, at the
// largest size each can legitimately be.
func applicationHeaders() http.Header {
	h := http.Header{}
	// interceptor.AuthorizationHeader. app.sessionTokenBytes is 32 bytes of
	// entropy, which is 43 base64url characters.
	h.Set("Authorization", "Bearer "+strings.Repeat("a", 43))
	// interceptor.IdempotencyHeader, a prefixed ULID.
	h.Set("Idempotency-Key", "idm_"+strings.Repeat("0", 26))
	// What otelhttp extracts, at the W3C maximum: tracestate is capped at 512
	// bytes by the specification, not by us.
	h.Set("Traceparent", "00-"+strings.Repeat("a", 32)+"-"+strings.Repeat("b", 16)+"-01")
	h.Set("Tracestate", strings.Repeat("x", 512))
	// clientip.Scope reads Header.Values, so eight separate field lines — one per
	// hop config.MaxTrustedProxyHops permits — each count against the value
	// budget. A comma-joined single line would be cheaper; a caller is under no
	// obligation to send it that way.
	for i := range 8 {
		h.Add("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i))
	}
	return h
}

// browserAndInfrastructureHeaders is applicationHeaders plus everything a real
// deployment adds without asking: Chrome's client hints, cookies split one per
// field as HTTP/2 clients do, a CDN's header family and a service mesh's.
//
// This is the set the limits are sized against, because it is the only one that
// describes a request we must not refuse.
func browserAndInfrastructureHeaders() http.Header {
	h := applicationHeaders()
	for name, v := range map[string]string{
		"User-Agent":      strings.Repeat("u", 200),
		"Accept":          "*/*",
		"Accept-Encoding": "gzip, deflate, br, zstd",
		"Accept-Language": "en-US,en;q=0.9,fr;q=0.8,de;q=0.7",
		"Origin":          "https://app.example.com",
		"Referer":         "https://app.example.com/some/long/path?with=query&params=here",
		"Priority":        "u=1, i",
		"Dnt":             "1",

		"Sec-Ch-Ua":                   `"Chromium";v="140", "Not:A-Brand";v="24", "Google Chrome";v="140"`,
		"Sec-Ch-Ua-Mobile":            "?0",
		"Sec-Ch-Ua-Platform":          `"macOS"`,
		"Sec-Ch-Ua-Platform-Version":  `"15.5.0"`,
		"Sec-Ch-Ua-Arch":              `"arm"`,
		"Sec-Ch-Ua-Model":             `""`,
		"Sec-Ch-Ua-Full-Version-List": `"Chromium";v="140.0.7339.80"`,
		"Sec-Fetch-Site":              "same-site",
		"Sec-Fetch-Mode":              "cors",
		"Sec-Fetch-Dest":              "empty",

		"Cf-Ray": "8f3a2b1c4d5e6f70-AMS", "Cf-Connecting-Ip": "203.0.113.9",
		"Cf-Ipcountry": "NL", "Cf-Visitor": `{"scheme":"https"}`,
		"X-Forwarded-Proto": "https", "X-Forwarded-Port": "443",
		"X-Forwarded-Host": "app.example.com", "X-Real-Ip": "203.0.113.9",
		"X-Request-Id":    strings.Repeat("r", 36),
		"X-Amzn-Trace-Id": "Root=1-67891233-abcdef012345678912345678",

		"X-Envoy-External-Address":       "203.0.113.9",
		"X-Envoy-Expected-Rq-Timeout-Ms": "15000",
		"X-B3-Traceid":                   strings.Repeat("b", 32),
		"X-B3-Spanid":                    strings.Repeat("s", 16),
		"X-B3-Sampled":                   "1",
	} {
		h.Set(name, v)
	}
	for i := range 8 {
		h.Add("Cookie", fmt.Sprintf("sess_%d=%s", i, strings.Repeat("c", 96)))
	}
	return h
}

// smallestWorkingValueCount finds the lowest MaxHeaderValueCount at which the
// request still succeeds.
//
// Searching for the floor rather than counting the headers is deliberate. Go's
// two accountings disagree with each other and with http.Request.Header: HTTP/2
// counts the four pseudo-headers, which never appear in the map, and HTTP/1
// moves Host and Content-Length out of it. A number derived by counting would be
// wrong in a direction nothing reports.
func smallestWorkingValueCount(t *testing.T, tr transport, h http.Header) int {
	t.Helper()
	for n := 1; n <= 256; n++ {
		if callWith(t, serveWithLimits(t, n, 1<<20), tr, h) == nil {
			return n
		}
	}
	t.Fatalf("%s: no MaxHeaderValueCount up to 256 accepted the request", tr.name)
	return 0
}

func smallestWorkingHeaderBytes(t *testing.T, tr transport, h http.Header) int {
	t.Helper()
	lo, hi := 64, 1<<20
	if callWith(t, serveWithLimits(t, 500, hi), tr, h) != nil {
		t.Fatalf("%s: the request fails even at %d header bytes", tr.name, hi)
	}
	for lo < hi {
		mid := lo + (hi-lo)/2
		if callWith(t, serveWithLimits(t, 500, mid), tr, h) == nil {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return lo
}

// The limits must be DERIVED from what the protocols send, and must leave room
// for the fat end of legitimate traffic.
//
// This test is the experiment that produced connect.MaxHeaderBytes and
// connect.MaxHeaderValueCount, kept so the derivation re-runs. It fails if a
// toolchain upgrade, a Connect upgrade or a new header this codebase reads
// pushes the real requirement up towards the configured ceiling — which is the
// moment the constants stop being safe and start being a rejection rate.
func TestTheHeaderLimitsAreDerivedFromWhatTheProtocolsActuallySend(t *testing.T) {
	sets := []struct {
		name string
		h    http.Header
	}{
		{"bare protocol floor", nil},
		{"plus what this codebase reads", applicationHeaders()},
		{"plus a browser, a CDN and a mesh", browserAndInfrastructureHeaders()},
	}

	worstValues, worstBytes := 0, 0
	for _, set := range sets {
		for _, tr := range transports() {
			values := smallestWorkingValueCount(t, tr, set.h)
			bytes := smallestWorkingHeaderBytes(t, tr, set.h)
			t.Logf("%-34s %-17s needs MaxHeaderValueCount>=%-3d MaxHeaderBytes>=%d",
				set.name, tr.name, values, bytes)
			worstValues = max(worstValues, values)
			worstBytes = max(worstBytes, bytes)
		}
	}

	// Headroom, stated as a ratio rather than a slack constant, so the assertion
	// keeps its meaning as the measured requirement moves.
	const (
		minValueHeadroom = 2.0
		minByteHeadroom  = 3.0
	)
	if got := float64(connect.MaxHeaderValueCount) / float64(worstValues); got < minValueHeadroom {
		t.Errorf("MaxHeaderValueCount is %d and the worst legitimate request measured needs "+
			"%d: %.1fx headroom, below the %.1fx this is meant to carry. Too low does not "+
			"fail loudly — it refuses real clients at 431 while every test here passes",
			connect.MaxHeaderValueCount, worstValues, got, minValueHeadroom)
	}
	if got := float64(connect.MaxHeaderBytes) / float64(worstBytes); got < minByteHeadroom {
		t.Errorf("MaxHeaderBytes is %d and the worst legitimate request measured needs %d: "+
			"%.1fx headroom, below the %.1fx this is meant to carry",
			connect.MaxHeaderBytes, worstBytes, got, minByteHeadroom)
	}

	// And the other direction. A limit far above what anything needs is not a
	// limit; the whole reason to set these is that Go's defaults (1 MiB, 500) are
	// larger than any real request by three orders of magnitude.
	if connect.MaxHeaderBytes >= http.DefaultMaxHeaderBytes {
		t.Errorf("MaxHeaderBytes is %d, no tighter than Go's default of %d",
			connect.MaxHeaderBytes, http.DefaultMaxHeaderBytes)
	}
	if connect.MaxHeaderValueCount >= http.DefaultMaxHeaderValueCount {
		t.Errorf("MaxHeaderValueCount is %d, no tighter than Go's default of %d",
			connect.MaxHeaderValueCount, http.DefaultMaxHeaderValueCount)
	}
}

// The configured limits must actually let a fat-but-legitimate request through,
// on every transport. This is the assertion that would fail if somebody tuned
// the constants down "to be safe".
func TestALargeButLegitimateRequestIsNotRefused(t *testing.T) {
	cfg := connect.DefaultConfig("127.0.0.1:0")
	for _, tr := range transports() {
		t.Run(tr.name, func(t *testing.T) {
			srv := serveWithLimits(t, cfg.MaxHeaderValueCount, cfg.MaxHeaderBytes)
			if err := callWith(t, srv, tr, browserAndInfrastructureHeaders()); err != nil {
				t.Fatalf("a request carrying a browser's, a CDN's and a mesh's headers was "+
					"refused at MaxHeaderValueCount=%d MaxHeaderBytes=%d: %v",
					cfg.MaxHeaderValueCount, cfg.MaxHeaderBytes, err)
			}
		})
	}
}

// An abusive request must be REFUSED. Without this, the limits could be unset
// and every other test here would still pass.
func TestAnAbusiveHeaderBlockIsRefused(t *testing.T) {
	cfg := connect.DefaultConfig("127.0.0.1:0")

	tooMany := http.Header{}
	for i := range cfg.MaxHeaderValueCount + 50 {
		tooMany.Add("X-Filler", fmt.Sprintf("%d", i))
	}
	// MaxHeaderBytes+1 is NOT enough to trip HTTP/1.1. Go reads up to
	// initialReadLimitSize, which is MaxHeaderBytes plus a further 4 KiB of
	// slack, and only then applies the limit — so the effective HTTP/1 ceiling
	// is 4 KiB above the configured one while HTTP/2 enforces it exactly.
	// Measured, not read off the docs: at +1 byte both HTTP/1 transports
	// accepted the request and both h2 transports refused it.
	const http1Slack = 4 << 10
	tooBig := http.Header{}
	tooBig.Set("X-Filler", strings.Repeat("z", cfg.MaxHeaderBytes+http1Slack+1))

	for _, tr := range transports() {
		srv := serveWithLimits(t, cfg.MaxHeaderValueCount, cfg.MaxHeaderBytes)
		if err := callWith(t, srv, tr, tooMany); err == nil {
			t.Errorf("%s: a request with %d header values was accepted at a limit of %d",
				tr.name, cfg.MaxHeaderValueCount+50, cfg.MaxHeaderValueCount)
		}
		if err := callWith(t, srv, tr, tooBig); err == nil {
			t.Errorf("%s: a request with a %d-byte header value was accepted at a limit of %d",
				tr.name, cfg.MaxHeaderBytes+http1Slack+1, cfg.MaxHeaderBytes)
		}
	}
}

// DefaultConfig must carry every limit through to the http.Server, and must
// bound the header phase.
//
// The two failures this catches are silent in opposite ways. A limit left at
// zero is Go's default, which works — it is just eight to thirty-two times
// looser than intended, and nothing says so. A ReadHeaderTimeout left at zero
// falls back to ReadTimeout, so a slowloris connection holds a socket for thirty
// seconds instead of five, and that too works.
func TestDefaultConfigSetsEveryHeaderLimit(t *testing.T) {
	cfg := connect.DefaultConfig("127.0.0.1:0")
	for _, tc := range []struct {
		name string
		got  int
	}{
		{"MaxHeaderBytes", cfg.MaxHeaderBytes},
		{"MaxHeaderValueCount", cfg.MaxHeaderValueCount},
		{"ReadHeaderTimeout", int(cfg.ReadHeaderTimeout)},
	} {
		if tc.got <= 0 {
			t.Errorf("DefaultConfig leaves %s at %d, which means Go's default", tc.name, tc.got)
		}
	}
	if cfg.ReadHeaderTimeout >= cfg.ReadTimeout {
		t.Errorf("ReadHeaderTimeout %s is not below ReadTimeout %s, so it bounds nothing "+
			"the read deadline did not already bound", cfg.ReadHeaderTimeout, cfg.ReadTimeout)
	}
}
