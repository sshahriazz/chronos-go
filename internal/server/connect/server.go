// Package connect bootstraps the HTTP server that carries every protocol.
//
// One port serves gRPC, gRPC-Web and HTTP/JSON from the same handlers
// (ADR-007).
//
// gRPC needs HTTP/2. Locally there is no TLS, so unencrypted HTTP/2 is enabled
// through http.Server.Protocols — the stdlib mechanism that replaced the
// deprecated x/net/http2/h2c wrapper. With TLS in front, ALPN negotiates it.
package connect

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// Config holds the server's transport settings.
type Config struct {
	Addr              string
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration

	// MaxHeaderBytes and MaxHeaderValueCount bound the request head. See
	// DefaultConfig for where the numbers come from — they are measured, not
	// chosen.
	MaxHeaderBytes      int
	MaxHeaderValueCount int
}

// MaxHeaderBytes and MaxHeaderValueCount bound how much request HEAD this
// server will accept. Both are derived from measurement — see
// TestTheHeaderLimitsAreDerivedFromWhatTheProtocolsActuallySend, which is the
// experiment that produced them and which fails if either number drops below
// what a real client needs.
//
// # How the numbers were obtained
//
// Not by counting headers by hand: Go's two accountings disagree with each other
// and with the wire. HTTP/1 charges raw bytes and then grants a further 4 KiB of
// slack on top of MaxHeaderBytes; HTTP/2 charges the HPACK-decoded size, which
// adds 32 bytes of bookkeeping PER FIELD, and its value count includes the four
// pseudo-headers that never appear in http.Request.Header at all. So the method
// was to serve a real handler behind this package's own Server, drive it with a
// real Connect client over all five transports this build carries
// (Connect/HTTP-1.1, Connect/h2c, gRPC/h2c, gRPC-Web/HTTP-1.1, gRPC-Web/h2c),
// and search for the SMALLEST limit at which each still succeeds.
//
// Three header sets were measured, on this toolchain:
//
//	                                        values   bytes (h2)
//	bare protocol floor                         10          320
//	+ everything this codebase reads            25        2 048
//	+ Chrome, split cookies, CDN and mesh       61        6 144
//
// The middle row is Authorization, Idempotency-Key, traceparent, a
// maximum-length W3C tracestate and eight X-Forwarded-For field lines — one per
// hop config.MaxTrustedProxyHops permits, each counting separately because
// clientip.Scope reads Header.Values and several field lines mean the same as
// one comma-joined line. The bottom row adds what a browser sends unbidden
// (sec-ch-ua-*, sec-fetch-*, priority), cookies split one-per-field as HTTP/2
// clients do, and the header families Cloudflare and Envoy inject.
//
// # The choice
//
// The bottom row is the number to design against, because it is the only one
// that describes a request we must not refuse. Too LOW breaks legitimate
// traffic; too HIGH costs memory an attacker chooses. The asymmetry is not in
// our favour in either direction, so both values sit a stated multiple above the
// measured worst case rather than at a round number that happens to be nearby.
const (
	// MaxHeaderBytes is 32 KiB: 5.3x the measured 6 KiB worst case, and 32x
	// below Go's 1 MiB default. It is also exactly nginx's default header budget
	// (large_client_header_buffers 4 8k), which matters more than the multiple —
	// a request that survived the reverse proxy in front of us must not then be
	// refused by us, and matching the commonest proxy's ceiling is what
	// guarantees the two agree.
	MaxHeaderBytes = 32 << 10

	// MaxHeaderValueCount is 128: 2.1x the measured 61, and a 4x cut from Go 1.27's
	// DefaultMaxHeaderValueCount of 500.
	//
	// The count is a separate control from the byte budget because they bound
	// different costs. 32 KiB of headers is 32 KiB whether it arrives as one
	// field or as four thousand; the per-field cost is a map insertion, a slice
	// growth and an HPACK table update, and that is what this bounds.
	MaxHeaderValueCount = 128
)

// DefaultConfig returns sane transport defaults.
//
// WriteTimeout is deliberately absent: it would cap the lifetime of a streaming
// RPC, and this server carries server-streaming methods. Per-request deadlines
// come from the client's context instead.
func DefaultConfig(addr string) Config {
	return Config{
		Addr:        addr,
		ReadTimeout: 30 * time.Second,
		// ReadHeaderTimeout bounds the phase before any handler exists.
		//
		// Without it, Go falls back to ReadTimeout, so a slowloris connection
		// dribbling one header byte at a time held a connection for THIRTY
		// seconds. Five is derived from the byte budget above: 32 KiB of headers
		// needs about four round trips out of TCP slow start (IW10 carries ~14 KiB,
		// the next window ~29 KiB), so on a 700ms satellite or 2G RTT the honest
		// worst case is near 3s. Five leaves margin and still cuts the slowloris
		// hold to a sixth of what it was.
		//
		// HTTP/1.1 only. HTTP/2 delivers headers in HEADERS frames and Go's h2
		// server does not consult this field; there the equivalent protection is
		// MaxHeaderBytes, which h2 enforces as MAX_HEADER_LIST_SIZE.
		ReadHeaderTimeout:   5 * time.Second,
		IdleTimeout:         120 * time.Second,
		ShutdownTimeout:     20 * time.Second,
		MaxHeaderBytes:      MaxHeaderBytes,
		MaxHeaderValueCount: MaxHeaderValueCount,
	}
}

// Server owns the listener lifecycle.
type Server struct {
	cfg  Config
	http *http.Server
	log  *slog.Logger
}

// New builds an HTTP server that speaks HTTP/1.1 and HTTP/2, with and without
// TLS, so a single listener carries every protocol Connect supports.
func New(cfg Config, handler http.Handler, log *slog.Logger) *Server {
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	// Cleartext HTTP/2: what gRPC clients need when there is no TLS.
	protocols.SetUnencryptedHTTP2(true)

	return &Server{
		cfg: cfg,
		log: log,
		http: &http.Server{
			Addr:              cfg.Addr,
			Handler:           handler,
			Protocols:         &protocols,
			ReadTimeout:       cfg.ReadTimeout,
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
			WriteTimeout:      cfg.WriteTimeout,
			IdleTimeout:       cfg.IdleTimeout,
			// Zero means Go's default on both of these, and Go's defaults are
			// 1 MiB and 500. Passing them through from Config rather than
			// hard-coding them here is what lets the measurement test build a
			// server at a deliberately low limit and find the floor.
			MaxHeaderBytes:      cfg.MaxHeaderBytes,
			MaxHeaderValueCount: cfg.MaxHeaderValueCount,
		},
	}
}

// Run serves until ctx is cancelled, then drains in-flight requests.
//
// Serving never returns an error for a dependency being unavailable — the
// process stays up regardless of what is unreachable (ADR-010).
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.log.Info("listening", "addr", s.cfg.Addr, "protocols", "grpc,grpc-web,http/json")
		if err := s.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		s.log.Info("shutting down", "grace", s.cfg.ShutdownTimeout)
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.ShutdownTimeout)
		defer cancel()
		if err := s.http.Shutdown(shutdownCtx); err != nil {
			// Drain failed; the listener is closed either way.
			return err
		}
		return nil
	}
}
