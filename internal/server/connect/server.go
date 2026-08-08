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
	Addr            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

// DefaultConfig returns sane transport defaults.
//
// WriteTimeout is deliberately absent: it would cap the lifetime of a streaming
// RPC, and this server carries server-streaming methods. Per-request deadlines
// come from the client's context instead.
func DefaultConfig(addr string) Config {
	return Config{
		Addr:            addr,
		ReadTimeout:     30 * time.Second,
		IdleTimeout:     120 * time.Second,
		ShutdownTimeout: 20 * time.Second,
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
			Addr:         cfg.Addr,
			Handler:      handler,
			Protocols:    &protocols,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			IdleTimeout:  cfg.IdleTimeout,
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
