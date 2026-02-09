package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"shushtls/internal/api"
	"shushtls/internal/certengine"
	"shushtls/internal/ui"
)

// Server is the main ShushTLS application server. It inspects the
// certificate engine state on startup and serves either HTTP or HTTPS
// accordingly. It never serves both simultaneously.
type Server struct {
	config Config
	engine *certengine.Engine
	logger *slog.Logger
}

// New creates a new Server with the given configuration.
func New(cfg Config) (*Server, error) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	engine, err := certengine.New(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("initialize certificate engine: %w", err)
	}

	// After loading from disk, re-associate the service host so
	// Engine.ServiceCert() and Engine.State() work correctly.
	if len(cfg.ServiceHosts) > 0 {
		engine.SetServiceHost(cfg.ServiceHosts[0])
	}

	return &Server{
		config: cfg,
		engine: engine,
		logger: logger,
	}, nil
}

// Engine returns the underlying certificate engine, primarily for use
// by API handlers.
func (s *Server) Engine() *certengine.Engine {
	return s.engine
}

// Run starts the server in the appropriate mode based on the certificate
// engine state, and blocks until shutdown.
//
// - Uninitialized or Initialized: HTTP-only mode (setup/trust installation)
// - Ready: HTTPS-only mode (normal operation)
//
// The server shuts down gracefully on SIGINT or SIGTERM.
func (s *Server) Run(ctx context.Context) error {
	state := s.engine.State()
	s.logger.Info("ShushTLS starting",
		"state", state.String(),
		"stateDir", s.config.StateDir,
	)

	switch state {
	case certengine.Uninitialized, certengine.Initialized:
		return s.runHTTP(ctx)
	case certengine.Ready:
		return s.runHTTPS(ctx)
	default:
		return fmt.Errorf("unexpected engine state: %s", state)
	}
}

// runHTTP starts an HTTP-only server for the setup/initialization flow.
// This is used before the root CA exists or before the service cert is ready.
func (s *Server) runHTTP(ctx context.Context) error {
	mux, err := s.buildMux()
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              s.config.HTTPAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	s.logger.Info("serving HTTP (setup mode)",
		"addr", s.config.HTTPAddr,
		"hint", "initialize via the web UI or POST /api/initialize",
	)

	return s.serve(ctx, srv)
}

// runHTTPS starts an HTTPS-only server using the ShushTLS service certificate.
// This is the normal operating mode after initialization and trust installation.
func (s *Server) runHTTPS(ctx context.Context) error {
	mux, err := s.buildMux()
	if err != nil {
		return err
	}

	certPath, keyPath := s.engine.Store().CertPaths(s.engine.ServiceHost())

	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	srv := &http.Server{
		Addr:              s.config.HTTPSAddr,
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}

	s.logger.Info("serving HTTPS (normal mode)",
		"addr", s.config.HTTPSAddr,
		"serviceHost", s.engine.ServiceHost(),
	)

	// TLSConfig is already set, so pass empty cert/key paths.
	return s.serveTLS(ctx, srv)
}

// buildMux constructs the HTTP router with API and UI routes.
func (s *Server) buildMux() (*http.ServeMux, error) {
	mux := http.NewServeMux()

	// Register API endpoints.
	apiHandler := api.NewHandler(s.engine, s.config.ServiceHosts, s.logger)
	apiHandler.Register(mux)

	// Catch-all for unmatched /api/ paths — return proper JSON errors
	// instead of letting them fall through to the UI handler.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, `{"error":"unknown API endpoint: %s %s"}`+"\n", r.Method, r.URL.Path)
	})

	// Register web UI routes.
	uiHandler, err := ui.NewHandler(s.engine, s.logger)
	if err != nil {
		return nil, fmt.Errorf("initialize UI: %w", err)
	}
	uiHandler.Register(mux)

	return mux, nil
}

// serve runs an HTTP server with graceful shutdown on context cancellation
// or OS signal.
func (s *Server) serve(ctx context.Context, srv *http.Server) error {
	return s.listenAndShutdown(ctx, srv, func() error {
		return srv.ListenAndServe()
	})
}

// serveTLS runs an HTTPS server with graceful shutdown.
func (s *Server) serveTLS(ctx context.Context, srv *http.Server) error {
	return s.listenAndShutdown(ctx, srv, func() error {
		// TLSConfig is pre-configured on the server, so pass empty strings.
		return srv.ListenAndServeTLS("", "")
	})
}

// listenAndShutdown is the common shutdown orchestration for both HTTP
// and HTTPS modes.
func (s *Server) listenAndShutdown(ctx context.Context, srv *http.Server, listenFn func() error) error {
	// Merge the parent context with OS signals for shutdown.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		if err := listenFn(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for shutdown signal or listen error.
	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("server error: %w", err)
		}
	case <-ctx.Done():
		s.logger.Info("shutting down gracefully...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown error: %w", err)
		}
		s.logger.Info("shutdown complete")
	}

	return nil
}
