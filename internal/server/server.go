package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"shushtls/internal/api"
	"shushtls/internal/auth"
	"shushtls/internal/certengine"
	"shushtls/internal/ui"
)

// Server is the main ShushTLS application server. It always starts an HTTP
// listener. When the certificate engine reaches Ready state (either at
// startup or after initialization), it also starts HTTPS and switches HTTP
// to redirect mode. No restart required.
type Server struct {
	config    Config
	engine    *certengine.Engine
	authStore *auth.Store
	logger    *slog.Logger
	readyCh   chan struct{} // closed when engine transitions to Ready
	readyOnce sync.Once
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

	authStore, err := auth.NewStore(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("initialize auth store: %w", err)
	}

	return &Server{
		config:    cfg,
		engine:    engine,
		authStore: authStore,
		logger:    logger,
		readyCh:   make(chan struct{}),
	}, nil
}

// Engine returns the underlying certificate engine, primarily for use
// by API handlers.
func (s *Server) Engine() *certengine.Engine {
	return s.engine
}

// notifyReady signals that the engine has reached Ready state. Safe to
// call multiple times — only the first call has any effect.
func (s *Server) notifyReady() {
	s.readyOnce.Do(func() {
		close(s.readyCh)
	})
}

// Run starts the server and blocks until shutdown. HTTP always starts
// immediately. If the engine is already Ready, HTTPS starts too and HTTP
// redirects. If not, HTTP serves the setup UI until initialization
// completes, then HTTPS activates automatically.
//
// The server shuts down gracefully on SIGINT or SIGTERM.
func (s *Server) Run(ctx context.Context) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	state := s.engine.State()
	s.logger.Info("ShushTLS starting",
		"state", state.String(),
		"stateDir", s.config.StateDir,
	)

	mux, err := s.buildMux()
	if err != nil {
		return err
	}

	// HTTP always runs. In setup mode it serves the full app; after
	// HTTPS activates it switches to redirecting.
	httpHandler := &switchableHandler{handler: mux}
	httpSrv := &http.Server{
		Addr:              s.config.HTTPAddr,
		Handler:           httpHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 2)

	go func() {
		s.logger.Info("serving HTTP", "addr", s.config.HTTPAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("HTTP server: %w", err)
		}
	}()

	var httpsSrv *http.Server

	if state == certengine.Ready {
		// Already initialized — start HTTPS immediately, HTTP redirects.
		httpHandler.Switch(s.httpsRedirectHandler())
		httpsSrv, err = s.startHTTPS(mux, errCh)
		if err != nil {
			httpSrv.Close()
			return err
		}
	} else {
		s.logger.Info("setup mode — initialize via the web UI or POST /api/initialize",
			"httpAddr", s.config.HTTPAddr,
		)

		// Wait for initialization or early exit.
		select {
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return s.shutdownAll(httpSrv, nil)
		case <-s.readyCh:
			s.logger.Info("initialization complete, activating HTTPS")
			httpsSrv, err = s.startHTTPS(mux, errCh)
			if err != nil {
				s.logger.Error("failed to start HTTPS, continuing HTTP only", "error", err)
			} else {
				httpHandler.Switch(s.httpsRedirectHandler())
				s.logger.Info("HTTP now redirects to HTTPS", "httpsAddr", s.config.HTTPSAddr)
			}
		}
	}

	// Wait for shutdown signal or server error.
	select {
	case err := <-errCh:
		s.shutdownAll(httpSrv, httpsSrv)
		return err
	case <-ctx.Done():
		return s.shutdownAll(httpSrv, httpsSrv)
	}
}

// startHTTPS creates and starts the HTTPS server in the background.
// Errors from the listener are sent to errCh.
func (s *Server) startHTTPS(handler http.Handler, errCh chan<- error) (*http.Server, error) {
	certPath, keyPath := s.engine.Store().CertPaths(s.engine.ServiceHost())

	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}

	srv := &http.Server{
		Addr:    s.config.HTTPSAddr,
		Handler: handler,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		},
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		s.logger.Info("serving HTTPS", "addr", s.config.HTTPSAddr, "serviceHost", s.engine.ServiceHost())
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("HTTPS server: %w", err)
		}
	}()

	return srv, nil
}

// httpsRedirectHandler returns a handler that 301-redirects all requests
// to the HTTPS equivalent, rewriting the port if needed.
func (s *Server) httpsRedirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		// Strip the HTTP port.
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		// Add the HTTPS port if non-standard.
		if _, port, _ := net.SplitHostPort(s.config.HTTPSAddr); port != "" && port != "443" {
			host = net.JoinHostPort(host, port)
		}
		target := "https://" + host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusFound)
	})
}

// buildMux constructs the HTTP router with API and UI routes.
func (s *Server) buildMux() (*http.ServeMux, error) {
	mux := http.NewServeMux()

	// Register API endpoints.
	apiHandler := api.NewHandler(s.engine, s.config.ServiceHosts, s.logger, s.notifyReady, s.authStore)
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

// shutdownAll gracefully shuts down both HTTP and HTTPS servers.
func (s *Server) shutdownAll(httpSrv, httpsSrv *http.Server) error {
	s.logger.Info("shutting down gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var firstErr error
	if httpSrv != nil {
		if err := httpSrv.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("HTTP shutdown: %w", err)
		}
	}
	if httpsSrv != nil {
		if err := httpsSrv.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("HTTPS shutdown: %w", err)
		}
	}
	s.logger.Info("shutdown complete")
	return firstErr
}

// switchableHandler wraps an http.Handler and allows it to be atomically
// replaced at runtime. Used to switch HTTP from serving the full app
// to redirecting after HTTPS activates.
type switchableHandler struct {
	mu      sync.RWMutex
	handler http.Handler
}

func (sh *switchableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sh.mu.RLock()
	h := sh.handler
	sh.mu.RUnlock()
	h.ServeHTTP(w, r)
}

// Switch atomically replaces the underlying handler.
func (sh *switchableHandler) Switch(h http.Handler) {
	sh.mu.Lock()
	sh.handler = h
	sh.mu.Unlock()
}
