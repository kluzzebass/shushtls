package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
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
	"shushtls/internal/version"
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
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	if err := validateStateDir(cfg.StateDir); err != nil {
		return nil, err
	}

	engine, err := certengine.New(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("initialize certificate engine: %w", err)
	}

	// If no persisted service host was loaded from disk, fall back to
	// the CLI config. This handles first-run and legacy state dirs.
	if engine.ServiceHost() == "" && len(cfg.ServiceHosts) > 0 {
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
	s.logStartup(state)

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
		s.logger.Info("HTTP listener started", "addr", s.config.HTTPAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("HTTP server: %w", err)
		}
	}()

	// When -no-tls is set (e.g. behind a reverse proxy), never start HTTPS;
	// HTTP serves the full app. Wait for shutdown.
	if s.config.NoTLS {
		select {
		case err := <-errCh:
			return err
		case <-ctx.Done():
			s.logger.Info("shutdown signal received")
			return s.shutdownAll(httpSrv, nil)
		}
	}

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
		s.logger.Info("shutdown signal received")
		return s.shutdownAll(httpSrv, httpsSrv)
	}
}

// startHTTPS creates and starts the HTTPS server in the background.
// Uses GetCertificate to dynamically serve the current service cert,
// so replacing the service cert takes effect without a restart.
// Errors from the listener are sent to errCh.
func (s *Server) startHTTPS(handler http.Handler, errCh chan<- error) (*http.Server, error) {
	// Verify we have a service cert before starting.
	if s.engine.ServiceCert() == nil {
		return nil, fmt.Errorf("no service certificate available")
	}

	srv := &http.Server{
		Addr:    s.config.HTTPSAddr,
		Handler: handler,
		TLSConfig: &tls.Config{
			GetCertificate: s.getCertificate,
			MinVersion:     tls.VersionTLS12,
		},
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		s.logger.Info("HTTPS listener started", "addr", s.config.HTTPSAddr)
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
		json.NewEncoder(w).Encode(struct {
			Error string `json:"error"`
		}{
			Error: fmt.Sprintf("unknown API endpoint: %s %s", r.Method, r.URL.Path),
		})
	})

	// Register web UI routes.
	uiHandler, err := ui.NewHandler(s.engine, s.authStore, s.logger, ui.AboutInfo{
		Version:   version.Version,
		RepoURL:   version.RepoURL,
		Author:    version.Author,
		Copyright: version.Copyright,
	})
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

// getCertificate is the tls.Config.GetCertificate callback. It returns
// the current service certificate from the engine on every TLS handshake,
// so replacing the service cert takes effect immediately.
func (s *Server) getCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	svc := s.engine.ServiceCert()
	if svc == nil {
		return nil, fmt.Errorf("no service certificate available")
	}
	return &tls.Certificate{
		Certificate: [][]byte{svc.Raw},
		PrivateKey:  svc.Key,
	}, nil
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

// --- Startup & lifecycle helpers ---

// validateStateDir checks that the state directory exists (or can be
// created) and is actually a directory.
func validateStateDir(dir string) error {
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		if mkErr := os.MkdirAll(dir, 0700); mkErr != nil {
			return fmt.Errorf("cannot create state directory %q: %w", dir, mkErr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot access state directory %q: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("state path %q exists but is not a directory", dir)
	}
	return nil
}

// logStartup emits structured startup info so operators and log pipelines
// get consistent, parseable records instead of free-form text.
func (s *Server) logStartup(state certengine.State) {
	httpURL := addrToURL(s.config.HTTPAddr, "http")

	attrs := []any{
		"state", state.String(),
		"state_dir", s.config.StateDir,
		"http_url", httpURL,
	}

	if s.config.NoTLS {
		attrs = append(attrs, "no_tls", true)
		s.logger.Info("ShushTLS started (HTTP only)", attrs...)
		return
	}

	switch state {
	case certengine.Ready:
		attrs = append(attrs, "https_url", s.serviceHTTPSURL())
		if svc := s.engine.ServiceCert(); svc != nil {
			attrs = append(attrs, "service_cert", svc.PrimarySAN(), "service_cert_expires", svc.Cert.NotAfter.Format("2006-01-02"))
		}
		if ca := s.engine.CA(); ca != nil {
			attrs = append(attrs, "root_ca_expires", ca.Cert.NotAfter.Format("2006-01-02"))
		}
		s.logger.Info("ShushTLS started", attrs...)
	default:
		attrs = append(attrs, "next", "open http_url in browser to initialize")
		s.logger.Info("ShushTLS started (setup mode)", attrs...)
	}
}

// serviceHTTPSURL constructs the HTTPS URL using the service hostname
// and HTTPS port.
func (s *Server) serviceHTTPSURL() string {
	host := s.engine.ServiceHost()
	_, port, _ := net.SplitHostPort(s.config.HTTPSAddr)
	if port == "" || port == "443" {
		return "https://" + host
	}
	return "https://" + net.JoinHostPort(host, port)
}

// addrToURL converts a listen address like ":8080" to a human-readable
// URL like "http://localhost:8080".
func addrToURL(addr, scheme string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return scheme + "://" + addr
	}
	if host == "" || host == "0.0.0.0" {
		host = "localhost"
	}
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		return scheme + "://" + host
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}
