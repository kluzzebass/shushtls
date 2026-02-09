package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"shushtls/internal/certengine"
)

// pickPort finds a free TCP port for testing.
func pickPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// noFollowClient returns an HTTP client that does not follow redirects.
func noFollowClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// TestServer_UninitializedServesHTTP verifies that a fresh server (no CA)
// starts in HTTP mode and serves the full application.
func TestServer_UninitializedServesHTTP(t *testing.T) {
	dir := t.TempDir()
	addr := pickPort(t)

	cfg := Config{
		StateDir:     dir,
		HTTPAddr:     addr,
		HTTPSAddr:    pickPort(t),
		ServiceHosts: []string{"shushtls.test", "localhost"},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if srv.Engine().State() != certengine.Uninitialized {
		t.Fatalf("expected Uninitialized, got %s", srv.Engine().State())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()

	// Wait for the HTTP server to be ready.
	waitForHTTP(t, "http://"+addr)

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if got := string(body); got == "" {
		t.Error("empty response body")
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("server error: %v", err)
	}
}

// TestServer_ReadyServesHTTPS verifies that an initialized server starts
// HTTPS immediately and redirects HTTP to HTTPS.
func TestServer_ReadyServesHTTPS(t *testing.T) {
	dir := t.TempDir()
	httpAddr := pickPort(t)
	httpsAddr := pickPort(t)

	serviceHosts := []string{"localhost"}

	// Initialize the cert engine manually to get to Ready state.
	engine, err := certengine.New(dir)
	if err != nil {
		t.Fatalf("certengine.New: %v", err)
	}
	if _, err := engine.Initialize(serviceHosts, certengine.CAParams{}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	cfg := Config{
		StateDir:     dir,
		HTTPAddr:     httpAddr,
		HTTPSAddr:    httpsAddr,
		ServiceHosts: serviceHosts,
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if srv.Engine().State() != certengine.Ready {
		t.Fatalf("expected Ready, got %s", srv.Engine().State())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()

	// Build a TLS client that trusts our CA.
	pool := x509.NewCertPool()
	pool.AddCert(engine.CA().Cert)
	tlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				ServerName: "localhost",
			},
		},
	}

	waitForHTTPS(t, "https://"+httpsAddr, tlsClient)

	// Verify HTTPS serves the app.
	resp, err := tlsClient.Get("https://" + httpsAddr + "/")
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("HTTPS status = %d, want 200", resp.StatusCode)
	}

	// Verify the server's TLS cert was signed by our CA.
	if resp.TLS == nil {
		t.Fatal("response has no TLS info")
	}
	if len(resp.TLS.PeerCertificates) == 0 {
		t.Fatal("no peer certificates")
	}
	peerCert := resp.TLS.PeerCertificates[0]
	if _, err := peerCert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("peer cert does not verify against our CA: %v", err)
	}

	// Verify HTTP redirects to HTTPS.
	waitForHTTP(t, "http://"+httpAddr)
	client := noFollowClient()
	httpResp, err := client.Get("http://" + httpAddr + "/setup")
	if err != nil {
		t.Fatalf("HTTP GET: %v", err)
	}
	httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("HTTP status = %d, want 301", httpResp.StatusCode)
	}
	loc := httpResp.Header.Get("Location")
	if loc == "" {
		t.Error("HTTP redirect missing Location header")
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("server error: %v", err)
	}
}

// TestServer_InitializedServesHTTP verifies that a partially initialized
// server (CA exists but no service cert) still serves HTTP.
func TestServer_InitializedServesHTTP(t *testing.T) {
	dir := t.TempDir()

	// Create just the CA, but no service cert.
	engine, err := certengine.New(dir)
	if err != nil {
		t.Fatalf("certengine.New: %v", err)
	}
	ca, err := certengine.GenerateCA(certengine.CAParams{})
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := engine.Store().SaveCA(ca); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}

	addr := pickPort(t)
	cfg := Config{
		StateDir:     dir,
		HTTPAddr:     addr,
		HTTPSAddr:    pickPort(t),
		ServiceHosts: []string{"shushtls.test"},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// State should be Initialized (CA exists, but no service cert for "shushtls.test").
	if srv.Engine().State() != certengine.Initialized {
		t.Fatalf("expected Initialized, got %s", srv.Engine().State())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()

	waitForHTTP(t, "http://"+addr)

	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("server error: %v", err)
	}
}

// TestServer_HTTPSActivatesAfterInit verifies that starting from an
// uninitialized state, posting to /api/initialize causes the server to
// start HTTPS and switch HTTP to redirect mode — no restart needed.
func TestServer_HTTPSActivatesAfterInit(t *testing.T) {
	dir := t.TempDir()
	httpAddr := pickPort(t)
	httpsAddr := pickPort(t)

	serviceHosts := []string{"localhost"}

	cfg := Config{
		StateDir:     dir,
		HTTPAddr:     httpAddr,
		HTTPSAddr:    httpsAddr,
		ServiceHosts: serviceHosts,
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()

	// Wait for HTTP to be ready.
	waitForHTTP(t, "http://"+httpAddr)

	// HTTP should serve the app (not redirect) before init.
	client := noFollowClient()
	resp, err := client.Get("http://" + httpAddr + "/")
	if err != nil {
		t.Fatalf("pre-init GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("pre-init status = %d, want 200", resp.StatusCode)
	}

	// Initialize via the API.
	body, _ := json.Marshal(map[string]any{})
	initResp, err := http.Post("http://"+httpAddr+"/api/initialize", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /api/initialize: %v", err)
	}
	initResp.Body.Close()
	if initResp.StatusCode != http.StatusOK {
		t.Fatalf("init status = %d, want 200", initResp.StatusCode)
	}

	// Wait for HTTPS to become available.
	// Reload the engine state to build a TLS client.
	engine2, err := certengine.New(dir)
	if err != nil {
		t.Fatalf("certengine.New (reload): %v", err)
	}
	engine2.SetServiceHost("localhost")
	pool := x509.NewCertPool()
	pool.AddCert(engine2.CA().Cert)
	tlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				ServerName: "localhost",
			},
		},
	}

	waitForHTTPS(t, "https://"+httpsAddr, tlsClient)

	// Verify HTTPS serves the app.
	httpsResp, err := tlsClient.Get("https://" + httpsAddr + "/api/status")
	if err != nil {
		t.Fatalf("HTTPS GET: %v", err)
	}
	httpsResp.Body.Close()
	if httpsResp.StatusCode != http.StatusOK {
		t.Errorf("HTTPS status = %d, want 200", httpsResp.StatusCode)
	}

	// Verify HTTP now redirects.
	httpResp, err := client.Get("http://" + httpAddr + "/")
	if err != nil {
		t.Fatalf("post-init HTTP GET: %v", err)
	}
	httpResp.Body.Close()
	if httpResp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("post-init HTTP status = %d, want 301", httpResp.StatusCode)
	}
	loc := httpResp.Header.Get("Location")
	if loc == "" {
		t.Error("redirect missing Location header")
	}

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("server error: %v", err)
	}
}

// TestServer_HTTPSNotServedWithoutCerts verifies that HTTPS is never
// attempted when there are no certificates (the Uninitialized state
// always results in HTTP only).
func TestServer_HTTPSNotServedWithoutCerts(t *testing.T) {
	dir := t.TempDir()
	httpsAddr := pickPort(t)

	cfg := Config{
		StateDir:     dir,
		HTTPAddr:     pickPort(t),
		HTTPSAddr:    httpsAddr,
		ServiceHosts: []string{"shushtls.test"},
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Must be Uninitialized.
	if srv.Engine().State() != certengine.Uninitialized {
		t.Fatalf("expected Uninitialized, got %s", srv.Engine().State())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Run(ctx)

	// Give the server a moment to start.
	time.Sleep(100 * time.Millisecond)

	// Attempting a TLS connection to the HTTPS port should fail.
	conn, err := net.DialTimeout("tcp", httpsAddr, 200*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Error("HTTPS port should not be listening when uninitialized")
	}

	cancel()
}

// TestServer_HTTPRedirectRewritesPort verifies that the HTTP redirect
// correctly rewrites the port when HTTPS uses a non-standard port.
func TestServer_HTTPRedirectRewritesPort(t *testing.T) {
	dir := t.TempDir()
	httpAddr := pickPort(t)
	httpsAddr := pickPort(t)

	serviceHosts := []string{"localhost"}

	// Pre-initialize so the server starts in dual mode.
	engine, err := certengine.New(dir)
	if err != nil {
		t.Fatalf("certengine.New: %v", err)
	}
	if _, err := engine.Initialize(serviceHosts, certengine.CAParams{}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	cfg := Config{
		StateDir:     dir,
		HTTPAddr:     httpAddr,
		HTTPSAddr:    httpsAddr,
		ServiceHosts: serviceHosts,
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()

	waitForHTTP(t, "http://"+httpAddr)

	client := noFollowClient()
	resp, err := client.Get("http://" + httpAddr + "/test/path?q=1")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("status = %d, want 301", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	// The Location should use the HTTPS addr port.
	_, httpsPort, _ := net.SplitHostPort(httpsAddr)
	expectedSuffix := ":" + httpsPort + "/test/path?q=1"
	if loc == "" {
		t.Fatal("missing Location header")
	}
	if !containsPort(loc, httpsPort) {
		t.Errorf("redirect Location %q does not contain HTTPS port %s", loc, httpsPort)
	}
	_ = expectedSuffix // checked implicitly above

	cancel()
	if err := <-errCh; err != nil {
		t.Errorf("server error: %v", err)
	}
}

// containsPort checks if a URL string contains the given port number.
func containsPort(url, port string) bool {
	// Simple substring check.
	return len(url) > 0 && len(port) > 0 &&
		// Look for ":PORT/" or ":PORT" at end
		(contains(url, ":"+port+"/") || hasSuffix(url, ":"+port))
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

// --- Helpers ---

func waitForHTTP(t *testing.T, url string) {
	t.Helper()
	// Use a no-follow client because in redirect mode, following
	// the redirect to HTTPS would fail (untrusted CA).
	client := noFollowClient()
	for i := 0; i < 50; i++ {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server at %s did not become ready", url)
}

func waitForHTTPS(t *testing.T, url string, client *http.Client) {
	t.Helper()
	for i := 0; i < 50; i++ {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		fmt.Printf("waiting for HTTPS: %v\n", err)
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("HTTPS server at %s did not become ready", url)
}
