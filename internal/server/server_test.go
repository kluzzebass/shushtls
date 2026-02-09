package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

// TestServer_UninitializedServesHTTP verifies that a fresh server (no CA)
// starts in HTTP mode.
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
// in HTTPS mode with a valid certificate.
func TestServer_ReadyServesHTTPS(t *testing.T) {
	dir := t.TempDir()
	httpsAddr := pickPort(t)

	serviceHosts := []string{"localhost"}

	// Initialize the cert engine manually to get to Ready state.
	engine, err := certengine.New(dir)
	if err != nil {
		t.Fatalf("certengine.New: %v", err)
	}
	if _, err := engine.Initialize(serviceHosts); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	cfg := Config{
		StateDir:     dir,
		HTTPAddr:     pickPort(t),
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
	// We must set ServerName to "localhost" so the TLS verifier checks
	// against the cert's SAN rather than the raw IP address.
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

	resp, err := tlsClient.Get("https://" + httpsAddr + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
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
	ca, err := certengine.GenerateCA()
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

// TestServer_HTTPSNotServedWithoutCerts verifies that HTTPS is never
// attempted when there are no certificates (the Uninitialized state
// always results in HTTP).
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

// --- Helpers ---

func waitForHTTP(t *testing.T, url string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		resp, err := http.Get(url)
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
