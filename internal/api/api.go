// Package api implements the ShushTLS HTTP API. All endpoints are JSON
// where applicable, idempotent where reasonable, and scriptable via curl.
// No authentication — ShushTLS uses a LAN trust model.
package api

import (
	"archive/tar"
	"archive/zip"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"shushtls/internal/auth"
	"shushtls/internal/certengine"
	"shushtls/internal/request"
)

// maxRequestBody is the maximum allowed request body size (1 MB).
// Prevents memory exhaustion from oversized payloads.
const maxRequestBody = 1 << 20

// limitBody wraps a handler to enforce a request body size limit.
func limitBody(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		next(w, r)
	}
}

// Handler holds the API dependencies and registers routes on a mux.
type Handler struct {
	engine       *certengine.Engine
	serviceHosts []string
	logger       *slog.Logger
	onReady      func()      // called when initialization reaches Ready state
	authStore    *auth.Store // optional; nil disables auth entirely
	trustProxy   bool        // when true, respect X-Forwarded-* headers
}

// NewHandler creates an API handler backed by the given engine.
// The onReady callback is invoked when initialization completes and the
// engine reaches Ready state. It may be nil.
// The authStore enables optional Basic Auth; pass nil to disable.
// trustProxy controls whether X-Forwarded-* headers are respected (enable
// only when running behind a reverse proxy, e.g. with -no-tls).
func NewHandler(engine *certengine.Engine, serviceHosts []string, logger *slog.Logger, onReady func(), authStore *auth.Store, trustProxy bool) *Handler {
	return &Handler{
		engine:       engine,
		serviceHosts: serviceHosts,
		logger:       logger,
		onReady:      onReady,
		authStore:    authStore,
		trustProxy:   trustProxy,
	}
}

// Register adds all API routes to the given mux.
//
// Protected endpoints (when auth is enabled):
//   - POST /api/initialize
//   - POST /api/certificates
//   - POST /api/auth
//   - GET  /api/status
//   - GET  /api/certificates/{san}?type=zip (cert+key bundle; auth when enabled)
//   - GET  /api/leaf-subject (default O, OU, C, L, ST for leaf certs)
//   - PUT  /api/leaf-subject (update default subject; body: LeafSubjectParams JSON)
//
// Unprotected endpoints (always open):
//   - GET  /api/ca/root.pem
//   - GET  /api/certificates (listing)
//   - GET  /api/certificates/{san} or ?type=zip (cert+key zip bundle; auth when enabled)
//   - GET  /api/ca/install/*
func (h *Handler) Register(mux *http.ServeMux) {
	h.RegisterAPI(mux)
	h.registerLegacy(mux)
}

func (h *Handler) registerLegacy(mux *http.ServeMux) {
	// Binary and script routes — migrated to Huma in shushtls-21bw.
	mux.HandleFunc("GET /api/ca/root.pem", h.handleCACert)
	mux.HandleFunc("GET /api/certificates/", h.handleGetCert) // auth checked inside for zip bundle
	mux.HandleFunc("GET /api/ca/install/macos", h.handleInstallMacOS)
	mux.HandleFunc("GET /api/ca/install/linux", h.handleInstallLinux)
	mux.HandleFunc("GET /api/ca/install/windows", h.handleInstallWindows)

	// Wrong-method handlers for Huma routes (Huma only registers allowed methods).
	mux.HandleFunc("/api/initialize", methodNotAllowed("POST"))
	mux.HandleFunc("/api/service-cert", methodNotAllowed("POST"))
	mux.HandleFunc("/api/status", methodNotAllowed("GET"))
	mux.HandleFunc("/api/auth", methodNotAllowed("POST"))
	mux.HandleFunc("/api/leaf-subject", methodNotAllowed("GET, PUT"))

	// Method-not-allowed handlers for legacy routes still on the mux.
	mux.HandleFunc("/api/ca/root.pem", methodNotAllowed("GET"))
}

// requireAuth wraps a handler with Basic Auth checking. If the auth store
// is nil or auth is disabled, the handler is called directly.
func (h *Handler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.authStore == nil || !h.authStore.IsEnabled() {
			next(w, r)
			return
		}

		username, password, ok := r.BasicAuth()
		if !ok || !h.authStore.Verify(username, password) {
			h.logger.Warn("authentication failed", "remote", r.RemoteAddr, "path", r.URL.Path)
			w.Header().Set("WWW-Authenticate", `Basic realm="ShushTLS"`)
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{
				Error: "authentication required",
			})
			return
		}

		next(w, r)
	}
}

// methodNotAllowed returns a handler that responds with 405 and an Allow header.
func methodNotAllowed(allowed string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", allowed)
		writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{
			Error: fmt.Sprintf("method %s not allowed, use %s", r.Method, allowed),
		})
	}
}

// internalError logs the real error and responds with a sanitized message.
// Used for 500 errors to avoid leaking internal details to the client.
func (h *Handler) internalError(w http.ResponseWriter, msg string, err error) {
	h.logger.Error(msg, "error", err)
	writeJSON(w, http.StatusInternalServerError, ErrorResponse{
		Error: msg + " — check server logs for details",
	})
}

// --- Response types ---

// StatusResponse is the JSON body for GET /api/status.
type StatusResponse struct {
	State       string         `json:"state"`
	ServingMode string         `json:"serving_mode"`
	RootCA      *CACertInfo    `json:"root_ca,omitempty"`
	Certs       []LeafCertInfo `json:"certificates,omitempty"`
}

// CACertInfo describes the root CA in API responses.
type CACertInfo struct {
	Fingerprint string `json:"fingerprint"` // SHA-256
	Subject     string `json:"subject"`
	NotBefore   string `json:"not_before"`
	NotAfter    string `json:"not_after"`
}

// LeafCertInfo describes a leaf certificate in API responses.
type LeafCertInfo struct {
	PrimarySAN string   `json:"primary_san"`
	DNSNames   []string `json:"dns_names"`
	NotBefore  string   `json:"not_before"`
	NotAfter   string   `json:"not_after"`
	IsService  bool     `json:"is_service"`
}

// InitializeResponse is the JSON body for POST /api/initialize.
type InitializeResponse struct {
	State   string `json:"state"`
	Message string `json:"message"`
}

// IssueCertRequest is the JSON body for POST /api/certificates.
type IssueCertRequest struct {
	DNSNames []string                   `json:"dns_names"`
	Subject  *certengine.LeafSubjectParams `json:"subject,omitempty"` // optional override for this cert
}

// IssueCertResponse is the JSON body for POST /api/certificates.
type IssueCertResponse struct {
	Cert    LeafCertInfo `json:"certificate"`
	Message string       `json:"message"`
}

// AuthRequest is the JSON body for POST /api/auth.
type AuthRequest struct {
	Enabled  *bool  `json:"enabled" required:"false"` // pointer to distinguish false from omitted
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// AuthResponse is the JSON body for POST /api/auth.
type AuthResponse struct {
	Enabled bool   `json:"enabled"`
	Message string `json:"message"`
}

// SetServiceCertRequest is the JSON body for POST /api/service-cert.
type SetServiceCertRequest struct {
	PrimarySAN string `json:"primary_san"`
}

// SetServiceCertResponse is the JSON body for POST /api/service-cert.
type SetServiceCertResponse struct {
	Cert    LeafCertInfo `json:"certificate"`
	Message string       `json:"message"`
}

// ErrorResponse is the JSON body for error responses.
type ErrorResponse struct {
	Error string `json:"error"`
}

// --- Handlers ---

// GET /api/ca/root.pem
func (h *Handler) handleCACert(w http.ResponseWriter, r *http.Request) {
	ca := h.engine.CA()
	if ca == nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{
			Error: "root CA does not exist yet — run POST /api/initialize first",
		})
		return
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Raw,
	})

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=\"shushtls-root-ca.pem\"")
	w.Write(pemBlock)
}

// GET /api/certificates/{san}
// Downloads the certificate and private key as a bundle for the given primary SAN.
// Query: type=zip, type=tar (default tar) — cert and key are always returned together to guarantee a matching pair.
// Use type=tar for systems without unzip (e.g. Synology DSM). Separate cert/key fetches are not supported.
// The {san} is the URL path after /api/certificates/.
func (h *Handler) handleGetCert(w http.ResponseWriter, r *http.Request) {
	// Extract the SAN from the URL path.
	san := strings.TrimPrefix(r.URL.Path, "/api/certificates/")
	if san == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: "certificate SAN is required in the URL path",
		})
		return
	}

	if err := certengine.ValidateSAN(san); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: fmt.Sprintf("invalid SAN: %v", err),
		})
		return
	}

	which := r.URL.Query().Get("type")
	if which == "" {
		which = "tar"
	}
	if which != "zip" && which != "tar" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: "use type=zip or type=tar to download cert+key bundle (separate cert/key downloads are not supported)",
		})
		return
	}

	leaf := h.engine.GetCert(san)
	if leaf == nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{
			Error: fmt.Sprintf("no certificate found for %q", san),
		})
		return
	}

	// Auth check for bundle download (contains private key).
	if h.authStore != nil && h.authStore.IsEnabled() {
		username, password, ok := r.BasicAuth()
		if !ok || !h.authStore.Verify(username, password) {
			h.logger.Warn("authentication failed", "remote", r.RemoteAddr, "path", r.URL.Path)
			w.Header().Set("WWW-Authenticate", `Basic realm="ShushTLS"`)
			writeJSON(w, http.StatusUnauthorized, ErrorResponse{
				Error: "authentication required for certificate bundle download",
			})
			return
		}
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	der, err := x509.MarshalECPrivateKey(leaf.Key)
	if err != nil {
		h.internalError(w, "failed to export private key for bundle", err)
		return
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	base := certengine.SanitizeSAN(san)

	switch which {
	case "tar":
		w.Header().Set("Content-Type", "application/x-tar")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", base+".tar"))
		tw := tar.NewWriter(w)
		for _, entry := range []struct {
			name string
			data []byte
		}{
			{base + ".cert.pem", certPEM},
			{base + ".key.pem", keyPEM},
		} {
			if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0644, Size: int64(len(entry.data))}); err != nil {
				tw.Close()
				h.internalError(w, "failed to write tar header", err)
				return
			}
			if _, err := tw.Write(entry.data); err != nil {
				tw.Close()
				h.internalError(w, "failed to write tar entry", err)
				return
			}
		}
		if err := tw.Close(); err != nil {
			h.internalError(w, "failed to close tar", err)
			return
		}
	case "zip":
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", base+".zip"))
		zw := zip.NewWriter(w)
		for _, entry := range []struct {
			name string
			data []byte
		}{
			{base + ".cert.pem", certPEM},
			{base + ".key.pem", keyPEM},
		} {
			fw, err := zw.Create(entry.name)
			if err != nil {
				zw.Close()
				h.internalError(w, "failed to create zip entry", err)
				return
			}
			if _, err := fw.Write(entry.data); err != nil {
				zw.Close()
				h.internalError(w, "failed to write zip entry", err)
				return
			}
		}
		if err := zw.Close(); err != nil {
			h.internalError(w, "failed to close zip", err)
			return
		}
	}
}

// --- Root CA install helpers ---

// InstallPlatform describes an available install script endpoint.
type InstallPlatform struct {
	Platform string `json:"platform"`
	Endpoint string `json:"endpoint"`
	Example  string `json:"example"`
}

// GET /api/ca/install/macos — shell script for macOS trust store.
func (h *Handler) handleInstallMacOS(w http.ResponseWriter, r *http.Request) {
	if h.engine.CA() == nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{
			Error: "root CA does not exist yet — run POST /api/initialize first",
		})
		return
	}

	base := h.baseURL(r)
	script := fmt.Sprintf(`#!/bin/bash
# ShushTLS Root CA Installer — macOS
# Usage: curl -kfsSL %[1]s/api/ca/install/macos | bash
set -euo pipefail

TMPFILE=$(mktemp /tmp/shushtls-root-ca.XXXXXX)
trap 'rm -f "$TMPFILE"' EXIT

echo "Downloading ShushTLS root CA..."
# -k is needed because the CA isn't trusted yet — that's what we're fixing.
curl -kfsSL -o "$TMPFILE" %[1]s/api/ca/root.pem

echo "Installing into macOS system trust store..."
echo "(You may be prompted for your password.)"
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$TMPFILE"

echo "Done! ShushTLS root CA is now trusted on this Mac."
`, base)

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Write([]byte(script))
}

// GET /api/ca/install/linux — shell script for Linux trust stores.
func (h *Handler) handleInstallLinux(w http.ResponseWriter, r *http.Request) {
	if h.engine.CA() == nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{
			Error: "root CA does not exist yet — run POST /api/initialize first",
		})
		return
	}

	base := h.baseURL(r)
	script := fmt.Sprintf(`#!/bin/bash
# ShushTLS Root CA Installer — Linux
# Usage: curl -kfsSL %[1]s/api/ca/install/linux | sudo bash
set -euo pipefail

echo "Downloading ShushTLS root CA..."
# -k is needed because the CA isn't trusted yet — that's what we're fixing.

# Detect distro family and install accordingly.
if command -v update-ca-certificates >/dev/null 2>&1; then
    # Debian / Ubuntu / Alpine
    curl -kfsSL -o /usr/local/share/ca-certificates/shushtls-root-ca.crt %[1]s/api/ca/root.pem
    update-ca-certificates
    echo "Done! Root CA installed via update-ca-certificates."
elif command -v update-ca-trust >/dev/null 2>&1; then
    # RHEL / Fedora / CentOS
    curl -kfsSL -o /etc/pki/ca-trust/source/anchors/shushtls-root-ca.pem %[1]s/api/ca/root.pem
    update-ca-trust extract
    echo "Done! Root CA installed via update-ca-trust."
else
    echo "Error: Could not find update-ca-certificates or update-ca-trust."
    echo "Please install the root CA manually:"
    echo "  curl -kfsSL -o shushtls-root-ca.pem %[1]s/api/ca/root.pem"
    exit 1
fi
`, base)

	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Write([]byte(script))
}

// GET /api/ca/install/windows — PowerShell script for Windows trust store.
func (h *Handler) handleInstallWindows(w http.ResponseWriter, r *http.Request) {
	if h.engine.CA() == nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{
			Error: "root CA does not exist yet — run POST /api/initialize first",
		})
		return
	}

	base := h.baseURL(r)
	script := fmt.Sprintf(`# ShushTLS Root CA Installer — Windows (PowerShell)
# Usage: irm -SkipCertificateCheck %[1]s/api/ca/install/windows | iex
# Must be run as Administrator.

$ErrorActionPreference = "Stop"

$tmpFile = Join-Path $env:TEMP "shushtls-root-ca.pem"

Write-Host "Downloading ShushTLS root CA..."
# -SkipCertificateCheck is needed because the CA isn't trusted yet.
Invoke-WebRequest -SkipCertificateCheck -Uri "%[1]s/api/ca/root.pem" -OutFile $tmpFile

Write-Host "Installing into Windows certificate store (LocalMachine\Root)..."
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($tmpFile)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()

Remove-Item $tmpFile -Force
Write-Host "Done! ShushTLS root CA is now trusted on this machine."
`, base)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(script))
}

// baseURL builds the scheme://host prefix from the incoming request,
// used by install scripts to self-reference the ShushTLS instance.
// Respects X-Forwarded-Proto and X-Forwarded-Host only when trustProxy is set.
func (h *Handler) baseURL(r *http.Request) string {
	return request.BaseURL(r, h.trustProxy)
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func servingMode(state certengine.State) string {
	switch state {
	case certengine.Ready:
		return "https"
	default:
		return "http"
	}
}

func certInfo(cert *x509.Certificate) *CACertInfo {
	return &CACertInfo{
		Fingerprint: fingerprint(cert),
		Subject:     cert.Subject.String(),
		NotBefore:   cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:    cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

func leafInfo(leaf *certengine.LeafCert) LeafCertInfo {
	return LeafCertInfo{
		PrimarySAN: leaf.PrimarySAN(),
		DNSNames:   leaf.Cert.DNSNames,
		NotBefore:  leaf.Cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:   leaf.Cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

// leafInfoFromItem builds LeafCertInfo from a CertListItem (stored or on-demand).
// DisplayNotAfter gives actual expiry for stored certs, or "if issued now" for on-demand.
func leafInfoFromItem(item *certengine.CertListItem) LeafCertInfo {
	info := LeafCertInfo{
		PrimarySAN: item.PrimarySAN,
		DNSNames:   item.DNSNames,
	}
	if item.Leaf != nil && item.Leaf.Cert != nil {
		info.NotBefore = item.Leaf.Cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z")
	}
	info.NotAfter = item.DisplayNotAfter().UTC().Format("2006-01-02T15:04:05Z")
	return info
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}
