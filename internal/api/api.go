// Package api implements the ShushTLS HTTP API. All endpoints are JSON
// where applicable, idempotent where reasonable, and scriptable via curl.
// No authentication — ShushTLS uses a LAN trust model.
package api

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"shushtls/internal/auth"
	"shushtls/internal/certengine"
)

// Handler holds the API dependencies and registers routes on a mux.
type Handler struct {
	engine       *certengine.Engine
	serviceHosts []string
	logger       *slog.Logger
	onReady      func()      // called when initialization reaches Ready state
	authStore    *auth.Store // optional; nil disables auth entirely
}

// NewHandler creates an API handler backed by the given engine.
// The onReady callback is invoked when initialization completes and the
// engine reaches Ready state. It may be nil.
// The authStore enables optional Basic Auth; pass nil to disable.
func NewHandler(engine *certengine.Engine, serviceHosts []string, logger *slog.Logger, onReady func(), authStore *auth.Store) *Handler {
	return &Handler{
		engine:       engine,
		serviceHosts: serviceHosts,
		logger:       logger,
		onReady:      onReady,
		authStore:    authStore,
	}
}

// Register adds all API routes to the given mux.
//
// Protected endpoints (when auth is enabled):
//   - POST /api/initialize
//   - POST /api/certificates
//   - POST /api/auth
//   - GET  /api/status
//   - GET  /api/certificates/{san}?type=key (private key downloads)
//
// Unprotected endpoints (always open):
//   - GET  /api/ca/root.pem
//   - GET  /api/certificates (listing)
//   - GET  /api/certificates/{san} (cert downloads, not keys)
//   - GET  /api/ca/install/*
func (h *Handler) Register(mux *http.ServeMux) {
	// Protected routes.
	mux.HandleFunc("GET /api/status", h.requireAuth(h.handleStatus))
	mux.HandleFunc("POST /api/initialize", h.requireAuth(h.handleInitialize))
	mux.HandleFunc("POST /api/certificates", h.requireAuth(h.handleIssueCert))
	mux.HandleFunc("POST /api/auth", h.requireAuth(h.handleAuth))

	// Unprotected routes — cert reads and install scripts.
	mux.HandleFunc("GET /api/ca/root.pem", h.handleCACert)
	mux.HandleFunc("GET /api/certificates", h.handleListCerts)
	mux.HandleFunc("GET /api/certificates/", h.handleGetCert) // auth checked inside for ?type=key
	mux.HandleFunc("GET /api/ca/install", h.handleInstallIndex)
	mux.HandleFunc("GET /api/ca/install/macos", h.handleInstallMacOS)
	mux.HandleFunc("GET /api/ca/install/linux", h.handleInstallLinux)
	mux.HandleFunc("GET /api/ca/install/windows", h.handleInstallWindows)

	// Method-not-allowed handlers for routes that only accept specific methods.
	// Without these, wrong-method requests fall through to the /api/ catch-all
	// and return 404 instead of 405.
	mux.HandleFunc("/api/initialize", methodNotAllowed("POST"))
	mux.HandleFunc("/api/status", methodNotAllowed("GET"))
	mux.HandleFunc("/api/ca/root.pem", methodNotAllowed("GET"))
	mux.HandleFunc("/api/auth", methodNotAllowed("POST"))
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		fmt.Fprintf(w, `{"error":"method %s not allowed, use %s"}`+"\n", r.Method, allowed)
	}
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
	DNSNames []string `json:"dns_names"`
}

// IssueCertResponse is the JSON body for POST /api/certificates.
type IssueCertResponse struct {
	Cert    LeafCertInfo `json:"certificate"`
	Message string       `json:"message"`
}

// AuthRequest is the JSON body for POST /api/auth.
type AuthRequest struct {
	Enabled  *bool  `json:"enabled"`  // pointer to distinguish false from omitted
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// AuthResponse is the JSON body for POST /api/auth.
type AuthResponse struct {
	Enabled bool   `json:"enabled"`
	Message string `json:"message"`
}

// ErrorResponse is the JSON body for error responses.
type ErrorResponse struct {
	Error string `json:"error"`
}

// --- Handlers ---

// GET /api/status
func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	state := h.engine.State()

	resp := StatusResponse{
		State:       state.String(),
		ServingMode: servingMode(state),
	}

	if ca := h.engine.CA(); ca != nil {
		resp.RootCA = certInfo(ca.Cert)
	}

	for _, leaf := range h.engine.ListCerts() {
		info := leafInfo(leaf)
		info.IsService = leaf.PrimarySAN() == h.engine.ServiceHost()
		resp.Certs = append(resp.Certs, info)
	}

	writeJSON(w, http.StatusOK, resp)
}

// POST /api/initialize
func (h *Handler) handleInitialize(w http.ResponseWriter, r *http.Request) {
	// Parse optional CA params from the request body.
	// An empty body is fine — all fields default to sensible values.
	var caParams certengine.CAParams
	if r.Body != nil {
		body, _ := io.ReadAll(r.Body)
		if len(body) > 0 {
			if err := json.Unmarshal(body, &caParams); err != nil {
				writeJSON(w, http.StatusBadRequest, ErrorResponse{
					Error: fmt.Sprintf("invalid request body: %v", err),
				})
				return
			}
		}
	}

	state, err := h.engine.Initialize(h.serviceHosts, caParams)
	if err != nil {
		h.logger.Error("initialization failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("initialization failed: %v", err),
		})
		return
	}

	var msg string
	switch state {
	case certengine.Ready:
		msg = "Initialization complete. HTTPS is now active. Download the root CA and install it on your devices."
	case certengine.Initialized:
		msg = "Root CA generated. Service certificate pending."
	default:
		msg = "Unexpected state after initialization."
	}

	h.logger.Info("initialization complete", "state", state.String())

	// Notify the server that HTTPS can be activated.
	if state == certengine.Ready && h.onReady != nil {
		h.onReady()
	}

	writeJSON(w, http.StatusOK, InitializeResponse{
		State:   state.String(),
		Message: msg,
	})
}

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

// GET /api/certificates
func (h *Handler) handleListCerts(w http.ResponseWriter, r *http.Request) {
	certs := h.engine.ListCerts()

	var infos []LeafCertInfo
	for _, leaf := range certs {
		info := leafInfo(leaf)
		info.IsService = leaf.PrimarySAN() == h.engine.ServiceHost()
		infos = append(infos, info)
	}

	writeJSON(w, http.StatusOK, infos)
}

// POST /api/certificates
func (h *Handler) handleIssueCert(w http.ResponseWriter, r *http.Request) {
	if h.engine.CA() == nil {
		writeJSON(w, http.StatusConflict, ErrorResponse{
			Error: "root CA does not exist — run POST /api/initialize first",
		})
		return
	}

	var req IssueCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: fmt.Sprintf("invalid request body: %v", err),
		})
		return
	}

	if len(req.DNSNames) == 0 {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: "dns_names must contain at least one entry",
		})
		return
	}

	leaf, err := h.engine.IssueCert(req.DNSNames)
	if err != nil {
		h.logger.Error("certificate issuance failed", "error", err)
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("certificate issuance failed: %v", err),
		})
		return
	}

	info := leafInfo(leaf)
	info.IsService = leaf.PrimarySAN() == h.engine.ServiceHost()

	h.logger.Info("certificate issued", "primarySAN", leaf.PrimarySAN())
	writeJSON(w, http.StatusOK, IssueCertResponse{
		Cert:    info,
		Message: "Certificate issued successfully.",
	})
}

// GET /api/certificates/{san}
// Downloads the certificate and key as PEM for the given primary SAN.
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

	// Determine what to return based on query parameter.
	// ?type=key returns the private key, ?type=cert (default) returns the cert.
	which := r.URL.Query().Get("type")
	if which == "" {
		which = "cert"
	}

	leaf := h.engine.GetCert(san)
	if leaf == nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{
			Error: fmt.Sprintf("no certificate found for %q", san),
		})
		return
	}

	switch which {
	case "cert":
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: leaf.Raw,
		})
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=%q", certengine.SanitizeSAN(san)+".cert.pem"))
		w.Write(pemBlock)

	case "key":
		// Private key downloads are protected by auth.
		if h.authStore != nil && h.authStore.IsEnabled() {
			username, password, ok := r.BasicAuth()
			if !ok || !h.authStore.Verify(username, password) {
				w.Header().Set("WWW-Authenticate", `Basic realm="ShushTLS"`)
				writeJSON(w, http.StatusUnauthorized, ErrorResponse{
					Error: "authentication required for private key download",
				})
				return
			}
		}
		der, err := x509.MarshalECPrivateKey(leaf.Key)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error: fmt.Sprintf("marshal key: %v", err),
			})
			return
		}
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: der,
		})
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=%q", certengine.SanitizeSAN(san)+".key.pem"))
		w.Write(pemBlock)

	default:
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: fmt.Sprintf("unknown type %q — use \"cert\" or \"key\"", which),
		})
	}
}

// POST /api/auth — enable or disable authentication.
func (h *Handler) handleAuth(w http.ResponseWriter, r *http.Request) {
	if h.authStore == nil {
		writeJSON(w, http.StatusConflict, ErrorResponse{
			Error: "authentication is not available (no auth store configured)",
		})
		return
	}

	if h.engine.State() == certengine.Uninitialized {
		writeJSON(w, http.StatusConflict, ErrorResponse{
			Error: "ShushTLS must be initialized before configuring auth",
		})
		return
	}

	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: fmt.Sprintf("invalid request body: %v", err),
		})
		return
	}

	if req.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: `"enabled" field is required`,
		})
		return
	}

	if *req.Enabled {
		// Enabling auth — username and password are required.
		if req.Username == "" || req.Password == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: "username and password are required when enabling auth",
			})
			return
		}
		if err := h.authStore.Enable(req.Username, req.Password); err != nil {
			h.logger.Error("failed to enable auth", "error", err)
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error: fmt.Sprintf("failed to enable auth: %v", err),
			})
			return
		}
		h.logger.Info("authentication enabled", "username", req.Username)
		writeJSON(w, http.StatusOK, AuthResponse{
			Enabled: true,
			Message: "Authentication enabled.",
		})
	} else {
		// Disabling auth.
		if err := h.authStore.Disable(); err != nil {
			h.logger.Error("failed to disable auth", "error", err)
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error: fmt.Sprintf("failed to disable auth: %v", err),
			})
			return
		}
		h.logger.Info("authentication disabled")
		writeJSON(w, http.StatusOK, AuthResponse{
			Enabled: false,
			Message: "Authentication disabled.",
		})
	}
}

// --- Root CA install helpers ---

// InstallPlatform describes an available install script endpoint.
type InstallPlatform struct {
	Platform string `json:"platform"`
	Endpoint string `json:"endpoint"`
	Example  string `json:"example"`
}

// GET /api/ca/install — summary of available platform install scripts.
func (h *Handler) handleInstallIndex(w http.ResponseWriter, r *http.Request) {
	if h.engine.CA() == nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{
			Error: "root CA does not exist yet — run POST /api/initialize first",
		})
		return
	}

	base := baseURL(r)
	platforms := []InstallPlatform{
		{
			Platform: "macOS",
			Endpoint: "/api/ca/install/macos",
			Example:  fmt.Sprintf("curl -kfsSL %s/api/ca/install/macos | bash", base),
		},
		{
			Platform: "Linux (Debian/Ubuntu/RHEL/Fedora)",
			Endpoint: "/api/ca/install/linux",
			Example:  fmt.Sprintf("curl -kfsSL %s/api/ca/install/linux | sudo bash", base),
		},
		{
			Platform: "Windows (PowerShell)",
			Endpoint: "/api/ca/install/windows",
			Example:  fmt.Sprintf("irm -SkipCertificateCheck %s/api/ca/install/windows | iex", base),
		},
	}

	writeJSON(w, http.StatusOK, platforms)
}

// GET /api/ca/install/macos — shell script for macOS trust store.
func (h *Handler) handleInstallMacOS(w http.ResponseWriter, r *http.Request) {
	if h.engine.CA() == nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{
			Error: "root CA does not exist yet — run POST /api/initialize first",
		})
		return
	}

	base := baseURL(r)
	script := fmt.Sprintf(`#!/bin/bash
# ShushTLS Root CA Installer — macOS
# Usage: curl -kfsSL %[1]s/api/ca/install/macos | bash
set -euo pipefail

TMPFILE=$(mktemp /tmp/shushtls-root-ca.XXXXXX.pem)
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

	base := baseURL(r)
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

	base := baseURL(r)
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
func baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
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

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}
