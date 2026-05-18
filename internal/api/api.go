// Package api implements the ShushTLS HTTP API (Huma). JSON where applicable,
// idempotent where reasonable, and scriptable via curl. Optional HTTP Basic Auth.
package api

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"shushtls/internal/auth"
	"shushtls/internal/certengine"
)

// maxRequestBody is the maximum allowed request body size (1 MB).
// Prevents memory exhaustion from oversized payloads.
const maxRequestBody = 1 << 20

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
	api := h.RegisterAPI(mux)
	registerAPINotFound(mux, api)
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
	PrimarySAN         string   `json:"primary_san"`
	DNSNames           []string `json:"dns_names"`
	NotBefore          string   `json:"not_before"`
	NotAfter           string   `json:"not_after"`
	IsService          bool     `json:"is_service" doc:"True if this certificate secures the ShushTLS UI/API (set via POST /api/service-cert); false for user-issued leaf certificates."`
	CommonName         string   `json:"common_name,omitempty"`
	Serial             string   `json:"serial,omitempty"`
	SHA256Fingerprint  string   `json:"sha256_fingerprint,omitempty"`
	KeyAlgorithm       string   `json:"key_algorithm,omitempty"`
	SignatureAlgorithm string   `json:"signature_algorithm,omitempty"`
	KeyUsage           []string `json:"key_usage,omitempty"`
	ExtendedKeyUsage   []string `json:"extended_key_usage,omitempty"`
}

// InitializeResponse is the JSON body for POST /api/initialize.
type InitializeResponse struct {
	State   string `json:"state"`
	Message string `json:"message"`
}

// IssueCertRequest is the JSON body for POST /api/certificates.
type IssueCertRequest struct {
	DNSNames   []string                      `json:"dns_names"`
	CommonName string                        `json:"common_name,omitempty" doc:"Subject CN; defaults to the first dns_name"`
	Subject    *certengine.LeafSubjectParams `json:"subject,omitempty" doc:"Optional O/OU/C/L/ST override for this cert only"`
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

// InstallPlatform describes an available install script endpoint.
type InstallPlatform struct {
	Platform string `json:"platform"`
	Endpoint string `json:"endpoint"`
	Example  string `json:"example"`
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
