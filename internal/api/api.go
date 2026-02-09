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
	"log/slog"
	"net/http"
	"strings"

	"shushtls/internal/certengine"
)

// Handler holds the API dependencies and registers routes on a mux.
type Handler struct {
	engine       *certengine.Engine
	serviceHosts []string
	logger       *slog.Logger
}

// NewHandler creates an API handler backed by the given engine.
func NewHandler(engine *certengine.Engine, serviceHosts []string, logger *slog.Logger) *Handler {
	return &Handler{
		engine:       engine,
		serviceHosts: serviceHosts,
		logger:       logger,
	}
}

// Register adds all API routes to the given mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/status", h.handleStatus)
	mux.HandleFunc("POST /api/initialize", h.handleInitialize)
	mux.HandleFunc("GET /api/ca/root.pem", h.handleCACert)
	mux.HandleFunc("GET /api/certificates", h.handleListCerts)
	mux.HandleFunc("POST /api/certificates", h.handleIssueCert)
	mux.HandleFunc("GET /api/certificates/", h.handleGetCert)

	// Method-not-allowed handlers for routes that only accept specific methods.
	// Without these, wrong-method requests fall through to the /api/ catch-all
	// and return 404 instead of 405.
	mux.HandleFunc("/api/initialize", methodNotAllowed("POST"))
	mux.HandleFunc("/api/status", methodNotAllowed("GET"))
	mux.HandleFunc("/api/ca/root.pem", methodNotAllowed("GET"))
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
	state, err := h.engine.Initialize(h.serviceHosts)
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
		msg = "Initialization complete. Download the root CA, install it on your devices, then restart ShushTLS to enable HTTPS."
	case certengine.Initialized:
		msg = "Root CA generated. Service certificate pending."
	default:
		msg = "Unexpected state after initialization."
	}

	h.logger.Info("initialization complete", "state", state.String())
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
