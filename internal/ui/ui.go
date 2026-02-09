// Package ui implements the ShushTLS web UI using server-rendered HTML
// and Pico.css. It is a thin presentation layer — all business logic
// lives in the API, and the UI calls the certificate engine directly
// only for read-only state queries.
package ui

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"shushtls/internal/certengine"
)

//go:embed templates/*.html
var templateFS embed.FS

// Handler serves the ShushTLS web UI pages.
type Handler struct {
	engine    *certengine.Engine
	logger    *slog.Logger
	templates map[string]*template.Template
}

// NewHandler creates a UI handler backed by the given engine.
func NewHandler(engine *certengine.Engine, logger *slog.Logger) (*Handler, error) {
	h := &Handler{
		engine: engine,
		logger: logger,
	}
	if err := h.loadTemplates(); err != nil {
		return nil, fmt.Errorf("load templates: %w", err)
	}
	return h, nil
}

// Register adds UI routes to the given mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", h.handleHome)
	mux.HandleFunc("GET /setup", h.handleSetup)
	mux.HandleFunc("GET /trust", h.handleTrust)
	mux.HandleFunc("GET /certificates", h.handleCertificates)
}

// --- Template loading ---

// loadTemplates parses the layout + each page template into ready-to-execute
// template sets. Each page overrides the "title" and "content" blocks
// defined in the layout.
func (h *Handler) loadTemplates() error {
	pages := []string{"home", "setup", "trust", "certificates"}
	h.templates = make(map[string]*template.Template, len(pages))

	for _, page := range pages {
		tmpl, err := template.ParseFS(templateFS,
			"templates/layout.html",
			"templates/"+page+".html",
		)
		if err != nil {
			return fmt.Errorf("parse %s: %w", page, err)
		}
		h.templates[page] = tmpl
	}
	return nil
}

// render executes a named page template with the given data.
func (h *Handler) render(w http.ResponseWriter, page string, data any) {
	tmpl, ok := h.templates[page]
	if !ok {
		h.logger.Error("template not found", "page", page)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		h.logger.Error("template render failed", "page", page, "error", err)
	}
}

// --- Page data types ---

// pageData is the common data passed to every template.
type pageData struct {
	ActiveNav string
	State     string
	Host      string
	Scheme    string
	RootCA    *caInfo
	Certs     []certInfo
}

type caInfo struct {
	Subject     string
	Fingerprint string
	NotBefore   string
	NotAfter    string
}

type certInfo struct {
	PrimarySAN string
	DNSNames   []string
	NotBefore  string
	NotAfter   string
	IsService  bool
}

// buildPageData creates the common template data from the current engine state.
func (h *Handler) buildPageData(r *http.Request, activeNav string) pageData {
	state := h.engine.State()

	pd := pageData{
		ActiveNav: activeNav,
		State:     state.String(),
		Host:      r.Host,
		Scheme:    requestScheme(r),
	}

	if ca := h.engine.CA(); ca != nil {
		pd.RootCA = buildCAInfo(ca.Cert)
	}

	for _, leaf := range h.engine.ListCerts() {
		pd.Certs = append(pd.Certs, buildCertInfo(leaf, h.engine.ServiceHost()))
	}

	return pd
}

// --- Page handlers ---

// GET / (exact match only via {$})
func (h *Handler) handleHome(w http.ResponseWriter, r *http.Request) {
	h.render(w, "home", h.buildPageData(r, "home"))
}

// GET /setup
func (h *Handler) handleSetup(w http.ResponseWriter, r *http.Request) {
	h.render(w, "setup", h.buildPageData(r, "setup"))
}

// GET /trust
func (h *Handler) handleTrust(w http.ResponseWriter, r *http.Request) {
	h.render(w, "trust", h.buildPageData(r, "trust"))
}

// GET /certificates
func (h *Handler) handleCertificates(w http.ResponseWriter, r *http.Request) {
	h.render(w, "certificates", h.buildPageData(r, "certificates"))
}

// --- Helpers ---

func buildCAInfo(cert *x509.Certificate) *caInfo {
	return &caInfo{
		Subject:     cert.Subject.String(),
		Fingerprint: fingerprint(cert),
		NotBefore:   cert.NotBefore.UTC().Format("2006-01-02"),
		NotAfter:    cert.NotAfter.UTC().Format("2006-01-02"),
	}
}

func buildCertInfo(leaf *certengine.LeafCert, serviceHost string) certInfo {
	return certInfo{
		PrimarySAN: leaf.PrimarySAN(),
		DNSNames:   leaf.Cert.DNSNames,
		NotBefore:  leaf.Cert.NotBefore.UTC().Format("2006-01-02"),
		NotAfter:   leaf.Cert.NotAfter.UTC().Format("2006-01-02"),
		IsService:  leaf.PrimarySAN() == serviceHost,
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

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
