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
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"shushtls/internal/auth"
	"shushtls/internal/certengine"
)

//go:embed templates/*.html templates/static/*
var templateFS embed.FS

// Handler serves the ShushTLS web UI pages.
type Handler struct {
	engine    *certengine.Engine
	authStore *auth.Store // optional; nil if auth is not available
	logger    *slog.Logger
	templates map[string]*template.Template
}

// NewHandler creates a UI handler backed by the given engine.
// The authStore may be nil to disable auth UI.
func NewHandler(engine *certengine.Engine, authStore *auth.Store, logger *slog.Logger) (*Handler, error) {
	h := &Handler{
		engine:    engine,
		authStore: authStore,
		logger:    logger,
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
	mux.HandleFunc("GET /docs", h.handleDocs)
	mux.HandleFunc("GET /settings", h.requireAuth(h.handleSettings))

	// Serve embedded static assets (JS, etc.).
	staticFS, _ := fs.Sub(templateFS, "templates/static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
}

// --- Template loading ---

// loadTemplates parses the layout + each page template into ready-to-execute
// template sets. Each page overrides the "title" and "content" blocks
// defined in the layout.
func (h *Handler) loadTemplates() error {
	pages := []string{"setup", "trust", "certificates", "docs", "settings"}
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
	ActiveNav   string
	State       string
	Host        string
	Scheme      string
	BaseURL     string // scheme://host for self-referencing URLs
	AuthEnabled bool
	RootCA      *caInfo
	Certs       []certInfo
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

	scheme := requestScheme(r)
	pd := pageData{
		ActiveNav:   activeNav,
		State:       state.String(),
		Host:        r.Host,
		Scheme:      scheme,
		BaseURL:     scheme + "://" + r.Host,
		AuthEnabled: h.authStore != nil && h.authStore.IsEnabled(),
	}

	if ca := h.engine.CA(); ca != nil {
		pd.RootCA = buildCAInfo(ca.Cert)
	}

	for _, leaf := range h.engine.ListCerts() {
		pd.Certs = append(pd.Certs, buildCertInfo(leaf, h.engine.ServiceHost()))
	}

	return pd
}

// requireAuth wraps a UI handler with Basic Auth when auth is enabled.
func (h *Handler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.authStore == nil || !h.authStore.IsEnabled() {
			next(w, r)
			return
		}

		username, password, ok := r.BasicAuth()
		if !ok || !h.authStore.Verify(username, password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="ShushTLS"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// --- Page handlers ---

// GET / — Setup when uninitialized, Install CA when ready. No separate status page.
func (h *Handler) handleHome(w http.ResponseWriter, r *http.Request) {
	if h.engine.State() == certengine.Uninitialized {
		h.render(w, "setup", h.buildPageData(r, "setup"))
	} else {
		h.render(w, "trust", h.buildPageData(r, "trust"))
	}
}

// GET /setup — redirect to / when already initialized (/ shows Install CA then).
func (h *Handler) handleSetup(w http.ResponseWriter, r *http.Request) {
	if h.engine.State() != certengine.Uninitialized {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
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

// GET /docs
func (h *Handler) handleDocs(w http.ResponseWriter, r *http.Request) {
	h.render(w, "docs", h.buildPageData(r, "docs"))
}

// GET /settings
func (h *Handler) handleSettings(w http.ResponseWriter, r *http.Request) {
	h.render(w, "settings", h.buildPageData(r, "settings"))
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
