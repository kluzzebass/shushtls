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
	"net/url"
	"strings"

	"shushtls/internal/auth"
	"shushtls/internal/certengine"
	"shushtls/internal/request"
)

//go:embed templates/*.html templates/static/*
var templateFS embed.FS

// AboutInfo holds version and attribution shown on the About page and footer.
type AboutInfo struct {
	Version   string
	RepoURL   string
	Author    string
	Copyright string
}

// Handler serves the ShushTLS web UI pages.
type Handler struct {
	engine     *certengine.Engine
	authStore  *auth.Store // optional; nil if auth is not available
	logger     *slog.Logger
	about      AboutInfo
	trustProxy bool // when true, respect X-Forwarded-* headers
	templates  map[string]*template.Template
}

// NewHandler creates a UI handler backed by the given engine.
// The authStore may be nil to disable auth UI. about is shown in the footer and About page.
// trustProxy controls whether X-Forwarded-* headers are respected.
func NewHandler(engine *certengine.Engine, authStore *auth.Store, logger *slog.Logger, about AboutInfo, trustProxy bool) (*Handler, error) {
	h := &Handler{
		engine:     engine,
		authStore:  authStore,
		logger:     logger,
		about:      about,
		trustProxy: trustProxy,
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
	mux.HandleFunc("GET /about", h.handleAbout)

	// Serve embedded static assets (JS, etc.).
	staticFS, _ := fs.Sub(templateFS, "templates/static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
}

// --- Template loading ---

// loadTemplates parses the layout + each page template into ready-to-execute
// template sets. Each page overrides the "title" and "content" blocks
// defined in the layout.
func (h *Handler) loadTemplates() error {
	pages := []string{"setup", "trust", "certificates", "docs", "settings", "about"}
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
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
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
	About       AboutInfo
	RootCA      *caInfo
	Certs       []certInfo
	LeafSubject certengine.LeafSubjectParams // default O, OU, C, L, ST for leaf certs (settings page)
	CountryCodes []CountryCode               // ISO 3166-1 alpha-2 for C field datalist and reference table
}

type caInfo struct {
	Subject     string
	Fingerprint string
	NotBefore   string
	NotAfter    string
}

type certInfo struct {
	PrimarySAN string
	SANURL     string // URL path-encoded for /api/certificates/ link
	DNSNames   []string
	NotBefore  string
	NotAfter   string
	IsService  bool
}

// buildPageData creates the common template data from the current engine state.
func (h *Handler) buildPageData(r *http.Request, activeNav string) pageData {
	state := h.engine.State()

	scheme := request.Scheme(r, h.trustProxy)
	host := request.Host(r, h.trustProxy)
	pd := pageData{
		ActiveNav:   activeNav,
		State:       state.String(),
		Host:        host,
		Scheme:      scheme,
		BaseURL:     scheme + "://" + host,
		AuthEnabled: h.authStore != nil && h.authStore.IsEnabled(),
		About:       h.about,
	}

	if ca := h.engine.CA(); ca != nil {
		pd.RootCA = buildCAInfo(ca.Cert)
	}

	for _, item := range h.engine.ListCerts() {
		pd.Certs = append(pd.Certs, buildCertInfoFromItem(item, h.engine.ServiceHost()))
	}

	if state != certengine.Uninitialized {
		pd.LeafSubject = h.engine.DefaultLeafSubject()
	}

	pd.CountryCodes = CountryCodes

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

// GET /about
func (h *Handler) handleAbout(w http.ResponseWriter, r *http.Request) {
	h.render(w, "about", h.buildPageData(r, "about"))
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
		SANURL:      url.PathEscape(leaf.PrimarySAN()),
		DNSNames:    leaf.Cert.DNSNames,
		NotBefore:   leaf.Cert.NotBefore.UTC().Format("2006-01-02"),
		NotAfter:    leaf.Cert.NotAfter.UTC().Format("2006-01-02"),
		IsService:   leaf.PrimarySAN() == serviceHost,
	}
}

func buildCertInfoFromItem(item *certengine.CertListItem, serviceHost string) certInfo {
	ci := certInfo{
		PrimarySAN: item.PrimarySAN,
		SANURL:     url.PathEscape(item.PrimarySAN),
		DNSNames:   item.DNSNames,
		IsService:  item.PrimarySAN == serviceHost,
	}
	if item.Leaf != nil && item.Leaf.Cert != nil {
		ci.NotBefore = item.Leaf.Cert.NotBefore.UTC().Format("2006-01-02")
	}
	ci.NotAfter = item.DisplayNotAfter().UTC().Format("2006-01-02")
	return ci
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

