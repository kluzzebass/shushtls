package ui

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"shushtls/internal/certengine"
)

// --- Test helpers ---

func newTestHandler(t *testing.T) (*Handler, *certengine.Engine) {
	t.Helper()
	engine, err := certengine.New(t.TempDir())
	if err != nil {
		t.Fatalf("certengine.New: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h, err := NewHandler(engine, nil, logger, AboutInfo{Version: "test"})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h, engine
}

func newInitializedHandler(t *testing.T) (*Handler, *certengine.Engine) {
	t.Helper()
	h, engine := newTestHandler(t)
	if _, err := engine.Initialize([]string{"shushtls.test", "localhost"}, certengine.CAParams{}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	return h, engine
}

func serveMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()
	h.Register(mux)
	return mux
}

func doGet(t *testing.T, mux *http.ServeMux, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

// --- Home (contextual: Setup when uninitialized, Install CA when ready) ---

func TestHome_Uninitialized_ShowsSetup(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doGet(t, mux, "/")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	assertContains(t, body, "Setup")
	assertContains(t, body, "Initialize ShushTLS")
	assertContentType(t, w, "text/html")
}

func TestHome_Ready_ShowsInstallCA(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doGet(t, mux, "/")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	assertContains(t, body, "Install root CA")
	assertContains(t, body, "download the root CA")
	assertContains(t, body, "macOS")
	assertContentType(t, w, "text/html")
}

// --- Setup page tests ---

func TestSetup_Uninitialized(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doGet(t, mux, "/setup")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	assertContains(t, body, "Initialize ShushTLS")
	assertContains(t, body, "organization")
	assertContains(t, body, "common_name")
	assertContentType(t, w, "text/html")
}

func TestSetup_AlreadyInitialized_RedirectsToHome(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doGet(t, mux, "/setup")
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want /", loc)
	}
}

// --- Trust page tests ---

func TestTrust_Uninitialized(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doGet(t, mux, "/trust")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	assertContains(t, body, "not been generated yet")
	assertContains(t, body, "Run Setup first")
}

func TestTrust_Initialized(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doGet(t, mux, "/trust")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	assertContains(t, body, "download the root CA")
	assertContains(t, body, "macOS")
	assertContains(t, body, "Linux")
	assertContains(t, body, "Windows")
	assertContains(t, body, "iOS")
	assertContains(t, body, "Android")
}

// --- Certificates page tests ---

func TestCertificates_Uninitialized(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doGet(t, mux, "/certificates")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	assertContains(t, body, "Initialize ShushTLS first")
}

func TestCertificates_WithCerts(t *testing.T) {
	h, engine := newInitializedHandler(t)
	mux := serveMux(h)

	// Issue an extra cert.
	if _, err := engine.IssueCert([]string{"*.home.arpa"}); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	w := doGet(t, mux, "/certificates")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	assertContains(t, body, "shushtls.test")
	assertContains(t, body, "*.home.arpa")
	assertContains(t, body, "Issue a new certificate")
}

// --- Navigation tests ---

func TestNavigation_ActivePageHighlighted(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	// When uninitialized, / shows Setup; /setup shows Setup; both highlight Setup.
	tests := []struct {
		path    string
		current string
	}{
		{"/", "Setup"},
		{"/setup", "Setup"},
		{"/trust", "Install CA"},
		{"/certificates", "Certificates"},
		{"/docs", "Docs"},
	}

	for _, tt := range tests {
		w := doGet(t, mux, tt.path)
		if w.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", tt.path, w.Code)
			continue
		}
		// The active nav item should have aria-current="page".
		body := w.Body.String()
		assertContains(t, body, `aria-current="page"`)
	}
}

// --- Layout tests ---

func TestLayout_ContainsPicoCSS(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doGet(t, mux, "/")
	body := w.Body.String()
	assertContains(t, body, "pico")
	assertContains(t, body, "ShushTLS")
}

func TestLayout_HasFooter(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doGet(t, mux, "/")
	body := w.Body.String()
	assertContains(t, body, "HTTPS for your home network")
}

// --- Static assets ---

func TestStaticJS_Served(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doGet(t, mux, "/static/app.js")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	assertContains(t, body, "api/initialize")
	assertContains(t, body, "api/certificates")
}

func TestLayout_IncludesScript(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doGet(t, mux, "/")
	body := w.Body.String()
	assertContains(t, body, "/static/app.js")
}

// --- Helpers ---

func assertContains(t *testing.T, body, substr string) {
	t.Helper()
	if !strings.Contains(body, substr) {
		t.Errorf("body does not contain %q\nbody (first 500 chars): %s", substr, truncate(body, 500))
	}
}

func assertContentType(t *testing.T, w *httptest.ResponseRecorder, want string) {
	t.Helper()
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, want) {
		t.Errorf("Content-Type = %q, want prefix %q", ct, want)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
