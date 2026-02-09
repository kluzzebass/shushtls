package api

import (
	"encoding/json"
	"encoding/pem"
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
	hosts := []string{"shushtls.test", "localhost"}
	h := NewHandler(engine, hosts, logger)
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

func doRequest(t *testing.T, mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func decodeJSON[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(w.Body).Decode(&v); err != nil {
		t.Fatalf("decode JSON: %v\nbody: %s", err, w.Body.String())
	}
	return v
}

// --- GET /api/status ---

func TestStatus_Uninitialized(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/status", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	resp := decodeJSON[StatusResponse](t, w)
	if resp.State != "uninitialized" {
		t.Errorf("state = %q, want %q", resp.State, "uninitialized")
	}
	if resp.ServingMode != "http" {
		t.Errorf("serving_mode = %q, want %q", resp.ServingMode, "http")
	}
	if resp.RootCA != nil {
		t.Error("root_ca should be nil when uninitialized")
	}
	if len(resp.Certs) != 0 {
		t.Errorf("certs should be empty, got %d", len(resp.Certs))
	}
}

func TestStatus_Ready(t *testing.T) {
	h, engine := newInitializedHandler(t)
	mux := serveMux(h)

	// Also issue a wildcard.
	if _, err := engine.IssueCert([]string{"*.home.arpa"}); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	w := doRequest(t, mux, "GET", "/api/status", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	resp := decodeJSON[StatusResponse](t, w)
	if resp.State != "ready" {
		t.Errorf("state = %q, want %q", resp.State, "ready")
	}
	if resp.ServingMode != "https" {
		t.Errorf("serving_mode = %q, want %q", resp.ServingMode, "https")
	}
	if resp.RootCA == nil {
		t.Fatal("root_ca should not be nil when ready")
	}
	if resp.RootCA.Fingerprint == "" {
		t.Error("root CA fingerprint is empty")
	}
	if resp.RootCA.Subject == "" {
		t.Error("root CA subject is empty")
	}

	// Should have 2 certs: service + wildcard.
	if len(resp.Certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(resp.Certs))
	}

	// One should be marked as service.
	serviceCount := 0
	for _, c := range resp.Certs {
		if c.IsService {
			serviceCount++
		}
	}
	if serviceCount != 1 {
		t.Errorf("expected 1 service cert, got %d", serviceCount)
	}
}

func TestStatus_ContentType(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/status", "")
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// --- POST /api/initialize ---

func TestInitialize_Success(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "POST", "/api/initialize", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\nbody: %s", w.Code, w.Body.String())
	}

	resp := decodeJSON[InitializeResponse](t, w)
	if resp.State != "ready" {
		t.Errorf("state = %q, want %q", resp.State, "ready")
	}
	if resp.Message == "" {
		t.Error("message should not be empty")
	}
}

func TestInitialize_Idempotent(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w1 := doRequest(t, mux, "POST", "/api/initialize", "")
	if w1.Code != http.StatusOK {
		t.Fatalf("first init: status = %d", w1.Code)
	}

	w2 := doRequest(t, mux, "POST", "/api/initialize", "")
	if w2.Code != http.StatusOK {
		t.Fatalf("second init: status = %d", w2.Code)
	}

	resp := decodeJSON[InitializeResponse](t, w2)
	if resp.State != "ready" {
		t.Errorf("state = %q, want %q", resp.State, "ready")
	}
}

func TestInitialize_WithCustomCAParams(t *testing.T) {
	h, engine := newTestHandler(t)
	mux := serveMux(h)

	body := `{"organization":"Acme Corp","common_name":"Acme Internal CA","validity_years":10}`
	w := doRequest(t, mux, "POST", "/api/initialize", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\nbody: %s", w.Code, w.Body.String())
	}

	resp := decodeJSON[InitializeResponse](t, w)
	if resp.State != "ready" {
		t.Errorf("state = %q, want %q", resp.State, "ready")
	}

	// Verify the CA actually used the custom params.
	ca := engine.CA().Cert
	if ca.Subject.CommonName != "Acme Internal CA" {
		t.Errorf("CA CN = %q, want %q", ca.Subject.CommonName, "Acme Internal CA")
	}
	if len(ca.Subject.Organization) == 0 || ca.Subject.Organization[0] != "Acme Corp" {
		t.Errorf("CA Org = %v, want [\"Acme Corp\"]", ca.Subject.Organization)
	}
}

func TestInitialize_WithPartialCAParams(t *testing.T) {
	h, engine := newTestHandler(t)
	mux := serveMux(h)

	// Only set organization — rest should use defaults.
	body := `{"organization":"My Lab"}`
	w := doRequest(t, mux, "POST", "/api/initialize", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\nbody: %s", w.Code, w.Body.String())
	}

	ca := engine.CA().Cert
	if len(ca.Subject.Organization) == 0 || ca.Subject.Organization[0] != "My Lab" {
		t.Errorf("CA Org = %v, want [\"My Lab\"]", ca.Subject.Organization)
	}
	if ca.Subject.CommonName != "ShushTLS Root CA" {
		t.Errorf("CA CN = %q, want default", ca.Subject.CommonName)
	}
}

func TestInitialize_InvalidBody(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "POST", "/api/initialize", "not json at all")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400\nbody: %s", w.Code, w.Body.String())
	}

	resp := decodeJSON[ErrorResponse](t, w)
	if resp.Error == "" {
		t.Error("error message should not be empty")
	}
}

// --- GET /api/ca/root.pem ---

func TestCACert_NotFoundBeforeInit(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/ca/root.pem", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestCACert_Download(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/ca/root.pem", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	// Check Content-Type.
	ct := w.Header().Get("Content-Type")
	if ct != "application/x-pem-file" {
		t.Errorf("Content-Type = %q, want application/x-pem-file", ct)
	}

	// Check Content-Disposition.
	cd := w.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "shushtls-root-ca.pem") {
		t.Errorf("Content-Disposition = %q, want filename containing shushtls-root-ca.pem", cd)
	}

	// Verify it's valid PEM.
	block, _ := pem.Decode(w.Body.Bytes())
	if block == nil {
		t.Fatal("response is not valid PEM")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("PEM type = %q, want CERTIFICATE", block.Type)
	}
}

// --- POST /api/certificates ---

func TestIssueCert_BeforeInit(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "POST", "/api/certificates",
		`{"dns_names": ["nas.home.arpa"]}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
}

func TestIssueCert_EmptyNames(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "POST", "/api/certificates",
		`{"dns_names": []}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestIssueCert_InvalidJSON(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "POST", "/api/certificates", "not json")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestIssueCert_FQDN(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "POST", "/api/certificates",
		`{"dns_names": ["nas.home.arpa"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\nbody: %s", w.Code, w.Body.String())
	}

	resp := decodeJSON[IssueCertResponse](t, w)
	if resp.Cert.PrimarySAN != "nas.home.arpa" {
		t.Errorf("primary_san = %q, want %q", resp.Cert.PrimarySAN, "nas.home.arpa")
	}
}

func TestIssueCert_Wildcard(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "POST", "/api/certificates",
		`{"dns_names": ["*.home.arpa"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\nbody: %s", w.Code, w.Body.String())
	}

	resp := decodeJSON[IssueCertResponse](t, w)
	if resp.Cert.PrimarySAN != "*.home.arpa" {
		t.Errorf("primary_san = %q, want %q", resp.Cert.PrimarySAN, "*.home.arpa")
	}
	// Should include bare domain in SANs.
	found := false
	for _, name := range resp.Cert.DNSNames {
		if name == "home.arpa" {
			found = true
		}
	}
	if !found {
		t.Errorf("wildcard cert missing bare domain, SANs = %v", resp.Cert.DNSNames)
	}
}

func TestIssueCert_Idempotent(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	body := `{"dns_names": ["nas.home.arpa"]}`
	w1 := doRequest(t, mux, "POST", "/api/certificates", body)
	w2 := doRequest(t, mux, "POST", "/api/certificates", body)

	resp1 := decodeJSON[IssueCertResponse](t, w1)
	resp2 := decodeJSON[IssueCertResponse](t, w2)

	if resp1.Cert.PrimarySAN != resp2.Cert.PrimarySAN {
		t.Error("idempotent requests returned different SANs")
	}
	if resp1.Cert.NotBefore != resp2.Cert.NotBefore {
		t.Error("idempotent requests returned different certs")
	}
}

// --- GET /api/certificates ---

func TestListCerts_Empty(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/certificates", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	// Should be null or empty array.
	body := strings.TrimSpace(w.Body.String())
	if body != "null" && body != "[]" {
		t.Errorf("expected null or [], got %s", body)
	}
}

func TestListCerts_AfterIssuance(t *testing.T) {
	h, engine := newInitializedHandler(t)
	mux := serveMux(h)

	// Issue an additional cert.
	if _, err := engine.IssueCert([]string{"nas.home.arpa"}); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	w := doRequest(t, mux, "GET", "/api/certificates", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var certs []LeafCertInfo
	if err := json.NewDecoder(w.Body).Decode(&certs); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// service cert + nas cert = 2
	if len(certs) != 2 {
		t.Errorf("expected 2 certs, got %d", len(certs))
	}
}

// --- GET /api/certificates/{san} ---

func TestGetCert_NotFound(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/certificates/nonexistent.home.arpa", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestGetCert_DownloadCert(t *testing.T) {
	h, engine := newInitializedHandler(t)
	mux := serveMux(h)

	if _, err := engine.IssueCert([]string{"nas.home.arpa"}); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	w := doRequest(t, mux, "GET", "/api/certificates/nas.home.arpa", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/x-pem-file" {
		t.Errorf("Content-Type = %q, want application/x-pem-file", ct)
	}

	block, _ := pem.Decode(w.Body.Bytes())
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("response is not a valid PEM certificate")
	}
}

func TestGetCert_DownloadKey(t *testing.T) {
	h, engine := newInitializedHandler(t)
	mux := serveMux(h)

	if _, err := engine.IssueCert([]string{"nas.home.arpa"}); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	w := doRequest(t, mux, "GET", "/api/certificates/nas.home.arpa?type=key", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	block, _ := pem.Decode(w.Body.Bytes())
	if block == nil || block.Type != "EC PRIVATE KEY" {
		t.Fatal("response is not a valid PEM private key")
	}
}

func TestGetCert_InvalidType(t *testing.T) {
	h, engine := newInitializedHandler(t)
	mux := serveMux(h)

	if _, err := engine.IssueCert([]string{"nas.home.arpa"}); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	w := doRequest(t, mux, "GET", "/api/certificates/nas.home.arpa?type=bogus", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestGetCert_EmptySAN(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/certificates/", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

// --- Error response format ---

func TestErrorResponse_IsJSON(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/ca/root.pem", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("error Content-Type = %q, want application/json", ct)
	}

	resp := decodeJSON[ErrorResponse](t, w)
	if resp.Error == "" {
		t.Error("error message should not be empty")
	}
}

// --- Method not allowed ---

func TestInitialize_WrongMethod(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/initialize", "")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405\nbody: %s", w.Code, w.Body.String())
	}

	allow := w.Header().Get("Allow")
	if allow != "POST" {
		t.Errorf("Allow = %q, want POST", allow)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestStatus_WrongMethod(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "POST", "/api/status", "")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405\nbody: %s", w.Code, w.Body.String())
	}
}

func TestCACert_WrongMethod(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "DELETE", "/api/ca/root.pem", "")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405\nbody: %s", w.Code, w.Body.String())
	}
}
