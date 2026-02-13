package api

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"shushtls/internal/auth"
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
	h := NewHandler(engine, hosts, logger, nil, nil, false)
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
	if _, err := engine.IssueCert([]string{"*.example.com"}, nil); err != nil {
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
		`{"dns_names": ["nas.example.com"]}`)
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
		`{"dns_names": ["nas.example.com"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\nbody: %s", w.Code, w.Body.String())
	}

	resp := decodeJSON[IssueCertResponse](t, w)
	if resp.Cert.PrimarySAN != "nas.example.com" {
		t.Errorf("primary_san = %q, want %q", resp.Cert.PrimarySAN, "nas.example.com")
	}
}

func TestIssueCert_Wildcard(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "POST", "/api/certificates",
		`{"dns_names": ["*.example.com"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\nbody: %s", w.Code, w.Body.String())
	}

	resp := decodeJSON[IssueCertResponse](t, w)
	if resp.Cert.PrimarySAN != "*.example.com" {
		t.Errorf("primary_san = %q, want %q", resp.Cert.PrimarySAN, "*.example.com")
	}
	// Should include bare domain in SANs.
	found := false
	for _, name := range resp.Cert.DNSNames {
		if name == "example.com" {
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

	body := `{"dns_names": ["nas.example.com"]}`
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
	if _, err := engine.IssueCert([]string{"nas.example.com"}, nil); err != nil {
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

	w := doRequest(t, mux, "GET", "/api/certificates/nonexistent.example.com", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestGetCert_DownloadZip(t *testing.T) {
	h, engine := newInitializedHandler(t)
	mux := serveMux(h)

	if _, err := engine.IssueCert([]string{"nas.example.com"}, nil); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// Default (no type) returns tar; type=zip returns zip.
	for _, path := range []string{"/api/certificates/nas.example.com?type=zip"} {
		w := doRequest(t, mux, "GET", path, "")
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", path, w.Code)
		}
		ct := w.Header().Get("Content-Type")
		if ct != "application/zip" {
			t.Errorf("%s: Content-Type = %q, want application/zip", path, ct)
		}
		zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
		if err != nil {
			t.Fatalf("zip.NewReader: %v", err)
		}
		if len(zr.File) != 2 {
			t.Fatalf("zip has %d files, want 2", len(zr.File))
		}
		names := make(map[string]bool)
		for _, f := range zr.File {
			names[f.Name] = true
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("open zip entry %q: %v", f.Name, err)
			}
			var buf bytes.Buffer
			if _, err := io.Copy(&buf, rc); err != nil {
				rc.Close()
				t.Fatalf("read zip entry %q: %v", f.Name, err)
			}
			rc.Close()
			block, _ := pem.Decode(buf.Bytes())
			if block == nil {
				t.Fatalf("zip entry %q is not valid PEM", f.Name)
			}
			if strings.HasSuffix(f.Name, ".cert.pem") && block.Type != "CERTIFICATE" {
				t.Fatalf("zip entry %q: PEM type = %q, want CERTIFICATE", f.Name, block.Type)
			}
			if strings.HasSuffix(f.Name, ".key.pem") && block.Type != "EC PRIVATE KEY" {
				t.Fatalf("zip entry %q: PEM type = %q, want EC PRIVATE KEY", f.Name, block.Type)
			}
		}
		base := certengine.SanitizeSAN("nas.example.com")
		if !names[base+".cert.pem"] || !names[base+".key.pem"] {
			t.Errorf("zip entries = %v, want %q and %q", names, base+".cert.pem", base+".key.pem")
		}
	}
}

func TestGetCert_InvalidType(t *testing.T) {
	h, engine := newInitializedHandler(t)
	mux := serveMux(h)

	if _, err := engine.IssueCert([]string{"nas.example.com"}, nil); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	for _, typ := range []string{"bogus", "cert", "key"} {
		w := doRequest(t, mux, "GET", "/api/certificates/nas.example.com?type="+typ, "")
		if w.Code != http.StatusBadRequest {
			t.Errorf("type=%q: status = %d, want 400", typ, w.Code)
		}
	}
}

func TestGetCert_DownloadTar(t *testing.T) {
	h, engine := newInitializedHandler(t)
	mux := serveMux(h)

	if _, err := engine.IssueCert([]string{"nas.example.com"}, nil); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// Default (no type) and type=tar both return tar.
	for _, path := range []string{"/api/certificates/nas.example.com", "/api/certificates/nas.example.com?type=tar"} {
		w := doRequest(t, mux, "GET", path, "")
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", path, w.Code)
		}
		ct := w.Header().Get("Content-Type")
		if ct != "application/x-tar" {
			t.Errorf("%s: Content-Type = %q, want application/x-tar", path, ct)
		}
		if !strings.Contains(w.Body.String(), "CERTIFICATE") || !strings.Contains(w.Body.String(), "EC PRIVATE KEY") {
			t.Error("tar should contain cert and key PEM blocks")
		}
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

// --- GET/PUT /api/leaf-subject ---

func TestLeafSubject_GetDefault(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/leaf-subject", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var p certengine.LeafSubjectParams
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if p.Organization == "" {
		t.Error("expected default organization to be set")
	}
}

func TestLeafSubject_SetAndGet(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	body := `{"organization": "My Org", "organizational_unit": "Dev", "country": "US", "locality": "NYC", "province": "NY"}`
	w := doRequest(t, mux, "PUT", "/api/leaf-subject", body)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200, body: %s", w.Code, w.Body.String())
	}
	var putResp certengine.LeafSubjectParams
	if err := json.Unmarshal(w.Body.Bytes(), &putResp); err != nil {
		t.Fatalf("decode PUT response: %v", err)
	}
	if putResp.Organization != "My Org" || putResp.OrganizationalUnit != "Dev" {
		t.Errorf("PUT response = %+v", putResp)
	}

	w = doRequest(t, mux, "GET", "/api/leaf-subject", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", w.Code)
	}
	var getResp certengine.LeafSubjectParams
	if err := json.Unmarshal(w.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	if getResp.Organization != "My Org" || getResp.OrganizationalUnit != "Dev" || getResp.Country != "US" || getResp.Locality != "NYC" || getResp.Province != "NY" {
		t.Errorf("GET response = %+v", getResp)
	}
}

func TestLeafSubject_PutUninitialized(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "PUT", "/api/leaf-subject", `{"organization": "X"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
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

// --- GET /api/ca/install ---

func TestInstallIndex_BeforeInit(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/ca/install", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestInstallIndex_AfterInit(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/ca/install", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var platforms []InstallPlatform
	if err := json.NewDecoder(w.Body).Decode(&platforms); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(platforms) != 3 {
		t.Errorf("expected 3 platforms, got %d", len(platforms))
	}
	// Each should have non-empty fields.
	for _, p := range platforms {
		if p.Platform == "" {
			t.Error("platform name is empty")
		}
		if p.Endpoint == "" {
			t.Error("endpoint is empty")
		}
		if p.Example == "" {
			t.Error("example is empty")
		}
	}
}

// --- GET /api/ca/install/{platform} ---

func TestInstallMacOS_BeforeInit(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/ca/install/macos", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestInstallMacOS_Script(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/ca/install/macos", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "#!/bin/bash") {
		t.Error("macOS script missing shebang")
	}
	if !strings.Contains(body, "security add-trusted-cert") {
		t.Error("macOS script missing security command")
	}
	if !strings.Contains(body, "/api/ca/root.pem") {
		t.Error("macOS script missing root CA download URL")
	}
}

func TestInstallLinux_Script(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/ca/install/linux", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "#!/bin/bash") {
		t.Error("linux script missing shebang")
	}
	if !strings.Contains(body, "update-ca-certificates") {
		t.Error("linux script missing Debian/Ubuntu path")
	}
	if !strings.Contains(body, "update-ca-trust") {
		t.Error("linux script missing RHEL/Fedora path")
	}
	if !strings.Contains(body, "/api/ca/root.pem") {
		t.Error("linux script missing root CA download URL")
	}
}

func TestInstallWindows_Script(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/ca/install/windows", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "X509Store") {
		t.Error("windows script missing certificate store commands")
	}
	if !strings.Contains(body, "/api/ca/root.pem") {
		t.Error("windows script missing root CA download URL")
	}
}

func TestInstallScripts_UseRequestHost(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	// Use a custom Host header to verify scripts embed it.
	req := httptest.NewRequest("GET", "/api/ca/install/macos", nil)
	req.Host = "nas.local:8443"
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "nas.local:8443") {
		t.Error("script does not reference the request host")
	}
}

func TestInstallScripts_XForwardedProto(t *testing.T) {
	h, _ := newInitializedHandler(t)
	h.trustProxy = true // simulate running behind a reverse proxy
	mux := serveMux(h)

	// Behind proxy: X-Forwarded-Proto=https means scripts should use https:// in URLs.
	req := httptest.NewRequest("GET", "/api/ca/install/macos", nil)
	req.Host = "shushtls.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "https://shushtls.example.com") {
		t.Errorf("script behind proxy should use https://, got: %s", body[:min(200, len(body))])
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

func TestAuth_WrongMethod(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/auth", "")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405\nbody: %s", w.Code, w.Body.String())
	}
}

// --- Authentication ---

func newAuthHandler(t *testing.T) (*Handler, *certengine.Engine, *auth.Store) {
	t.Helper()
	dir := t.TempDir()
	engine, err := certengine.New(dir)
	if err != nil {
		t.Fatalf("certengine.New: %v", err)
	}
	authStore, err := auth.NewStore(dir)
	if err != nil {
		t.Fatalf("auth.NewStore: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	hosts := []string{"shushtls.test", "localhost"}
	h := NewHandler(engine, hosts, logger, nil, authStore, false)
	return h, engine, authStore
}

func newInitializedAuthHandler(t *testing.T) (*Handler, *certengine.Engine, *auth.Store) {
	t.Helper()
	h, engine, authStore := newAuthHandler(t)
	if _, err := engine.Initialize([]string{"shushtls.test", "localhost"}, certengine.CAParams{}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	return h, engine, authStore
}

func doAuthRequest(t *testing.T, mux *http.ServeMux, method, path, body, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if user != "" || pass != "" {
		req.SetBasicAuth(user, pass)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func TestAuth_EnableAndProtect(t *testing.T) {
	h, _, _ := newInitializedAuthHandler(t)
	mux := serveMux(h)

	// Enable auth.
	w := doRequest(t, mux, "POST", "/api/auth",
		`{"enabled": true, "username": "admin", "password": "secret123"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("enable auth: status = %d, body = %s", w.Code, w.Body.String())
	}

	// Protected endpoint without creds should 401.
	w = doRequest(t, mux, "GET", "/api/status", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthed status: got %d, want 401", w.Code)
	}

	// Protected endpoint with wrong creds should 401.
	w = doAuthRequest(t, mux, "GET", "/api/status", "", "admin", "wrong")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("bad creds status: got %d, want 401", w.Code)
	}

	// Protected endpoint with correct creds should 200.
	w = doAuthRequest(t, mux, "GET", "/api/status", "", "admin", "secret123")
	if w.Code != http.StatusOK {
		t.Errorf("good creds status: got %d, want 200", w.Code)
	}
}

func TestAuth_UnprotectedEndpoints(t *testing.T) {
	h, engine, _ := newInitializedAuthHandler(t)
	mux := serveMux(h)

	// Issue a cert so we have something to list/download.
	if _, err := engine.IssueCert([]string{"nas.local"}, nil); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// Enable auth.
	w := doRequest(t, mux, "POST", "/api/auth",
		`{"enabled": true, "username": "admin", "password": "s3cret"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("enable auth: status = %d", w.Code)
	}

	// These should remain accessible without creds.
	// Certificate bundle (zip) is protected when auth is on (contains private key).
	unprotected := []string{
		"/api/ca/root.pem",
		"/api/certificates",
		"/api/ca/install",
		"/api/ca/install/macos",
		"/api/ca/install/linux",
		"/api/ca/install/windows",
	}

	for _, path := range unprotected {
		w := doRequest(t, mux, "GET", path, "")
		if w.Code == http.StatusUnauthorized {
			t.Errorf("%s should be unprotected, got 401", path)
		}
	}
}

func TestAuth_BundleDownloadProtected(t *testing.T) {
	h, engine, _ := newInitializedAuthHandler(t)
	mux := serveMux(h)

	if _, err := engine.IssueCert([]string{"nas.local"}, nil); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// Enable auth.
	doRequest(t, mux, "POST", "/api/auth",
		`{"enabled": true, "username": "admin", "password": "s3cret"}`)

	// Zip bundle without creds should 401 (contains key).
	w := doRequest(t, mux, "GET", "/api/certificates/nas.local?type=zip", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthed zip download: got %d, want 401", w.Code)
	}

	// Zip bundle with creds should work.
	w = doAuthRequest(t, mux, "GET", "/api/certificates/nas.local?type=zip", "", "admin", "s3cret")
	if w.Code != http.StatusOK {
		t.Errorf("authed zip download: got %d, want 200", w.Code)
	}
}

func TestAuth_DisableRemovesProtection(t *testing.T) {
	h, _, _ := newInitializedAuthHandler(t)
	mux := serveMux(h)

	// Enable then disable auth.
	doRequest(t, mux, "POST", "/api/auth",
		`{"enabled": true, "username": "admin", "password": "secret123"}`)

	// Must use creds to disable (auth is now active).
	w := doAuthRequest(t, mux, "POST", "/api/auth",
		`{"enabled": false}`, "admin", "secret123")
	if w.Code != http.StatusOK {
		t.Fatalf("disable auth: status = %d, body = %s", w.Code, w.Body.String())
	}

	// Status should now be accessible without creds.
	w = doRequest(t, mux, "GET", "/api/status", "")
	if w.Code != http.StatusOK {
		t.Errorf("status after disable: got %d, want 200", w.Code)
	}
}

func TestAuth_RequiresInit(t *testing.T) {
	h, _, _ := newAuthHandler(t)
	mux := serveMux(h)

	// Auth before init should be rejected.
	w := doRequest(t, mux, "POST", "/api/auth",
		`{"enabled": true, "username": "admin", "password": "secret"}`)
	if w.Code != http.StatusConflict {
		t.Errorf("auth before init: got %d, want 409", w.Code)
	}
}

func TestAuth_MissingFields(t *testing.T) {
	h, _, _ := newInitializedAuthHandler(t)
	mux := serveMux(h)

	// Missing enabled field.
	w := doRequest(t, mux, "POST", "/api/auth", `{"username": "admin"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing enabled: got %d, want 400", w.Code)
	}

	// Enable without username.
	w = doRequest(t, mux, "POST", "/api/auth", `{"enabled": true, "password": "x"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing username: got %d, want 400", w.Code)
	}

	// Enable without password.
	w = doRequest(t, mux, "POST", "/api/auth", `{"enabled": true, "username": "admin"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing password: got %d, want 400", w.Code)
	}
}

// --- POST /api/service-cert ---

func TestSetServiceCert_BeforeInit(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "POST", "/api/service-cert",
		`{"primary_san": "something"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
}

func TestSetServiceCert_EmptySAN(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "POST", "/api/service-cert", `{"primary_san": ""}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestSetServiceCert_InvalidJSON(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "POST", "/api/service-cert", "not json")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestSetServiceCert_NonexistentCert(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "POST", "/api/service-cert",
		`{"primary_san": "nonexistent.local"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400\nbody: %s", w.Code, w.Body.String())
	}
}

func TestSetServiceCert_Success(t *testing.T) {
	h, engine := newInitializedHandler(t)
	mux := serveMux(h)

	// Issue another cert.
	if _, err := engine.IssueCert([]string{"mybox.local"}, nil); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	w := doRequest(t, mux, "POST", "/api/service-cert",
		`{"primary_san": "mybox.local"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\nbody: %s", w.Code, w.Body.String())
	}

	resp := decodeJSON[SetServiceCertResponse](t, w)
	if resp.Cert.PrimarySAN != "mybox.local" {
		t.Errorf("primary_san = %q, want mybox.local", resp.Cert.PrimarySAN)
	}
	if !resp.Cert.IsService {
		t.Error("cert should be marked as service")
	}

	// Engine should reflect the change.
	if engine.ServiceHost() != "mybox.local" {
		t.Errorf("engine host = %q, want mybox.local", engine.ServiceHost())
	}

	// Old cert should still exist — just no longer the service cert.
	if engine.GetCert("shushtls.test") == nil {
		t.Error("old cert should still exist")
	}
}

func TestSetServiceCert_WrongMethod(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/service-cert", "")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", w.Code)
	}
}

func TestSetServiceCert_Protected(t *testing.T) {
	h, engine, _ := newInitializedAuthHandler(t)
	mux := serveMux(h)

	// Issue a cert to designate.
	if _, err := engine.IssueCert([]string{"mybox.local"}, nil); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// Enable auth.
	doRequest(t, mux, "POST", "/api/auth",
		`{"enabled": true, "username": "admin", "password": "secret123"}`)

	// Without creds should 401.
	w := doRequest(t, mux, "POST", "/api/service-cert",
		`{"primary_san": "mybox.local"}`)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthed: got %d, want 401", w.Code)
	}

	// With creds should work.
	w = doAuthRequest(t, mux, "POST", "/api/service-cert",
		`{"primary_san": "mybox.local"}`, "admin", "secret123")
	if w.Code != http.StatusOK {
		t.Errorf("authed: got %d, want 200, body: %s", w.Code, w.Body.String())
	}
}

func TestAuth_NilStoreIgnored(t *testing.T) {
	// With nil auth store, auth endpoints should gracefully refuse.
	h, _ := newInitializedHandler(t) // uses nil auth store
	mux := serveMux(h)

	w := doRequest(t, mux, "POST", "/api/auth",
		`{"enabled": true, "username": "admin", "password": "secret"}`)
	if w.Code != http.StatusConflict {
		t.Errorf("nil store: got %d, want 409", w.Code)
	}

	// Protected endpoints should still work without auth.
	w = doRequest(t, mux, "GET", "/api/status", "")
	if w.Code != http.StatusOK {
		t.Errorf("status with nil store: got %d, want 200", w.Code)
	}
}
