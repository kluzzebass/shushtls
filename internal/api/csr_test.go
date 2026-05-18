package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIssueCert_CSR(t *testing.T) {
	h, _ := newInitializedHandler(t)
	mux := serveMux(h)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "csr.example.com"},
		DNSNames: []string{"csr.example.com"},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	req := httptestPostCSR(t, mux, csrPEM)
	if req.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\nbody: %s", req.Code, req.Body.String())
	}
	block, _ := pem.Decode(req.Body.Bytes())
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("response is not certificate PEM: %s", req.Body.String())
	}

	w := doRequest(t, mux, "GET", "/api/certificates", "")
	var certs []LeafCertInfo
	if err := json.NewDecoder(w.Body).Decode(&certs); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	found := false
	for _, c := range certs {
		if c.PrimarySAN == "csr.example.com" {
			found = true
			if c.CommonName != "csr.example.com" {
				t.Errorf("CN = %q", c.CommonName)
			}
		}
	}
	if !found {
		t.Error("CSR-issued cert not in list")
	}

	w = doRequest(t, mux, "GET", "/api/certificates/csr.example.com?type=tar", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("bundle download for CSR cert: status = %d, want 400", w.Code)
	}
}

func httptestPostCSR(t *testing.T, mux *http.ServeMux, csrPEM []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/certificates", bytes.NewReader(csrPEM))
	req.Header.Set("Content-Type", "application/pkcs10")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}
