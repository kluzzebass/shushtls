package acme

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"shushtls/internal/certengine"
)

func TestACME_Directory(t *testing.T) {
	dir := t.TempDir()
	e, err := certengine.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = e.Initialize([]string{"shushtls.test"}, certengine.CAParams{})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	srv := NewServer(e, func(r *http.Request) string { return "https://shushtls.test:8443" }, nil)
	mux := http.NewServeMux()
	srv.Register(mux)

	req := httptest.NewRequest("GET", "https://shushtls.test:8443/acme/directory", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	if body == "" {
		t.Error("empty body")
	}
	if body != "" && body[0] != '{' {
		t.Errorf("body should be JSON object, got %q", body[:min(50, len(body))])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
