package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestRegisterAPI_OpenAPI(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/openapi.json", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\nbody: %s", w.Code, w.Body.String())
	}

	var doc struct {
		OpenAPI string `json:"openapi"`
		Info    struct {
			Title string `json:"title"`
		} `json:"info"`
		Paths map[string]any `json:"paths"`
	}
	if err := json.NewDecoder(w.Body).Decode(&doc); err != nil {
		t.Fatalf("decode OpenAPI: %v", err)
	}
	if doc.OpenAPI == "" {
		t.Error("openapi version missing")
	}
	if doc.Info.Title != "ShushTLS API" {
		t.Errorf("title = %q, want ShushTLS API", doc.Info.Title)
	}
	for _, path := range []string{
		"/api/status",
		"/api/initialize",
		"/api/certificates",
		"/api/leaf-subject",
	} {
		if doc.Paths[path] == nil {
			t.Errorf("paths missing %s", path)
		}
	}
}

func TestRegisterAPI_Docs(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/docs", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}
