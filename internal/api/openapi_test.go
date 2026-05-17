package api

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

func TestOpenAPI_ValidDocument(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/openapi.json", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	body, err := io.ReadAll(w.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	doc, err := loader.LoadFromData(body)
	if err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}
	if err := doc.Validate(context.Background()); err != nil {
		t.Fatalf("validate OpenAPI: %v", err)
	}

	if !strings.HasPrefix(doc.OpenAPI, "3.") {
		t.Errorf("OpenAPI version = %q, want 3.x", doc.OpenAPI)
	}
	if doc.Info == nil || doc.Info.Title != "ShushTLS API" {
		t.Errorf("info.title = %v, want ShushTLS API", doc.Info)
	}
	if doc.ExternalDocs == nil || doc.ExternalDocs.URL != "/acme/directory" {
		t.Errorf("externalDocs = %v, want url /acme/directory", doc.ExternalDocs)
	}
	if doc.Components == nil || doc.Components.SecuritySchemes["basicAuth"] == nil {
		t.Error("missing components.securitySchemes.basicAuth")
	}

	wantPaths := []string{
		"/api/status",
		"/api/initialize",
		"/api/certificates",
		"/api/certificates/{san}",
		"/api/service-cert",
		"/api/auth",
		"/api/leaf-subject",
		"/api/ca/root.pem",
		"/api/ca/install",
		"/api/ca/install/macos",
		"/api/ca/install/linux",
		"/api/ca/install/windows",
	}
	for _, path := range wantPaths {
		if doc.Paths.Find(path) == nil {
			t.Errorf("paths missing %s", path)
		}
	}
}

func TestOpenAPI_YAMLEndpoint(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/openapi.yaml", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	body, err := io.ReadAll(w.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	s := string(body)
	if !strings.Contains(s, "openapi:") && !strings.Contains(s, "ShushTLS API") {
		t.Errorf("unexpected yaml body prefix: %q", s[:min(120, len(s))])
	}
}
