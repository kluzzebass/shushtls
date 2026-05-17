package api

import (
	"net/http"
	"testing"
)

func TestRegisterAPI_Docs(t *testing.T) {
	h, _ := newTestHandler(t)
	mux := serveMux(h)

	w := doRequest(t, mux, "GET", "/api/docs", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}
