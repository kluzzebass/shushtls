package api

import (
	"io"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
)

func (h *Handler) issueCertCSRMiddleware(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if ctx.Operation().OperationID != "issue-certificate" || ctx.Method() != http.MethodPost {
			next(ctx)
			return
		}

		r, w := humago.Unwrap(ctx)
		if !isCSRRequest(r) {
			next(ctx)
			return
		}

		if h.authStore != nil && h.authStore.IsEnabled() {
			username, password, ok := r.BasicAuth()
			if !ok || !h.authStore.Verify(username, password) {
				ctx.SetHeader("WWW-Authenticate", `Basic realm="ShushTLS"`)
				_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "authentication required")
				return
			}
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusBadRequest, "failed to read CSR body")
			return
		}

		if h.engine.CA() == nil {
			_ = huma.WriteErr(api, ctx, http.StatusConflict, "root CA does not exist — run POST /api/initialize first")
			return
		}

		leaf, err := h.engine.IssueCSR(body)
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusBadRequest, err.Error())
			return
		}

		pemBlock := pemEncodeCert(leaf.Raw)
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pemBlock)
	}
}

func isCSRRequest(r *http.Request) bool {
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(ct, "pkcs10") {
		return true
	}
	if strings.Contains(ct, "application/x-pem-file") {
		return true
	}
	if strings.Contains(ct, "pem") && !strings.Contains(ct, "json") {
		return true
	}
	return false
}
