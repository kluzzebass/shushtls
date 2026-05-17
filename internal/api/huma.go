package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"shushtls/internal/request"
	"shushtls/internal/version"
)

// RegisterAPI wires the Huma API on mux and registers all REST operations.
func (h *Handler) RegisterAPI(mux *http.ServeMux) huma.API {
	cfg := huma.DefaultConfig("ShushTLS API", version.Version)
	cfg.DocsPath = "/api/docs"
	cfg.OpenAPIPath = "/api/openapi"
	cfg.SchemasPath = "/api/schemas"

	api := humago.New(mux, cfg)

	h.registerHumaStatus(api)
	h.registerHumaJSON(api)
	h.registerHumaBinary(api)

	return api
}

func (h *Handler) registerHumaStatus(api huma.API) {
	requireAuth := h.humaRequireAuthMiddleware(api)

	huma.Get(api, "/api/status", func(_ context.Context, _ *struct{}) (*statusOutput, error) {
		return &statusOutput{Body: h.buildStatusResponse()}, nil
	}, func(o *huma.Operation) {
		o.OperationID = "get-status"
		o.Summary = "Server and certificate status"
		o.Description = "Returns engine state, serving mode, root CA metadata, and issued certificates."
		o.Middlewares = huma.Middlewares{requireAuth}
	})
}

// statusOutput is the Huma response wrapper for GET /api/status.
type statusOutput struct {
	Body StatusResponse
}

func (h *Handler) buildStatusResponse() StatusResponse {
	state := h.engine.State()

	resp := StatusResponse{
		State:       state.String(),
		ServingMode: servingMode(state),
	}

	if ca := h.engine.CA(); ca != nil {
		resp.RootCA = certInfo(ca.Cert)
	}

	for _, item := range h.engine.ListCerts() {
		info := leafInfoFromItem(item)
		info.IsService = item.PrimarySAN == h.engine.ServiceHost()
		resp.Certs = append(resp.Certs, info)
	}

	return resp
}

// baseURLFromHeaders builds scheme://host from header values (for Huma handlers without *http.Request).
func baseURLFromHeaders(host, xForwardedProto, xForwardedHost, forwarded string, trustProxy bool) string {
	r := &http.Request{Host: host, Header: http.Header{}}
	if xForwardedProto != "" {
		r.Header.Set("X-Forwarded-Proto", xForwardedProto)
	}
	if xForwardedHost != "" {
		r.Header.Set("X-Forwarded-Host", xForwardedHost)
	}
	if forwarded != "" {
		r.Header.Set("Forwarded", forwarded)
	}
	return request.BaseURL(r, trustProxy)
}

// humaRequireAuthMiddleware returns middleware that enforces HTTP Basic auth when enabled.
func (h *Handler) humaRequireAuthMiddleware(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if h.authStore == nil || !h.authStore.IsEnabled() {
			next(ctx)
			return
		}

		r, _ := humago.Unwrap(ctx)
		username, password, ok := r.BasicAuth()
		if !ok || !h.authStore.Verify(username, password) {
			h.logger.Warn("authentication failed", "remote", r.RemoteAddr, "path", r.URL.Path)
			ctx.SetHeader("WWW-Authenticate", `Basic realm="ShushTLS"`)
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "authentication required")
			return
		}

		next(ctx)
	}
}
