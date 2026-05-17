package api

import (
	"context"
	"fmt"

	"github.com/danielgtaylor/huma/v2"

	"shushtls/internal/certengine"
)

func (h *Handler) registerHumaJSON(api huma.API) {
	requireAuth := h.humaRequireAuthMiddleware(api)

	huma.Post(api, "/api/initialize", h.humaInitialize,
		op("initialize", "Initialize ShushTLS", "Create the root CA and service certificate."),
		maxBody, requireAuthOp(requireAuth))

	huma.Get(api, "/api/certificates", h.humaListCerts,
		op("list-certificates", "List certificates", "List all issued certificates."))

	huma.Post(api, "/api/certificates", h.humaIssueCert,
		op("issue-certificate", "Issue certificate", "Register a certificate for the given DNS names."),
		maxBody, requireAuthOp(requireAuth))

	huma.Post(api, "/api/service-cert", h.humaSetServiceCert,
		op("set-service-cert", "Set service certificate", "Designate which certificate secures the ShushTLS UI/API."),
		maxBody, requireAuthOp(requireAuth))

	huma.Post(api, "/api/auth", h.humaAuth,
		op("configure-auth", "Configure authentication", "Enable or disable HTTP Basic authentication."),
		maxBody, requireAuthOp(requireAuth))

	huma.Get(api, "/api/leaf-subject", h.humaGetLeafSubject,
		op("get-leaf-subject", "Get default leaf subject", "Default O, OU, C, L, ST for leaf certificates."),
		requireAuthOp(requireAuth))

	huma.Put(api, "/api/leaf-subject", h.humaSetLeafSubject,
		op("set-leaf-subject", "Set default leaf subject", "Update default subject fields for future leaf certificates."),
		maxBody, requireAuthOp(requireAuth))

	huma.Get(api, "/api/ca/install", h.humaInstallIndex,
		op("list-ca-installers", "List CA install scripts", "Platform install script endpoints and examples."))
}

func op(id, summary, description string) func(*huma.Operation) {
	return func(o *huma.Operation) {
		o.OperationID = id
		o.Summary = summary
		o.Description = description
	}
}

func maxBody(o *huma.Operation) {
	o.MaxBodyBytes = maxRequestBody
}

func requireAuthOp(m func(huma.Context, func(huma.Context))) func(*huma.Operation) {
	return func(o *huma.Operation) {
		o.Middlewares = append(o.Middlewares, m)
	}
}

type initializeInput struct {
	Body *certengine.CAParams `doc:"Optional root CA parameters"`
}

type initializeOutput struct {
	Body InitializeResponse
}

func (h *Handler) humaInitialize(_ context.Context, input *initializeInput) (*initializeOutput, error) {
	caParams := certengine.CAParams{}
	if input != nil && input.Body != nil {
		caParams = *input.Body
	}

	state, err := h.engine.Initialize(h.serviceHosts, caParams)
	if err != nil {
		h.logger.Error("initialization failed", "error", err)
		return nil, huma.Error500InternalServerError("initialization failed — check server logs for details")
	}

	var msg string
	switch state {
	case certengine.Ready:
		msg = "Initialization complete. HTTPS is now active. Download the root CA and install it on your devices."
	case certengine.Initialized:
		msg = "Root CA generated. Service certificate pending."
	default:
		msg = "Unexpected state after initialization."
	}

	h.logger.Info("initialization complete", "state", state.String())

	if state == certengine.Ready && h.onReady != nil {
		h.onReady()
	}

	return &initializeOutput{Body: InitializeResponse{
		State:   state.String(),
		Message: msg,
	}}, nil
}

type listCertsOutput struct {
	Body []LeafCertInfo
}

func (h *Handler) humaListCerts(_ context.Context, _ *struct{}) (*listCertsOutput, error) {
	items := h.engine.ListCerts()

	infos := make([]LeafCertInfo, 0, len(items))
	for _, item := range items {
		info := leafInfoFromItem(item)
		info.IsService = item.PrimarySAN == h.engine.ServiceHost()
		infos = append(infos, info)
	}

	return &listCertsOutput{Body: infos}, nil
}

type issueCertInput struct {
	Body IssueCertRequest
}

type issueCertOutput struct {
	Body IssueCertResponse
}

func (h *Handler) humaIssueCert(_ context.Context, input *issueCertInput) (*issueCertOutput, error) {
	if h.engine.CA() == nil {
		return nil, huma.Error409Conflict("root CA does not exist — run POST /api/initialize first")
	}

	req := input.Body

	if len(req.DNSNames) == 0 {
		return nil, huma.Error400BadRequest("dns_names must contain at least one entry")
	}

	for _, name := range req.DNSNames {
		if err := certengine.ValidateSAN(name); err != nil {
			return nil, huma.Error400BadRequest(fmt.Sprintf("invalid dns_name: %v", err))
		}
	}

	item, err := h.engine.IssueCert(req.DNSNames, req.Subject)
	if err != nil {
		h.logger.Error("certificate issuance failed", "error", err)
		return nil, huma.Error500InternalServerError("certificate issuance failed — check server logs for details")
	}

	info := leafInfoFromItem(item)
	info.IsService = item.PrimarySAN == h.engine.ServiceHost()

	h.logger.Info("certificate issued", "primarySAN", item.PrimarySAN)
	return &issueCertOutput{Body: IssueCertResponse{
		Cert:    info,
		Message: "Certificate issued successfully.",
	}}, nil
}

type setServiceCertInput struct {
	Body SetServiceCertRequest
}

type setServiceCertOutput struct {
	Body SetServiceCertResponse
}

func (h *Handler) humaSetServiceCert(_ context.Context, input *setServiceCertInput) (*setServiceCertOutput, error) {
	if h.engine.State() == certengine.Uninitialized {
		return nil, huma.Error409Conflict("ShushTLS must be initialized first")
	}

	req := input.Body

	if req.PrimarySAN == "" {
		return nil, huma.Error400BadRequest("primary_san is required")
	}

	if err := certengine.ValidateSAN(req.PrimarySAN); err != nil {
		return nil, huma.Error400BadRequest(fmt.Sprintf("invalid primary_san: %v", err))
	}

	if err := h.engine.DesignateServiceCert(req.PrimarySAN); err != nil {
		h.logger.Error("failed to set service cert", "error", err)
		return nil, huma.Error400BadRequest(err.Error())
	}

	info := leafInfo(h.engine.ServiceCert())
	info.IsService = true

	h.logger.Info("service certificate changed", "primarySAN", req.PrimarySAN)

	return &setServiceCertOutput{Body: SetServiceCertResponse{
		Cert:    info,
		Message: "Service certificate updated. New certificate is active immediately.",
	}}, nil
}

type authInput struct {
	Body AuthRequest
}

type authOutput struct {
	Body AuthResponse
}

func (h *Handler) humaAuth(_ context.Context, input *authInput) (*authOutput, error) {
	if h.authStore == nil {
		return nil, huma.Error409Conflict("authentication is not available (no auth store configured)")
	}

	if h.engine.State() == certengine.Uninitialized {
		return nil, huma.Error409Conflict("ShushTLS must be initialized before configuring auth")
	}

	req := input.Body

	if req.Enabled == nil {
		return nil, huma.Error400BadRequest(`"enabled" field is required`)
	}

	if *req.Enabled {
		if req.Username == "" || req.Password == "" {
			return nil, huma.Error400BadRequest("username and password are required when enabling auth")
		}
		if err := h.authStore.Enable(req.Username, req.Password); err != nil {
			h.logger.Error("failed to enable authentication", "error", err)
			return nil, huma.Error500InternalServerError("failed to enable authentication — check server logs for details")
		}
		h.logger.Info("authentication enabled", "username", req.Username)
		return &authOutput{Body: AuthResponse{
			Enabled: true,
			Message: "Authentication enabled.",
		}}, nil
	}

	if err := h.authStore.Disable(); err != nil {
		h.logger.Error("failed to disable authentication", "error", err)
		return nil, huma.Error500InternalServerError("failed to disable authentication — check server logs for details")
	}
	h.logger.Info("authentication disabled")
	return &authOutput{Body: AuthResponse{
		Enabled: false,
		Message: "Authentication disabled.",
	}}, nil
}

type leafSubjectOutput struct {
	Body certengine.LeafSubjectParams
}

func (h *Handler) humaGetLeafSubject(_ context.Context, _ *struct{}) (*leafSubjectOutput, error) {
	return &leafSubjectOutput{Body: h.engine.DefaultLeafSubject()}, nil
}

type setLeafSubjectInput struct {
	Body certengine.LeafSubjectParams
}

func (h *Handler) humaSetLeafSubject(_ context.Context, input *setLeafSubjectInput) (*leafSubjectOutput, error) {
	if h.engine.State() == certengine.Uninitialized {
		return nil, huma.Error409Conflict("ShushTLS must be initialized before setting leaf subject")
	}

	p := input.Body
	if err := h.engine.SetDefaultLeafSubject(p); err != nil {
		h.logger.Error("failed to save leaf subject", "error", err)
		return nil, huma.Error500InternalServerError("failed to save leaf subject — check server logs for details")
	}
	return &leafSubjectOutput{Body: h.engine.DefaultLeafSubject()}, nil
}

type installIndexOutput struct {
	Body []InstallPlatform
}

type installIndexInput struct {
	Host            string `header:"Host"`
	XForwardedProto string `header:"X-Forwarded-Proto"`
	XForwardedHost  string `header:"X-Forwarded-Host"`
	Forwarded       string `header:"Forwarded"`
}

func (h *Handler) humaInstallIndex(_ context.Context, in *installIndexInput) (*installIndexOutput, error) {
	if h.engine.CA() == nil {
		return nil, huma.Error404NotFound("root CA does not exist yet — run POST /api/initialize first")
	}

	base := baseURLFromHeaders(in.Host, in.XForwardedProto, in.XForwardedHost, in.Forwarded, h.trustProxy)
	platforms := []InstallPlatform{
		{
			Platform: "macOS",
			Endpoint: "/api/ca/install/macos",
			Example:  fmt.Sprintf("curl -kfsSL %s/api/ca/install/macos | bash", base),
		},
		{
			Platform: "Linux (Debian/Ubuntu/RHEL/Fedora)",
			Endpoint: "/api/ca/install/linux",
			Example:  fmt.Sprintf("curl -kfsSL %s/api/ca/install/linux | sudo bash", base),
		},
		{
			Platform: "Windows (PowerShell)",
			Endpoint: "/api/ca/install/windows",
			Example:  fmt.Sprintf("irm -SkipCertificateCheck %s/api/ca/install/windows | iex", base),
		},
	}

	return &installIndexOutput{Body: platforms}, nil
}
