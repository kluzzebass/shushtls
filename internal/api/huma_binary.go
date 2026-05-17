package api

import (
	"archive/tar"
	"archive/zip"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"shushtls/internal/certengine"
)

func (h *Handler) registerHumaBinary(api huma.API) {
	bundleAuth := h.humaRequireAuthBundleMiddleware(api)

	huma.Get(api, "/api/ca/root.pem", h.humaCACert,
		op("get-ca-cert", "Download root CA", "Root CA certificate in PEM format."))

	huma.Get(api, "/api/certificates/{san}", h.humaGetCertBundle,
		op("get-certificate-bundle", "Download certificate bundle", "Cert and key as tar (default) or zip."),
		requireAuthOp(bundleAuth))

	huma.Get(api, "/api/ca/install/macos", h.humaInstallMacOS,
		op("install-ca-macos", "macOS CA install script", "Shell script to trust the root CA on macOS."))

	huma.Get(api, "/api/ca/install/linux", h.humaInstallLinux,
		op("install-ca-linux", "Linux CA install script", "Shell script to trust the root CA on Linux."))

	huma.Get(api, "/api/ca/install/windows", h.humaInstallWindows,
		op("install-ca-windows", "Windows CA install script", "PowerShell script to trust the root CA on Windows."))
}

type bytesOutput struct {
	ContentType string `header:"Content-Type"`
	Body        []byte
}

func (h *Handler) humaCACert(_ context.Context, _ *struct{}) (*huma.StreamResponse, error) {
	ca := h.engine.CA()
	if ca == nil {
		return nil, huma.Error404NotFound("root CA does not exist yet — run POST /api/initialize first")
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.Raw,
	})

	return &huma.StreamResponse{
		Body: func(ctx huma.Context) {
			ctx.SetStatus(http.StatusOK)
			ctx.SetHeader("Content-Type", "application/x-pem-file")
			ctx.SetHeader("Content-Disposition", `attachment; filename="shushtls-root-ca.pem"`)
			_, _ = ctx.BodyWriter().Write(pemBlock)
		},
	}, nil
}

type getCertBundleInput struct {
	SAN             string `path:"san" doc:"Primary SAN (hostname) of the certificate"`
	Type            string `query:"type" doc:"Bundle format: tar (default) or zip"`
	Host            string `header:"Host"`
	XForwardedProto string `header:"X-Forwarded-Proto"`
	XForwardedHost  string `header:"X-Forwarded-Host"`
	Forwarded       string `header:"Forwarded"`
}

func (h *Handler) humaGetCertBundle(_ context.Context, input *getCertBundleInput) (*huma.StreamResponse, error) {
	san := input.SAN
	if san == "" {
		return nil, huma.Error400BadRequest("certificate SAN is required in the URL path")
	}

	if err := certengine.ValidateSAN(san); err != nil {
		return nil, huma.Error400BadRequest(fmt.Sprintf("invalid SAN: %v", err))
	}

	which := input.Type
	if which == "" {
		which = "tar"
	}
	if which != "zip" && which != "tar" {
		return nil, huma.Error400BadRequest("use type=zip or type=tar to download cert+key bundle (separate cert/key downloads are not supported)")
	}

	leaf := h.engine.GetCert(san)
	if leaf == nil {
		return nil, huma.Error404NotFound(fmt.Sprintf("no certificate found for %q", san))
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	der, err := x509.MarshalECPrivateKey(leaf.Key)
	if err != nil {
		h.logger.Error("failed to export private key for bundle", "error", err)
		return nil, huma.Error500InternalServerError("failed to export private key for bundle — check server logs for details")
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	base := certengine.SanitizeSAN(san)

	entries := []struct {
		name string
		data []byte
	}{
		{base + ".cert.pem", certPEM},
		{base + ".key.pem", keyPEM},
	}

	switch which {
	case "tar":
		return &huma.StreamResponse{
			Body: func(ctx huma.Context) {
				ctx.SetStatus(http.StatusOK)
				ctx.SetHeader("Content-Type", "application/x-tar")
				ctx.SetHeader("Content-Disposition", fmt.Sprintf("attachment; filename=%q", base+".tar"))
				tw := tar.NewWriter(ctx.BodyWriter())
				for _, entry := range entries {
					_ = tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0644, Size: int64(len(entry.data))})
					_, _ = tw.Write(entry.data)
				}
				_ = tw.Close()
			},
		}, nil
	case "zip":
		return &huma.StreamResponse{
			Body: func(ctx huma.Context) {
				ctx.SetStatus(http.StatusOK)
				ctx.SetHeader("Content-Type", "application/zip")
				ctx.SetHeader("Content-Disposition", fmt.Sprintf("attachment; filename=%q", base+".zip"))
				zw := zip.NewWriter(ctx.BodyWriter())
				for _, entry := range entries {
					fw, _ := zw.Create(entry.name)
					_, _ = fw.Write(entry.data)
				}
				_ = zw.Close()
			},
		}, nil
	default:
		return nil, huma.Error400BadRequest("use type=zip or type=tar")
	}
}

type installScriptInput struct {
	Host            string `header:"Host"`
	XForwardedProto string `header:"X-Forwarded-Proto"`
	XForwardedHost  string `header:"X-Forwarded-Host"`
	Forwarded       string `header:"Forwarded"`
}

func (h *Handler) humaInstallMacOS(_ context.Context, in *installScriptInput) (*bytesOutput, error) {
	return h.installScriptOutput(in, "text/x-shellscript; charset=utf-8", macOSScript)
}

func (h *Handler) humaInstallLinux(_ context.Context, in *installScriptInput) (*bytesOutput, error) {
	return h.installScriptOutput(in, "text/x-shellscript; charset=utf-8", linuxScript)
}

func (h *Handler) humaInstallWindows(_ context.Context, in *installScriptInput) (*bytesOutput, error) {
	return h.installScriptOutput(in, "text/plain; charset=utf-8", windowsScript)
}

func (h *Handler) installScriptOutput(in *installScriptInput, contentType string, tmpl func(string) string) (*bytesOutput, error) {
	if h.engine.CA() == nil {
		return nil, huma.Error404NotFound("root CA does not exist yet — run POST /api/initialize first")
	}
	base := baseURLFromHeaders(in.Host, in.XForwardedProto, in.XForwardedHost, in.Forwarded, h.trustProxy)
	return &bytesOutput{
		ContentType: contentType,
		Body:        []byte(tmpl(base)),
	}, nil
}

func macOSScript(base string) string {
	return fmt.Sprintf(`#!/bin/bash
# ShushTLS Root CA Installer — macOS
# Usage: curl -kfsSL %[1]s/api/ca/install/macos | bash
set -euo pipefail

TMPFILE=$(mktemp /tmp/shushtls-root-ca.XXXXXX)
trap 'rm -f "$TMPFILE"' EXIT

echo "Downloading ShushTLS root CA..."
# -k is needed because the CA isn't trusted yet — that's what we're fixing.
curl -kfsSL -o "$TMPFILE" %[1]s/api/ca/root.pem

echo "Installing into macOS system trust store..."
echo "(You may be prompted for your password.)"
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$TMPFILE"

echo "Done! ShushTLS root CA is now trusted on this Mac."
`, base)
}

func linuxScript(base string) string {
	return fmt.Sprintf(`#!/bin/bash
# ShushTLS Root CA Installer — Linux
# Usage: curl -kfsSL %[1]s/api/ca/install/linux | sudo bash
set -euo pipefail

echo "Downloading ShushTLS root CA..."
# -k is needed because the CA isn't trusted yet — that's what we're fixing.

# Detect distro family and install accordingly.
if command -v update-ca-certificates >/dev/null 2>&1; then
    # Debian / Ubuntu / Alpine
    curl -kfsSL -o /usr/local/share/ca-certificates/shushtls-root-ca.crt %[1]s/api/ca/root.pem
    update-ca-certificates
    echo "Done! Root CA installed via update-ca-certificates."
elif command -v update-ca-trust >/dev/null 2>&1; then
    # RHEL / Fedora / CentOS
    curl -kfsSL -o /etc/pki/ca-trust/source/anchors/shushtls-root-ca.pem %[1]s/api/ca/root.pem
    update-ca-trust extract
    echo "Done! Root CA installed via update-ca-trust."
else
    echo "Error: Could not find update-ca-certificates or update-ca-trust."
    echo "Please install the root CA manually:"
    echo "  curl -kfsSL -o shushtls-root-ca.pem %[1]s/api/ca/root.pem"
    exit 1
fi
`, base)
}

func windowsScript(base string) string {
	return fmt.Sprintf(`# ShushTLS Root CA Installer — Windows (PowerShell)
# Usage: irm -SkipCertificateCheck %[1]s/api/ca/install/windows | iex
# Must be run as Administrator.

$ErrorActionPreference = "Stop"

$tmpFile = Join-Path $env:TEMP "shushtls-root-ca.pem"

Write-Host "Downloading ShushTLS root CA..."
# -SkipCertificateCheck is needed because the CA isn't trusted yet.
Invoke-WebRequest -SkipCertificateCheck -Uri "%[1]s/api/ca/root.pem" -OutFile $tmpFile

Write-Host "Installing into Windows certificate store (LocalMachine\Root)..."
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($tmpFile)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()

Remove-Item $tmpFile -Force
Write-Host "Done! ShushTLS root CA is now trusted on this machine."
`, base)
}

// humaRequireAuthBundleMiddleware enforces Basic auth for cert+key bundle downloads when auth is enabled.
func (h *Handler) humaRequireAuthBundleMiddleware(api huma.API) func(huma.Context, func(huma.Context)) {
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
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "authentication required for certificate bundle download")
			return
		}

		next(ctx)
	}
}
