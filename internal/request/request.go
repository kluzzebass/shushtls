// Package request provides helpers for deriving URL components from HTTP
// requests, including when behind an HTTPS-terminating reverse proxy.
package request

import (
	"net/http"
	"strings"
)

// Scheme returns the scheme (http or https) for the request.
// It checks X-Forwarded-Proto and Forwarded (RFC 7239) so the correct scheme
// is used when running behind a reverse proxy that terminates TLS.
func Scheme(r *http.Request) string {
	// X-Forwarded-Proto: de facto standard, most proxies set this.
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		p := strings.TrimSpace(strings.ToLower(proto))
		if p == "https" {
			return "https"
		}
		if p == "http" {
			return "http"
		}
	}
	// Forwarded (RFC 7239): proto="https" or proto=https
	if forwarded := r.Header.Get("Forwarded"); forwarded != "" {
		first := strings.Split(forwarded, ",")[0]
		for _, part := range strings.Split(first, ";") {
			part = strings.TrimSpace(strings.ToLower(part))
			if strings.HasPrefix(part, "proto=") {
				val := strings.Trim(strings.TrimPrefix(part, "proto="), `"`)
				if val == "https" {
					return "https"
				}
				if val == "http" {
					return "http"
				}
				break
			}
		}
	}
	// Direct connection.
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// Host returns the host for URL building. Uses X-Forwarded-Host when set
// (reverse proxy), otherwise r.Host.
func Host(r *http.Request) string {
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		return strings.TrimSpace(h)
	}
	if forwarded := r.Header.Get("Forwarded"); forwarded != "" {
		first := strings.Split(forwarded, ",")[0]
		for _, part := range strings.Split(first, ";") {
			part = strings.TrimSpace(strings.ToLower(part))
			if strings.HasPrefix(part, "host=") {
				val := strings.Trim(strings.TrimPrefix(part, "host="), `"`)
				if val != "" {
					return val
				}
				break
			}
		}
	}
	return r.Host
}

// BaseURL returns scheme://host for self-referencing URLs (e.g. install scripts).
// Respects X-Forwarded-Proto, X-Forwarded-Host, and Forwarded headers.
func BaseURL(r *http.Request) string {
	return Scheme(r) + "://" + Host(r)
}
