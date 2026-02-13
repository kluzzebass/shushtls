package request

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestScheme(t *testing.T) {
	tests := []struct {
		name       string
		req        *http.Request
		trustProxy bool
		expect     string
	}{
		{
			name:   "direct TLS",
			req:    &http.Request{TLS: &tls.ConnectionState{}},
			expect: "https",
		},
		{
			name:   "direct HTTP",
			req:    &http.Request{},
			expect: "http",
		},
		{
			name: "X-Forwarded-Proto https (trusted)",
			req: &http.Request{
				Header: http.Header{"X-Forwarded-Proto": {"https"}},
			},
			trustProxy: true,
			expect:     "https",
		},
		{
			name: "X-Forwarded-Proto https (untrusted)",
			req: &http.Request{
				Header: http.Header{"X-Forwarded-Proto": {"https"}},
			},
			trustProxy: false,
			expect:     "http",
		},
		{
			name: "X-Forwarded-Proto http (trusted)",
			req: &http.Request{
				Header: http.Header{"X-Forwarded-Proto": {"http"}},
			},
			trustProxy: true,
			expect:     "http",
		},
		{
			name: "X-Forwarded-Proto overrides TLS (trusted)",
			req: &http.Request{
				TLS:    &tls.ConnectionState{},
				Header: http.Header{"X-Forwarded-Proto": {"http"}},
			},
			trustProxy: true,
			expect:     "http",
		},
		{
			name: "X-Forwarded-Proto ignored when untrusted",
			req: &http.Request{
				TLS:    &tls.ConnectionState{},
				Header: http.Header{"X-Forwarded-Proto": {"http"}},
			},
			trustProxy: false,
			expect:     "https",
		},
		{
			name: "Forwarded proto=https (trusted)",
			req: &http.Request{
				Header: http.Header{"Forwarded": {`for=192.0.2.60;proto=https;by=203.0.113.43`}},
			},
			trustProxy: true,
			expect:     "https",
		},
		{
			name: "Forwarded proto=http (trusted)",
			req: &http.Request{
				Header: http.Header{"Forwarded": {`proto=http`}},
			},
			trustProxy: true,
			expect:     "http",
		},
		{
			name: "Forwarded ignored when untrusted",
			req: &http.Request{
				Header: http.Header{"Forwarded": {`proto=https`}},
			},
			trustProxy: false,
			expect:     "http",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Scheme(tt.req, tt.trustProxy)
			if got != tt.expect {
				t.Errorf("Scheme() = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestHost(t *testing.T) {
	tests := []struct {
		name       string
		req        *http.Request
		trustProxy bool
		expect     string
	}{
		{
			name:   "r.Host",
			req:    &http.Request{Host: "shushtls.local:8443"},
			expect: "shushtls.local:8443",
		},
		{
			name: "X-Forwarded-Host (trusted)",
			req: &http.Request{
				Host:   "localhost:8080",
				Header: http.Header{"X-Forwarded-Host": {"shushtls.example.com"}},
			},
			trustProxy: true,
			expect:     "shushtls.example.com",
		},
		{
			name: "X-Forwarded-Host (untrusted)",
			req: &http.Request{
				Host:   "localhost:8080",
				Header: http.Header{"X-Forwarded-Host": {"evil.com"}},
			},
			trustProxy: false,
			expect:     "localhost:8080",
		},
		{
			name: "Forwarded host (trusted)",
			req: &http.Request{
				Host:   "localhost:8080",
				Header: http.Header{"Forwarded": {`host=shushtls.example.com;proto=https`}},
			},
			trustProxy: true,
			expect:     "shushtls.example.com",
		},
		{
			name: "Forwarded host (untrusted)",
			req: &http.Request{
				Host:   "localhost:8080",
				Header: http.Header{"Forwarded": {`host=evil.com;proto=https`}},
			},
			trustProxy: false,
			expect:     "localhost:8080",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Host(tt.req, tt.trustProxy)
			if got != tt.expect {
				t.Errorf("Host() = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestBaseURL(t *testing.T) {
	req := &http.Request{
		Host:   "shushtls.local:8443",
		Header: http.Header{"X-Forwarded-Proto": {"https"}},
	}
	got := BaseURL(req, true)
	want := "https://shushtls.local:8443"
	if got != want {
		t.Errorf("BaseURL() = %q, want %q", got, want)
	}

	// Without trust, X-Forwarded-Proto should be ignored.
	got = BaseURL(req, false)
	want = "http://shushtls.local:8443"
	if got != want {
		t.Errorf("BaseURL(trustProxy=false) = %q, want %q", got, want)
	}
}
