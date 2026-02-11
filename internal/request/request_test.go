package request

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestScheme(t *testing.T) {
	tests := []struct {
		name   string
		req    *http.Request
		expect string
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
			name: "X-Forwarded-Proto https",
			req: &http.Request{
				Header: http.Header{"X-Forwarded-Proto": {"https"}},
			},
			expect: "https",
		},
		{
			name: "X-Forwarded-Proto http",
			req: &http.Request{
				Header: http.Header{"X-Forwarded-Proto": {"http"}},
			},
			expect: "http",
		},
		{
			name: "X-Forwarded-Proto overrides TLS",
			req: &http.Request{
				TLS:    &tls.ConnectionState{},
				Header: http.Header{"X-Forwarded-Proto": {"http"}},
			},
			expect: "http",
		},
		{
			name: "Forwarded proto=https",
			req: &http.Request{
				Header: http.Header{"Forwarded": {`for=192.0.2.60;proto=https;by=203.0.113.43`}},
			},
			expect: "https",
		},
		{
			name: "Forwarded proto=http",
			req: &http.Request{
				Header: http.Header{"Forwarded": {`proto=http`}},
			},
			expect: "http",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Scheme(tt.req)
			if got != tt.expect {
				t.Errorf("Scheme() = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestHost(t *testing.T) {
	tests := []struct {
		name   string
		req    *http.Request
		expect string
	}{
		{
			name:   "r.Host",
			req:    &http.Request{Host: "shushtls.local:8443"},
			expect: "shushtls.local:8443",
		},
		{
			name: "X-Forwarded-Host",
			req: &http.Request{
				Host:   "localhost:8080",
				Header: http.Header{"X-Forwarded-Host": {"shushtls.example.com"}},
			},
			expect: "shushtls.example.com",
		},
		{
			name: "Forwarded host",
			req: &http.Request{
				Host:   "localhost:8080",
				Header: http.Header{"Forwarded": {`host=shushtls.example.com;proto=https`}},
			},
			expect: "shushtls.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Host(tt.req)
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
	got := BaseURL(req)
	want := "https://shushtls.local:8443"
	if got != want {
		t.Errorf("BaseURL() = %q, want %q", got, want)
	}
}
