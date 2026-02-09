// Package server implements the ShushTLS HTTP/HTTPS server with
// bootstrap-aware serving logic.
package server

// Config holds the configuration for the ShushTLS server.
type Config struct {
	// StateDir is the directory where all persistent state is stored
	// (CA material, issued certificates, etc.).
	StateDir string

	// HTTPAddr is the address to listen on in HTTP mode (before initialization).
	// Example: ":8080" or "0.0.0.0:8080"
	HTTPAddr string

	// HTTPSAddr is the address to listen on in HTTPS mode (after initialization).
	// Example: ":8443" or "0.0.0.0:443"
	HTTPSAddr string

	// ServiceHosts are the DNS names for ShushTLS's own TLS certificate.
	// The first entry is the primary SAN. These are used during initialization
	// to issue the service certificate.
	// Example: ["shushtls.home.arpa", "localhost"]
	ServiceHosts []string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		StateDir:     "./state",
		HTTPAddr:     ":8080",
		HTTPSAddr:    ":8443",
		ServiceHosts: []string{"shushtls.local", "localhost"},
	}
}
