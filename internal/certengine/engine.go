package certengine

import (
	"fmt"
	"sort"
)

// State represents the initialization state of the certificate engine.
type State int

const (
	// Uninitialized means no root CA exists. ShushTLS should serve HTTP only.
	Uninitialized State = iota

	// Initialized means the root CA exists but the ShushTLS service cert
	// may or may not exist yet. The user needs to install trust and restart.
	Initialized

	// Ready means the root CA and the ShushTLS service cert are both present.
	// HTTPS serving is possible.
	Ready
)

// String returns a human-readable name for the state.
func (s State) String() string {
	switch s {
	case Uninitialized:
		return "uninitialized"
	case Initialized:
		return "initialized"
	case Ready:
		return "ready"
	default:
		return "unknown"
	}
}

// Engine is the top-level interface to the certificate engine. It wraps
// the store and provides idempotent, high-level operations.
type Engine struct {
	store       *Store
	ca          *CACert                // cached after load/generate
	certs       map[string]*LeafCert   // all issued certs, keyed by primary SAN
	serviceHost string                 // primary SAN of the ShushTLS service cert
}

// New creates a new Engine backed by the given state directory.
// It loads any existing material from disk.
func New(stateDir string) (*Engine, error) {
	store, err := NewStore(stateDir)
	if err != nil {
		return nil, fmt.Errorf("initialize store: %w", err)
	}

	e := &Engine{
		store: store,
		certs: make(map[string]*LeafCert),
	}
	if err := e.load(); err != nil {
		return nil, fmt.Errorf("load existing state: %w", err)
	}
	return e, nil
}

// State returns the current initialization state.
func (e *Engine) State() State {
	if e.ca == nil {
		return Uninitialized
	}
	if e.serviceHost == "" || e.certs[e.serviceHost] == nil {
		return Initialized
	}
	return Ready
}

// Initialize generates the root CA and the ShushTLS service certificate.
// The first entry in serviceHosts becomes the primary SAN used to identify
// the service cert. It is idempotent: existing material is not regenerated.
// Returns the current state after the operation.
func (e *Engine) Initialize(serviceHosts []string) (State, error) {
	if len(serviceHosts) == 0 {
		return e.State(), fmt.Errorf("at least one service hostname is required")
	}

	// Step 1: Root CA
	if e.ca == nil {
		ca, err := GenerateCA()
		if err != nil {
			return e.State(), fmt.Errorf("generate root CA: %w", err)
		}
		if err := e.store.SaveCA(ca); err != nil {
			return e.State(), fmt.Errorf("save root CA: %w", err)
		}
		e.ca = ca
	}

	// Step 2: Service certificate (for ShushTLS's own HTTPS listener)
	e.serviceHost = serviceHosts[0]
	if e.certs[e.serviceHost] == nil {
		leaf, err := IssueCertificate(e.ca, serviceHosts)
		if err != nil {
			return e.State(), fmt.Errorf("generate service cert: %w", err)
		}
		if err := e.store.SaveCert(leaf); err != nil {
			return e.State(), fmt.Errorf("save service cert: %w", err)
		}
		e.certs[e.serviceHost] = leaf
	}

	return e.State(), nil
}

// IssueCert generates a leaf certificate for the given DNS names, signed
// by the root CA. The first name becomes the primary SAN (the key in the
// store). Idempotent: if a cert with the same primary SAN already exists,
// it is returned as-is.
//
// Requires the root CA to exist (State >= Initialized).
func (e *Engine) IssueCert(dnsNames []string) (*LeafCert, error) {
	if e.ca == nil {
		return nil, fmt.Errorf("cannot issue certificate: root CA does not exist (run Initialize first)")
	}
	if len(dnsNames) == 0 {
		return nil, fmt.Errorf("at least one DNS name is required")
	}

	primarySAN := dnsNames[0]
	if existing := e.certs[primarySAN]; existing != nil {
		return existing, nil
	}

	leaf, err := IssueCertificate(e.ca, dnsNames)
	if err != nil {
		return nil, fmt.Errorf("generate cert for %s: %w", primarySAN, err)
	}
	if err := e.store.SaveCert(leaf); err != nil {
		return nil, fmt.Errorf("save cert for %s: %w", primarySAN, err)
	}
	e.certs[primarySAN] = leaf
	return leaf, nil
}

// GetCert returns an issued certificate by its primary SAN, or nil if
// no cert has been issued for that name.
func (e *Engine) GetCert(primarySAN string) *LeafCert {
	return e.certs[primarySAN]
}

// ListCerts returns all issued certificates, sorted by primary SAN.
func (e *Engine) ListCerts() []*LeafCert {
	sans := make([]string, 0, len(e.certs))
	for san := range e.certs {
		sans = append(sans, san)
	}
	sort.Strings(sans)

	result := make([]*LeafCert, 0, len(sans))
	for _, san := range sans {
		result = append(result, e.certs[san])
	}
	return result
}

// CA returns the root CA, or nil if not yet generated.
func (e *Engine) CA() *CACert {
	return e.ca
}

// ServiceCert returns the ShushTLS service leaf cert, or nil if not yet
// generated. This is a convenience accessor — the service cert is just
// a regular issued cert that ShushTLS uses for its own HTTPS listener.
func (e *Engine) ServiceCert() *LeafCert {
	if e.serviceHost == "" {
		return nil
	}
	return e.certs[e.serviceHost]
}

// ServiceHost returns the primary SAN of the service certificate.
func (e *Engine) ServiceHost() string {
	return e.serviceHost
}

// Store returns the underlying store, for direct path queries.
func (e *Engine) Store() *Store {
	return e.store
}

// load reads all existing material from disk into memory.
func (e *Engine) load() error {
	ca, err := e.store.LoadCA()
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}
	e.ca = ca

	certs, err := e.store.LoadAllCerts()
	if err != nil {
		return fmt.Errorf("load certs: %w", err)
	}
	e.certs = certs

	return nil
}

// SetServiceHost sets the primary SAN used to identify the service cert.
// This is called during initialization and can be called after reload
// to re-associate the service cert.
func (e *Engine) SetServiceHost(host string) {
	e.serviceHost = host
}
