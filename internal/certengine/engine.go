package certengine

import (
	"fmt"
	"sort"
	"time"
)

// CertListItem is one entry in the certificate list: either a stored cert
// (e.g. service cert) or a registered SAN config (cert generated on download).
type CertListItem struct {
	Leaf       *LeafCert // nil for on-demand certs
	PrimarySAN string
	DNSNames   []string
}

// NotAfter returns the cert expiry for display; zero time means "generated on download".
func (c *CertListItem) NotAfter() time.Time {
	if c.Leaf != nil && c.Leaf.Cert != nil {
		return c.Leaf.Cert.NotAfter
	}
	return time.Time{}
}

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
	certs       map[string]*LeafCert   // stored certs (service + legacy), keyed by primary SAN
	configs     map[string][]string    // registered SAN configs (on-demand), keyed by primary SAN
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
		store:   store,
		certs:   make(map[string]*LeafCert),
		configs: make(map[string][]string),
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
// the service cert. The caParams argument configures the root CA's subject
// and validity; zero-value fields use defaults (see CAParams.WithDefaults).
// CAParams are only used when creating a new CA — if the CA already exists,
// they are ignored (idempotency). Returns the current state after the operation.
func (e *Engine) Initialize(serviceHosts []string, caParams CAParams) (State, error) {
	if len(serviceHosts) == 0 {
		return e.State(), fmt.Errorf("at least one service hostname is required")
	}

	// Step 1: Root CA
	if e.ca == nil {
		ca, err := GenerateCA(caParams)
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
		leaf, err := IssueCertificateWithValidity(e.ca, serviceHosts, SC081MaxLeafValidity(time.Now()))
		if err != nil {
			return e.State(), fmt.Errorf("generate service cert: %w", err)
		}
		if err := e.store.SaveCert(leaf); err != nil {
			return e.State(), fmt.Errorf("save service cert: %w", err)
		}
		e.certs[e.serviceHost] = leaf
	}

	// Persist the service host choice.
	if err := e.store.SaveServiceHost(e.serviceHost); err != nil {
		return e.State(), fmt.Errorf("persist service host: %w", err)
	}

	return e.State(), nil
}

// IssueCert registers a leaf certificate for the given DNS names. For the
// service cert (during Initialize) a cert is generated and stored. For all
// other SANs only the SAN config is persisted; the cert is generated on download
// with SC-081 validity. Idempotent: if the primary SAN is already registered,
// returns a list item (stored cert or stub for on-demand).
//
// Requires the root CA to exist (State >= Initialized).
func (e *Engine) IssueCert(dnsNames []string) (*CertListItem, error) {
	if e.ca == nil {
		return nil, fmt.Errorf("cannot issue certificate: root CA does not exist (run Initialize first)")
	}
	if len(dnsNames) == 0 {
		return nil, fmt.Errorf("at least one DNS name is required")
	}

	primarySAN := dnsNames[0]

	// Service cert: generate and store (only when created during Initialize).
	if primarySAN == e.serviceHost {
		if existing := e.certs[primarySAN]; existing != nil {
			return &CertListItem{Leaf: existing, PrimarySAN: primarySAN, DNSNames: existing.Cert.DNSNames}, nil
		}
		leaf, err := IssueCertificateWithValidity(e.ca, dnsNames, SC081MaxLeafValidity(time.Now()))
		if err != nil {
			return nil, fmt.Errorf("generate service cert: %w", err)
		}
		if err := e.store.SaveCert(leaf); err != nil {
			return nil, fmt.Errorf("save service cert: %w", err)
		}
		e.certs[primarySAN] = leaf
		return &CertListItem{Leaf: leaf, PrimarySAN: primarySAN, DNSNames: leaf.Cert.DNSNames}, nil
	}

	// Non-service: already have stored cert (legacy)?
	if existing := e.certs[primarySAN]; existing != nil {
		return &CertListItem{Leaf: existing, PrimarySAN: primarySAN, DNSNames: existing.Cert.DNSNames}, nil
	}
	// Already registered as on-demand?
	if dns, ok := e.configs[primarySAN]; ok {
		return &CertListItem{PrimarySAN: primarySAN, DNSNames: dns}, nil
	}
	// Register SAN config only (expanded so generated certs match); cert generated on download.
	expanded := expandWildcardSANs(dnsNames)
	if err := e.store.SaveSANConfig(primarySAN, expanded); err != nil {
		return nil, fmt.Errorf("save SAN config for %s: %w", primarySAN, err)
	}
	e.configs[primarySAN] = expanded
	return &CertListItem{PrimarySAN: primarySAN, DNSNames: expanded}, nil
}

// GetCert returns a certificate for the given primary SAN for download.
// For the service cert or any stored (legacy) cert, returns the stored cert.
// For registered on-demand SANs, generates a fresh cert with SC-081 validity
// and returns it (not persisted). Returns nil if the SAN is not registered.
func (e *Engine) GetCert(primarySAN string) *LeafCert {
	if leaf := e.certs[primarySAN]; leaf != nil {
		return leaf
	}
	dnsNames, err := e.store.LoadSANConfig(primarySAN)
	if err != nil || len(dnsNames) == 0 {
		return nil
	}
	leaf, err := IssueCertificateWithValidity(e.ca, dnsNames, SC081MaxLeafValidity(time.Now()))
	if err != nil {
		return nil
	}
	return leaf
}

// ListCerts returns all certificates and registered SAN configs, sorted by primary SAN.
// Stored certs (e.g. service) have Leaf set; on-demand entries have Leaf nil.
func (e *Engine) ListCerts() []*CertListItem {
	seen := make(map[string]bool)
	var sans []string
	for san := range e.certs {
		seen[san] = true
		sans = append(sans, san)
	}
	for san := range e.configs {
		if !seen[san] {
			seen[san] = true
			sans = append(sans, san)
		}
	}
	sort.Strings(sans)

	result := make([]*CertListItem, 0, len(sans))
	for _, san := range sans {
		if leaf := e.certs[san]; leaf != nil {
			result = append(result, &CertListItem{Leaf: leaf, PrimarySAN: san, DNSNames: leaf.Cert.DNSNames})
		} else {
			result = append(result, &CertListItem{PrimarySAN: san, DNSNames: e.configs[san]})
		}
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

	configs, err := e.store.LoadAllSANConfigs()
	if err != nil {
		return fmt.Errorf("load SAN configs: %w", err)
	}
	for san, names := range configs {
		// Only add if we don't already have a stored cert for this SAN.
		if e.certs[san] == nil {
			e.configs[san] = names
		}
	}

	// Restore persisted service host choice.
	if host := e.store.LoadServiceHost(); host != "" {
		e.serviceHost = host
	}

	// Rotate service cert if it exceeds current SC-081 max validity (e.g. after a step-down date).
	if e.serviceHost != "" && e.certs[e.serviceHost] != nil {
		svc := e.certs[e.serviceHost]
		now := time.Now()
		maxValidity := SC081MaxLeafValidity(now)
		remaining := svc.Cert.NotAfter.Sub(now)
		if remaining > maxValidity {
			dnsNames := svc.Cert.DNSNames
			newLeaf, err := IssueCertificateWithValidity(e.ca, dnsNames, maxValidity)
			if err != nil {
				return fmt.Errorf("rotate service cert: %w", err)
			}
			if err := e.store.SaveCert(newLeaf); err != nil {
				return fmt.Errorf("save rotated service cert: %w", err)
			}
			e.certs[e.serviceHost] = newLeaf
		}
	}

	return nil
}

// DesignateServiceCert sets the certificate for primarySAN as the service
// cert used by ShushTLS's HTTPS listener. If that SAN has a stored cert
// (legacy or already designated), it is used. If it is only registered as
// on-demand, a cert is generated with SC-081 validity and stored so the
// listener can use it. The choice is persisted to disk so it survives restarts.
func (e *Engine) DesignateServiceCert(primarySAN string) error {
	if e.ca == nil {
		return fmt.Errorf("cannot set service cert: root CA does not exist")
	}
	if e.certs[primarySAN] == nil {
		// On-demand SAN: generate and store a service cert so we have one to serve.
		dnsNames, err := e.store.LoadSANConfig(primarySAN)
		if err != nil || len(dnsNames) == 0 {
			return fmt.Errorf("no certificate found for %q", primarySAN)
		}
		leaf, err := IssueCertificateWithValidity(e.ca, dnsNames, SC081MaxLeafValidity(time.Now()))
		if err != nil {
			return fmt.Errorf("generate service cert for %s: %w", primarySAN, err)
		}
		if err := e.store.SaveCert(leaf); err != nil {
			return fmt.Errorf("save service cert: %w", err)
		}
		e.certs[primarySAN] = leaf
	}

	e.serviceHost = primarySAN

	// Persist the choice so it survives restarts.
	if err := e.store.SaveServiceHost(primarySAN); err != nil {
		return fmt.Errorf("persist service host: %w", err)
	}

	return nil
}

// SetServiceHost sets the primary SAN used to identify the service cert.
// This is called during initialization and can be called after reload
// to re-associate the service cert.
func (e *Engine) SetServiceHost(host string) {
	e.serviceHost = host
}
