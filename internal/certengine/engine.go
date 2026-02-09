package certengine

import (
	"fmt"
)

// State represents the initialization state of the certificate engine.
type State int

const (
	// Uninitialized means no root CA exists. ShushTLS should serve HTTP only.
	Uninitialized State = iota

	// Initialized means the root CA exists but the ShushTLS service cert
	// may or may not exist yet. The user needs to install trust and restart.
	Initialized

	// Ready means all material is present for HTTPS serving.
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
	store *Store
	ca    *CACert    // cached after load/generate
	wild  *LeafCert  // cached wildcard cert
	svc   *LeafCert  // cached service cert
}

// New creates a new Engine backed by the given state directory.
// It loads any existing material from disk.
func New(stateDir string) (*Engine, error) {
	store, err := NewStore(stateDir)
	if err != nil {
		return nil, fmt.Errorf("initialize store: %w", err)
	}

	e := &Engine{store: store}
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
	if e.svc == nil {
		return Initialized
	}
	return Ready
}

// Initialize generates the root CA and the ShushTLS service certificate.
// It is idempotent: if material already exists, it is not regenerated.
// Returns the current state after the operation.
func (e *Engine) Initialize(serviceHosts []string) (State, error) {
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
	if e.svc == nil {
		svc, err := IssueServiceCert(e.ca, serviceHosts...)
		if err != nil {
			return e.State(), fmt.Errorf("generate service cert: %w", err)
		}
		if err := e.store.SaveServiceCert(svc); err != nil {
			return e.State(), fmt.Errorf("save service cert: %w", err)
		}
		e.svc = svc
	}

	return e.State(), nil
}

// GenerateWildcard issues a wildcard certificate for the given domain.
// Idempotent: if a wildcard cert already exists, it is not regenerated.
// Requires the root CA to exist (State >= Initialized).
func (e *Engine) GenerateWildcard(domain string) (*LeafCert, error) {
	if e.ca == nil {
		return nil, fmt.Errorf("cannot issue wildcard: root CA does not exist (run Initialize first)")
	}

	if e.wild != nil {
		return e.wild, nil
	}

	wild, err := IssueWildcard(e.ca, domain)
	if err != nil {
		return nil, fmt.Errorf("generate wildcard cert: %w", err)
	}
	if err := e.store.SaveWildcard(wild); err != nil {
		return nil, fmt.Errorf("save wildcard cert: %w", err)
	}
	e.wild = wild
	return wild, nil
}

// CA returns the root CA, or nil if not yet generated.
func (e *Engine) CA() *CACert {
	return e.ca
}

// Wildcard returns the wildcard leaf cert, or nil if not yet generated.
func (e *Engine) Wildcard() *LeafCert {
	return e.wild
}

// ServiceCert returns the service leaf cert, or nil if not yet generated.
func (e *Engine) ServiceCert() *LeafCert {
	return e.svc
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

	wild, err := e.store.LoadWildcard()
	if err != nil {
		return fmt.Errorf("load wildcard: %w", err)
	}
	e.wild = wild

	svc, err := e.store.LoadServiceCert()
	if err != nil {
		return fmt.Errorf("load service cert: %w", err)
	}
	e.svc = svc

	return nil
}
