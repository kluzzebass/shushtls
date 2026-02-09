// Package certengine implements the core certificate generation and management
// logic for ShushTLS. It has no HTTP or UI concerns — it is the pure
// cryptographic layer.
package certengine

import (
	"crypto/x509"
	"time"
)

// Key algorithm. ShushTLS uses ECDSA P-256 for all keys. It's fast, compact,
// and universally supported by modern TLS stacks and browsers.
const (
	// ECDSACurve is the elliptic curve used for all generated keys.
	// P-256 (aka secp256r1 / prime256v1) is the pragmatic choice:
	// broad compatibility, good performance, and more than sufficient
	// security for a home network CA that will never face nation-state
	// adversaries.
	ECDSACurve = "P-256"
)

// Validity periods. These are intentionally long — ShushTLS is designed to
// be set up once and forgotten for years.
const (
	// RootCAValidity is how long the root CA certificate is valid.
	// 25 years. The root CA is the anchor of trust; if it expires,
	// every device needs to re-trust a new one. Make it last.
	RootCAValidity = 25 * 365 * 24 * time.Hour // ~25 years

	// LeafCertValidity is how long wildcard leaf certificates are valid.
	// 10 years. Shorter than the root CA, but still long enough that
	// you shouldn't have to think about it for a decade.
	LeafCertValidity = 10 * 365 * 24 * time.Hour // ~10 years

	// ServiceCertValidity is how long the ShushTLS service's own leaf
	// certificate is valid. Same as other leaf certs.
	ServiceCertValidity = LeafCertValidity
)

// Default subject fields for the root CA.
const (
	DefaultCAOrganization = "ShushTLS"
	DefaultCACommonName   = "ShushTLS Root CA"
)

// DefaultDomain is the default wildcard domain for leaf certificates.
// home.arpa is the IETF-recommended domain for home networks (RFC 8375).
const DefaultDomain = "home.arpa"

// RootCAKeyUsages defines the X.509 key usage flags for the root CA.
// CertSign: the CA can sign other certificates.
// CRLSign: included for standards compliance, even though ShushTLS
// does not implement revocation.
const RootCAKeyUsages = x509.KeyUsageCertSign | x509.KeyUsageCRLSign

// LeafKeyUsages defines the X.509 key usage flags for leaf certificates.
// DigitalSignature: required for ECDSA-based TLS handshakes.
// KeyEncipherment: included for compatibility with RSA key exchange
// (not strictly needed for ECDSA, but harmless and expected by some clients).
const LeafKeyUsages = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment

// LeafExtKeyUsages defines the extended key usage for leaf certificates.
// ServerAuth only — these certs are for TLS servers, not clients.
var LeafExtKeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
