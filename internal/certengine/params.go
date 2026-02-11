// Package certengine implements the core certificate generation and management
// logic for ShushTLS. It has no HTTP or UI concerns — it is the pure
// cryptographic layer.
package certengine

import (
	"crypto/x509"
	"time"
)

// SC-081 cutoff dates (CA/Browser Forum ballot): max leaf validity steps down over time.
var (
	sc081Step1 = time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC) // until: 398 days
	sc081Step2 = time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC) // until: 200 days
	sc081Step3 = time.Date(2029, 3, 15, 0, 0, 0, 0, time.UTC) // until: 100 days
	// after step3: 47 days
)

// SC081MaxLeafValidity returns the maximum leaf certificate validity allowed
// by CA/Browser Forum ballot SC-081 on the given date.
func SC081MaxLeafValidity(at time.Time) time.Duration {
	u := at.UTC()
	switch {
	case u.Before(sc081Step1):
		return 398 * 24 * time.Hour
	case u.Before(sc081Step2):
		return 200 * 24 * time.Hour
	case u.Before(sc081Step3):
		return 100 * 24 * time.Hour
	default:
		return 47 * 24 * time.Hour
	}
}

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

// Validity periods.
const (
	// DefaultCAValidityYears is the default validity for the root CA in years.
	// 25 years. The root CA is the anchor of trust; if it expires,
	// every device needs to re-trust a new one. Make it last.
	DefaultCAValidityYears = 25

	// RootCAValidity is the default root CA validity as a time.Duration.
	// Derived from DefaultCAValidityYears for backward compatibility.
	RootCAValidity = time.Duration(DefaultCAValidityYears) * 365 * 24 * time.Hour // ~25 years

	// LeafCertValidity is how long leaf certificates are valid.
	// CA/Browser Forum ballot SC-081 step-down schedule:
	//   Until  2026-03-15: 398 days
	//   From   2026-03-15: 200 days
	//   From   2027-03-15: 100 days
	//   From   2029-03-15:  47 days
	// Using 200 days now to be safe through the next step-down.
	LeafCertValidity = 200 * 24 * time.Hour // 200 days

	// ServiceCertValidity is how long the ShushTLS service's own leaf
	// certificate is valid. Same as other leaf certs.
	ServiceCertValidity = LeafCertValidity
)

// Default subject fields for the root CA and leaf certs.
const (
	DefaultCAOrganization   = "ShushTLS"
	DefaultCACommonName     = "ShushTLS Root CA"
	DefaultLeafOrganization = "ShushTLS"
)

// LeafSubjectParams holds optional subject fields for leaf certificates.
// Zero values are replaced with defaults via WithDefaults(). Used for
// O, OU, C, L, ST in the certificate subject; CN is always the primary SAN.
type LeafSubjectParams struct {
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Country            string `json:"country,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Province           string `json:"province,omitempty"`
}

// WithDefaults returns a copy with zero-value Organization set to DefaultLeafOrganization.
// Other fields are left empty if not set (pkix.Name allows empty OU, C, L, ST).
func (p LeafSubjectParams) WithDefaults() LeafSubjectParams {
	if p.Organization == "" {
		p.Organization = DefaultLeafOrganization
	}
	return p
}

// DefaultDomain is the default wildcard domain for leaf certificates.
// .local is the conventional suffix for devices on a local network.
const DefaultDomain = "local"

// CAParams holds optional configuration for root CA generation.
// All fields are optional — zero values are replaced with defaults
// via WithDefaults(). Once the CA is generated, these values are
// baked into the certificate permanently.
type CAParams struct {
	// Organization is the O= field in the CA subject.
	// Default: "ShushTLS"
	Organization string `json:"organization,omitempty"`

	// CommonName is the CN= field in the CA subject.
	// Default: "ShushTLS Root CA"
	CommonName string `json:"common_name,omitempty"`

	// ValidityYears is how long the root CA certificate is valid, in years.
	// Default: 25
	ValidityYears int `json:"validity_years,omitempty"`
}

// WithDefaults returns a copy of p with zero-value fields replaced by defaults.
func (p CAParams) WithDefaults() CAParams {
	if p.Organization == "" {
		p.Organization = DefaultCAOrganization
	}
	if p.CommonName == "" {
		p.CommonName = DefaultCACommonName
	}
	if p.ValidityYears <= 0 {
		p.ValidityYears = DefaultCAValidityYears
	}
	return p
}

// RootCAKeyUsages defines the X.509 key usage flags for the root CA.
// CertSign: the CA can sign other certificates.
// CRLSign: included for standards compliance, even though ShushTLS
// does not implement revocation.
const RootCAKeyUsages = x509.KeyUsageCertSign | x509.KeyUsageCRLSign

// LeafKeyUsages defines the X.509 key usage flags for leaf certificates.
// DigitalSignature: required for ECDSA-based TLS handshakes.
// KeyEncipherment is intentionally omitted — it is only valid for RSA keys
// and including it on an ECDSA cert violates RFC 5480, causing macOS to
// flag the certificate as "not standards compliant".
const LeafKeyUsages = x509.KeyUsageDigitalSignature

// LeafExtKeyUsages defines the extended key usage for leaf certificates.
// ServerAuth and ClientAuth — certs can be used for TLS server identity,
// client authentication (mTLS), or both.
var LeafExtKeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
