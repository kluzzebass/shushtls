package certengine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
	"time"
)

// LeafCert holds a leaf certificate's private key and certificate.
type LeafCert struct {
	Key  *ecdsa.PrivateKey
	Cert *x509.Certificate
	Raw  []byte // DER-encoded certificate
}

// PrimarySAN returns the first DNS name in the certificate, which is used
// as the unique identifier for this cert in the store.
func (l *LeafCert) PrimarySAN() string {
	if len(l.Cert.DNSNames) > 0 {
		return l.Cert.DNSNames[0]
	}
	return l.Cert.Subject.CommonName
}

// IssueCertificate generates a leaf certificate with the given DNS names,
// signed by the provided CA. The first name in dnsNames becomes the
// primary SAN and the certificate's CommonName. Validity uses LeafCertValidity.
// Subject O/OU/C/L/ST use default leaf subject (Organization only).
//
// If any name contains a wildcard (e.g. "*.home.arpa"), the bare domain
// is automatically added as an additional SAN if not already present.
//
// This is the single entry point for all leaf certificate issuance —
// both wildcards and FQDNs.
func IssueCertificate(ca *CACert, dnsNames []string) (*LeafCert, error) {
	return IssueCertificateWithValidity(ca, dnsNames, LeafCertValidity)
}

// IssueCertificateWithValidity is like IssueCertificate but uses the given
// validity duration (e.g. SC081MaxLeafValidity(time.Now()) for browser-accepted certs).
// Subject uses default leaf params (Organization only).
func IssueCertificateWithValidity(ca *CACert, dnsNames []string, validity time.Duration) (*LeafCert, error) {
	return IssueCertificateWithValidityAndSubject(ca, dnsNames, validity, LeafSubjectParams{}.WithDefaults())
}

// IssueCertificateWithValidityAndSubject is like IssueCertificateWithValidity but
// uses the given subject params for O, OU, C, L, ST; CN is always the primary SAN.
func IssueCertificateWithValidityAndSubject(ca *CACert, dnsNames []string, validity time.Duration, subject LeafSubjectParams) (*LeafCert, error) {
	if len(dnsNames) == 0 {
		return nil, fmt.Errorf("at least one DNS name is required")
	}

	subject = subject.WithDefaults()

	// Expand wildcard SANs: if *.example.com is requested, also include
	// example.com so the bare domain works too.
	expanded := expandWildcardSANs(dnsNames)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate leaf serial: %w", err)
	}

	// Compute SubjectKeyIdentifier per RFC 5280 §4.2.1.2 — SHA-256 hash of
	// the DER-encoded public key bit string. Go only auto-generates this for
	// CA certs, so we must set it explicitly for leaves.
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal leaf public key: %w", err)
	}
	// The PKIX structure wraps the key in a BIT STRING inside a SEQUENCE.
	// We hash the raw BIT STRING value (the actual key bytes).
	var spki struct {
		Algorithm asn1.RawValue
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(pubDER, &spki); err != nil {
		return nil, fmt.Errorf("unmarshal SPKI: %w", err)
	}
	ski := sha256.Sum256(spki.PublicKey.Bytes)

	// Build subject from params; CN is always the primary SAN.
	name := pkix.Name{
		CommonName: dnsNames[0],
	}
	if subject.Organization != "" {
		name.Organization = []string{subject.Organization}
	}
	if subject.OrganizationalUnit != "" {
		name.OrganizationalUnit = []string{subject.OrganizationalUnit}
	}
	if subject.Country != "" {
		name.Country = []string{subject.Country}
	}
	if subject.Locality != "" {
		name.Locality = []string{subject.Locality}
	}
	if subject.Province != "" {
		name.Province = []string{subject.Province}
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      name,
		DNSNames:     expanded,
		NotBefore:             now,
		NotAfter:              now.Add(validity),
		KeyUsage:              LeafKeyUsages,
		ExtKeyUsage:           LeafExtKeyUsages,
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          ski[:],
	}

	// Signed by the CA.
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("create leaf certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}

	return &LeafCert{
		Key:  key,
		Cert: cert,
		Raw:  der,
	}, nil
}

// expandWildcardSANs takes a list of DNS names and, for each wildcard
// entry like "*.example.com", adds the bare domain "example.com" if it
// isn't already in the list.
func expandWildcardSANs(names []string) []string {
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		seen[n] = true
	}

	var result []string
	for _, n := range names {
		result = append(result, n)
		if strings.HasPrefix(n, "*.") {
			bare := n[2:] // "*.example.com" -> "example.com"
			if !seen[bare] {
				result = append(result, bare)
				seen[bare] = true
			}
		}
	}
	return result
}
