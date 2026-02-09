package certengine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
// primary SAN and the certificate's CommonName.
//
// If any name contains a wildcard (e.g. "*.home.arpa"), the bare domain
// is automatically added as an additional SAN if not already present.
//
// This is the single entry point for all leaf certificate issuance —
// both wildcards and FQDNs.
func IssueCertificate(ca *CACert, dnsNames []string) (*LeafCert, error) {
	if len(dnsNames) == 0 {
		return nil, fmt.Errorf("at least one DNS name is required")
	}

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

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{DefaultCAOrganization},
			CommonName:   dnsNames[0],
		},
		DNSNames:              expanded,
		NotBefore:             now,
		NotAfter:              now.Add(LeafCertValidity),
		KeyUsage:              LeafKeyUsages,
		ExtKeyUsage:           LeafExtKeyUsages,
		BasicConstraintsValid: true,
		IsCA:                  false,
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
