package certengine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"
)

// LeafCert holds a leaf certificate's private key and certificate.
type LeafCert struct {
	Key  *ecdsa.PrivateKey
	Cert *x509.Certificate
	Raw  []byte // DER-encoded certificate
}

// IssueWildcard generates a wildcard leaf certificate for the given domain,
// signed by the provided CA. The resulting certificate covers *.domain
// (e.g. *.home.arpa) and the bare domain itself.
func IssueWildcard(ca *CACert, domain string) (*LeafCert, error) {
	return issueLeaf(ca, domain, LeafCertValidity)
}

// IssueServiceCert generates a leaf certificate for a specific hostname,
// signed by the provided CA. This is used for the ShushTLS service itself.
func IssueServiceCert(ca *CACert, hostnames ...string) (*LeafCert, error) {
	if len(hostnames) == 0 {
		return nil, fmt.Errorf("at least one hostname is required")
	}
	return issueLeafForHosts(ca, hostnames, ServiceCertValidity)
}

// issueLeaf creates a wildcard leaf certificate for the given domain.
func issueLeaf(ca *CACert, domain string, validity time.Duration) (*LeafCert, error) {
	// Wildcard SAN covers *.domain; include the bare domain too
	// so that https://home.arpa also works.
	hosts := []string{
		"*." + domain,
		domain,
	}
	return issueLeafForHosts(ca, hosts, validity)
}

// issueLeafForHosts creates a leaf certificate with the given DNS SANs.
func issueLeafForHosts(ca *CACert, dnsNames []string, validity time.Duration) (*LeafCert, error) {
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
		DNSNames:              dnsNames,
		NotBefore:             now,
		NotAfter:              now.Add(validity),
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
