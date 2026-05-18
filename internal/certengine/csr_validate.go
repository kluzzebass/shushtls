package certengine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
)

// ParseCSRPEM decodes a PEM-encoded certificate signing request.
func ParseCSRPEM(pemData []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("PEM block type is %q, want CERTIFICATE REQUEST", block.Type)
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// ValidateCSR checks a CSR is acceptable for ShushTLS leaf issuance.
func ValidateCSR(csr *x509.CertificateRequest) error {
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("invalid CSR signature: %w", err)
	}
	if len(csr.DNSNames) == 0 && csr.Subject.CommonName == "" {
		return fmt.Errorf("CSR must include DNS SANs or a subject common name")
	}
	for _, ext := range csr.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 19}) { // id-ce-basicConstraints
			var basic struct {
				IsCA bool `asn1:"optional"`
			}
			if _, err := asn1.Unmarshal(ext.Value, &basic); err == nil && basic.IsCA {
				return fmt.Errorf("CSR must not request a CA certificate")
			}
		}
	}
	switch pub := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() {
			return fmt.Errorf("CSR public key must use P-256 (only ECDSA P-256 leaf certs are supported)")
		}
	default:
		return fmt.Errorf("CSR public key must be ECDSA P-256")
	}
	return nil
}
