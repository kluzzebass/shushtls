package certengine

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"time"
)

// SignCSR signs a certificate signing request with the CA, producing a leaf
// certificate. Uses the public key and subject/DNS names from the CSR.
// Validity follows SC-081. Used by ACME finalize.
func (ca *CACert) SignCSR(csr *x509.CertificateRequest) ([]byte, error) {
	if ca == nil || ca.Cert == nil || ca.Key == nil {
		return nil, fmt.Errorf("CA not initialized")
	}
	if csr == nil {
		return nil, fmt.Errorf("CSR is required")
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	validity := SC081MaxLeafValidity(time.Now())
	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		NotBefore:    now,
		NotAfter:     now.Add(validity),
		KeyUsage:     LeafKeyUsages,
		ExtKeyUsage:  LeafExtKeyUsages,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, csr.PublicKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("sign CSR: %w", err)
	}
	return der, nil
}
