package certengine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// CACert holds a root CA's private key and certificate.
type CACert struct {
	Key  *ecdsa.PrivateKey
	Cert *x509.Certificate
	Raw  []byte // DER-encoded certificate
}

// GenerateCA creates a new self-signed root CA certificate and key pair.
// The certificate is valid for RootCAValidity from now.
func GenerateCA() (*CACert, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate CA serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{DefaultCAOrganization},
			CommonName:   DefaultCACommonName,
		},
		NotBefore:             now,
		NotAfter:              now.Add(RootCAValidity),
		KeyUsage:              RootCAKeyUsages,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,    // This CA only signs leaf certs, not intermediate CAs.
		MaxPathLenZero:        true, // Explicitly encode MaxPathLen:0.
	}

	// Self-signed: issuer = subject, signed with own key.
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	return &CACert{
		Key:  key,
		Cert: cert,
		Raw:  der,
	}, nil
}

// randomSerial generates a random 128-bit serial number for a certificate.
// X.509 serial numbers must be positive integers unique per CA. Using
// crypto/rand with 128 bits makes collisions astronomically unlikely
// without needing a counter or database.
func randomSerial() (*big.Int, error) {
	// 128 bits = 16 bytes. Enough entropy to be unique without tracking state.
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("generate random serial: %w", err)
	}
	return serial, nil
}
