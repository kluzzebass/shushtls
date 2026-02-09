package certengine

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// On-disk layout within the state directory:
//
//   <stateDir>/
//     ca/
//       ca-key.pem       (0600)
//       ca-cert.pem      (0644)
//     certs/
//       wildcard-key.pem  (0600)
//       wildcard-cert.pem (0644)
//       service-key.pem   (0600)
//       service-cert.pem  (0644)

const (
	caDirName   = "ca"
	certDirName = "certs"

	caKeyFile  = "ca-key.pem"
	caCertFile = "ca-cert.pem"

	wildcardKeyFile  = "wildcard-key.pem"
	wildcardCertFile = "wildcard-cert.pem"

	serviceKeyFile  = "service-key.pem"
	serviceCertFile = "service-cert.pem"

	dirPerms     = 0700
	keyFilePerms = 0600
	certPerms    = 0644
)

// Store handles reading and writing certificate material to disk.
type Store struct {
	dir string // root state directory
}

// NewStore creates a Store rooted at the given directory. The directory
// and its subdirectories are created if they don't exist.
func NewStore(dir string) (*Store, error) {
	for _, sub := range []string{caDirName, certDirName} {
		if err := os.MkdirAll(filepath.Join(dir, sub), dirPerms); err != nil {
			return nil, fmt.Errorf("create state directory %s: %w", sub, err)
		}
	}
	return &Store{dir: dir}, nil
}

// --- Write operations ---

// SaveCA writes the root CA key and certificate to disk.
func (s *Store) SaveCA(ca *CACert) error {
	keyPath := filepath.Join(s.dir, caDirName, caKeyFile)
	certPath := filepath.Join(s.dir, caDirName, caCertFile)

	if err := writeKey(keyPath, ca.Key); err != nil {
		return fmt.Errorf("save CA key: %w", err)
	}
	if err := writeCert(certPath, ca.Raw); err != nil {
		return fmt.Errorf("save CA cert: %w", err)
	}
	return nil
}

// SaveWildcard writes the wildcard leaf key and certificate to disk.
func (s *Store) SaveWildcard(leaf *LeafCert) error {
	keyPath := filepath.Join(s.dir, certDirName, wildcardKeyFile)
	certPath := filepath.Join(s.dir, certDirName, wildcardCertFile)

	if err := writeKey(keyPath, leaf.Key); err != nil {
		return fmt.Errorf("save wildcard key: %w", err)
	}
	if err := writeCert(certPath, leaf.Raw); err != nil {
		return fmt.Errorf("save wildcard cert: %w", err)
	}
	return nil
}

// SaveServiceCert writes the ShushTLS service leaf key and certificate to disk.
func (s *Store) SaveServiceCert(leaf *LeafCert) error {
	keyPath := filepath.Join(s.dir, certDirName, serviceKeyFile)
	certPath := filepath.Join(s.dir, certDirName, serviceCertFile)

	if err := writeKey(keyPath, leaf.Key); err != nil {
		return fmt.Errorf("save service key: %w", err)
	}
	if err := writeCert(certPath, leaf.Raw); err != nil {
		return fmt.Errorf("save service cert: %w", err)
	}
	return nil
}

// --- Read operations ---

// LoadCA loads the root CA key and certificate from disk.
// Returns nil, nil if the CA material does not exist yet.
func (s *Store) LoadCA() (*CACert, error) {
	keyPath := filepath.Join(s.dir, caDirName, caKeyFile)
	certPath := filepath.Join(s.dir, caDirName, caCertFile)

	if !fileExists(keyPath) || !fileExists(certPath) {
		return nil, nil
	}

	key, err := readKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load CA key: %w", err)
	}
	raw, cert, err := readCert(certPath)
	if err != nil {
		return nil, fmt.Errorf("load CA cert: %w", err)
	}

	if err := validateKeyMatchesCert(key, cert); err != nil {
		return nil, fmt.Errorf("CA key/cert mismatch: %w", err)
	}

	return &CACert{Key: key, Cert: cert, Raw: raw}, nil
}

// LoadWildcard loads the wildcard leaf key and certificate from disk.
// Returns nil, nil if the material does not exist yet.
func (s *Store) LoadWildcard() (*LeafCert, error) {
	return s.loadLeaf(wildcardKeyFile, wildcardCertFile, "wildcard")
}

// LoadServiceCert loads the ShushTLS service leaf key and certificate from disk.
// Returns nil, nil if the material does not exist yet.
func (s *Store) LoadServiceCert() (*LeafCert, error) {
	return s.loadLeaf(serviceKeyFile, serviceCertFile, "service")
}

func (s *Store) loadLeaf(keyFile, certFile, label string) (*LeafCert, error) {
	keyPath := filepath.Join(s.dir, certDirName, keyFile)
	certPath := filepath.Join(s.dir, certDirName, certFile)

	if !fileExists(keyPath) || !fileExists(certPath) {
		return nil, nil
	}

	key, err := readKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load %s key: %w", label, err)
	}
	raw, cert, err := readCert(certPath)
	if err != nil {
		return nil, fmt.Errorf("load %s cert: %w", label, err)
	}

	if err := validateKeyMatchesCert(key, cert); err != nil {
		return nil, fmt.Errorf("%s key/cert mismatch: %w", label, err)
	}

	return &LeafCert{Key: key, Cert: cert, Raw: raw}, nil
}

// --- State queries ---

// HasCA returns true if root CA material exists on disk.
func (s *Store) HasCA() bool {
	return fileExists(filepath.Join(s.dir, caDirName, caKeyFile)) &&
		fileExists(filepath.Join(s.dir, caDirName, caCertFile))
}

// HasWildcard returns true if wildcard cert material exists on disk.
func (s *Store) HasWildcard() bool {
	return fileExists(filepath.Join(s.dir, certDirName, wildcardKeyFile)) &&
		fileExists(filepath.Join(s.dir, certDirName, wildcardCertFile))
}

// HasServiceCert returns true if the ShushTLS service cert exists on disk.
func (s *Store) HasServiceCert() bool {
	return fileExists(filepath.Join(s.dir, certDirName, serviceKeyFile)) &&
		fileExists(filepath.Join(s.dir, certDirName, serviceCertFile))
}

// ServiceCertPaths returns the file paths to the service certificate and key.
// Useful for configuring the TLS listener.
func (s *Store) ServiceCertPaths() (certPath, keyPath string) {
	return filepath.Join(s.dir, certDirName, serviceCertFile),
		filepath.Join(s.dir, certDirName, serviceKeyFile)
}

// WildcardCertPaths returns the file paths to the wildcard certificate and key.
func (s *Store) WildcardCertPaths() (certPath, keyPath string) {
	return filepath.Join(s.dir, certDirName, wildcardCertFile),
		filepath.Join(s.dir, certDirName, wildcardKeyFile)
}

// CACertPath returns the file path to the root CA certificate.
func (s *Store) CACertPath() string {
	return filepath.Join(s.dir, caDirName, caCertFile)
}

// --- Helpers ---

func writeKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	return writeFileAtomic(path, pem.EncodeToMemory(block), keyFilePerms)
}

func writeCert(path string, der []byte) error {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return writeFileAtomic(path, pem.EncodeToMemory(block), certPerms)
}

func readKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key from %s: %w", path, err)
	}
	return key, nil
}

func readCert(path string) ([]byte, *x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM block found in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse cert from %s: %w", path, err)
	}
	return block.Bytes, cert, nil
}

func validateKeyMatchesCert(key *ecdsa.PrivateKey, cert *x509.Certificate) error {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key is not ECDSA")
	}
	if !key.PublicKey.Equal(pub) {
		return fmt.Errorf("private key does not match certificate public key")
	}
	return nil
}

// writeFileAtomic writes data to a temporary file then renames it into place.
// This prevents partial writes from corrupting existing files.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp) // best-effort cleanup
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
