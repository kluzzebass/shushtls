package certengine

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// On-disk layout within the state directory:
//
//   <stateDir>/
//     ca/
//       ca-key.pem         (0600)
//       ca-cert.pem        (0644)
//     certs/
//       <sanitized-SAN>/
//         key.pem          (0600)
//         cert.pem         (0644)
//
// Each issued certificate gets its own subdirectory under certs/, named
// after the primary SAN with * replaced by _wildcard_. Examples:
//
//   certs/_wildcard_.home.arpa/   — wildcard cert for *.home.arpa
//   certs/nas.home.arpa/          — FQDN cert for nas.home.arpa
//   certs/shushtls.home.arpa/     — service cert used by ShushTLS itself

const (
	caDirName   = "ca"
	certDirName = "certs"

	caKeyFile  = "ca-key.pem"
	caCertFile = "ca-cert.pem"

	leafKeyFile      = "key.pem"
	leafCertFile     = "cert.pem"
	leafDNSNames     = "dns_names"     // SAN config only (cert generated on download)
	leafSubjectOverrideFile = "leaf_subject.json" // optional subject override per SAN

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

// --- CA operations ---

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

// HasCA returns true if root CA material exists on disk.
func (s *Store) HasCA() bool {
	return fileExists(filepath.Join(s.dir, caDirName, caKeyFile)) &&
		fileExists(filepath.Join(s.dir, caDirName, caCertFile))
}

// CACertPath returns the file path to the root CA certificate.
func (s *Store) CACertPath() string {
	return filepath.Join(s.dir, caDirName, caCertFile)
}

// --- Leaf certificate operations (generic, keyed by primary SAN) ---

// SaveCert writes a leaf certificate's key and cert to disk, keyed by
// its primary SAN (the first DNS name in the certificate).
func (s *Store) SaveCert(leaf *LeafCert) error {
	san := leaf.PrimarySAN()
	dir := s.certDir(san)

	if err := os.MkdirAll(dir, dirPerms); err != nil {
		return fmt.Errorf("create cert directory for %s: %w", san, err)
	}

	keyPath := filepath.Join(dir, leafKeyFile)
	certPath := filepath.Join(dir, leafCertFile)

	if err := writeKey(keyPath, leaf.Key); err != nil {
		return fmt.Errorf("save key for %s: %w", san, err)
	}
	if err := writeCert(certPath, leaf.Raw); err != nil {
		return fmt.Errorf("save cert for %s: %w", san, err)
	}
	return nil
}

// LoadCert loads a leaf certificate by its primary SAN.
// Returns nil, nil if no cert exists for that SAN.
func (s *Store) LoadCert(primarySAN string) (*LeafCert, error) {
	dir := s.certDir(primarySAN)
	keyPath := filepath.Join(dir, leafKeyFile)
	certPath := filepath.Join(dir, leafCertFile)

	if !fileExists(keyPath) || !fileExists(certPath) {
		return nil, nil
	}

	key, err := readKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load key for %s: %w", primarySAN, err)
	}
	raw, cert, err := readCert(certPath)
	if err != nil {
		return nil, fmt.Errorf("load cert for %s: %w", primarySAN, err)
	}

	if err := validateKeyMatchesCert(key, cert); err != nil {
		return nil, fmt.Errorf("key/cert mismatch for %s: %w", primarySAN, err)
	}

	return &LeafCert{Key: key, Cert: cert, Raw: raw}, nil
}

// LoadAllCerts loads every leaf certificate found in the certs/ directory.
// Returns an empty map (not nil) if no certs exist.
func (s *Store) LoadAllCerts() (map[string]*LeafCert, error) {
	certsDir := filepath.Join(s.dir, certDirName)
	entries, err := os.ReadDir(certsDir)
	if err != nil {
		return nil, fmt.Errorf("read certs directory: %w", err)
	}

	certs := make(map[string]*LeafCert)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		san := UnsanitizeSAN(entry.Name())
		leaf, err := s.LoadCert(san)
		if err != nil {
			return nil, fmt.Errorf("load cert %s: %w", san, err)
		}
		if leaf != nil {
			certs[san] = leaf
		}
	}
	return certs, nil
}

// HasCert returns true if a cert for the given primary SAN exists on disk.
func (s *Store) HasCert(primarySAN string) bool {
	dir := s.certDir(primarySAN)
	return fileExists(filepath.Join(dir, leafKeyFile)) &&
		fileExists(filepath.Join(dir, leafCertFile))
}

// SaveSANConfig persists only the SAN config (primary + DNS names) for
// on-demand cert generation. No key or cert is stored — certs are generated on download.
func (s *Store) SaveSANConfig(primarySAN string, dnsNames []string) error {
	if len(dnsNames) == 0 {
		return fmt.Errorf("at least one DNS name is required")
	}
	dir := s.certDir(primarySAN)
	if err := os.MkdirAll(dir, dirPerms); err != nil {
		return fmt.Errorf("create cert directory for %s: %w", primarySAN, err)
	}
	path := filepath.Join(dir, leafDNSNames)
	body := strings.Join(dnsNames, "\n")
	return writeFileAtomic(path, []byte(body), certPerms)
}

// LoadSANConfig loads the persisted SAN config (DNS names) for a primary SAN.
// Returns nil, nil if no config exists.
func (s *Store) LoadSANConfig(primarySAN string) ([]string, error) {
	path := filepath.Join(s.certDir(primarySAN), leafDNSNames)
	if !fileExists(path) {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read SAN config for %s: %w", primarySAN, err)
	}
	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			names = append(names, line)
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	return names, nil
}

// SaveLeafSubjectForSAN persists optional subject params for a primary SAN.
// Used when issuing with a subject override; GetCert uses this when generating on-demand.
func (s *Store) SaveLeafSubjectForSAN(primarySAN string, p LeafSubjectParams) error {
	dir := s.certDir(primarySAN)
	if err := os.MkdirAll(dir, dirPerms); err != nil {
		return fmt.Errorf("create cert directory for %s: %w", primarySAN, err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal leaf subject: %w", err)
	}
	path := filepath.Join(dir, leafSubjectOverrideFile)
	return writeFileAtomic(path, data, certPerms)
}

// LoadLeafSubjectForSAN loads optional subject params for a primary SAN.
// Returns (params, true) if a file exists, (zero, false) otherwise.
func (s *Store) LoadLeafSubjectForSAN(primarySAN string) (LeafSubjectParams, bool) {
	path := filepath.Join(s.certDir(primarySAN), leafSubjectOverrideFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return LeafSubjectParams{}, false
	}
	var p LeafSubjectParams
	if err := json.Unmarshal(data, &p); err != nil {
		return LeafSubjectParams{}, false
	}
	return p.WithDefaults(), true
}

// LoadAllSANConfigs returns all primary SANs that have a SAN config (dns_names)
// on disk. Used to list registered SANs for on-demand issuance.
func (s *Store) LoadAllSANConfigs() (map[string][]string, error) {
	certsDir := filepath.Join(s.dir, certDirName)
	entries, err := os.ReadDir(certsDir)
	if err != nil {
		return nil, fmt.Errorf("read certs directory: %w", err)
	}
	out := make(map[string][]string)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		san := UnsanitizeSAN(entry.Name())
		names, err := s.LoadSANConfig(san)
		if err != nil || names == nil {
			continue
		}
		out[san] = names
	}
	return out, nil
}

// CertPaths returns the file paths to a certificate's cert and key files.
func (s *Store) CertPaths(primarySAN string) (certPath, keyPath string) {
	dir := s.certDir(primarySAN)
	return filepath.Join(dir, leafCertFile), filepath.Join(dir, leafKeyFile)
}

// certDir returns the on-disk directory for a cert identified by its primary SAN.
func (s *Store) certDir(primarySAN string) string {
	return filepath.Join(s.dir, certDirName, SanitizeSAN(primarySAN))
}

// --- Service host persistence ---

const serviceHostFile = "service-host"

// SaveServiceHost writes the current service host (primary SAN) to disk.
func (s *Store) SaveServiceHost(host string) error {
	path := filepath.Join(s.dir, serviceHostFile)
	return writeFileAtomic(path, []byte(host), certPerms)
}

// LoadServiceHost reads the persisted service host from disk.
// Returns "" if no file exists.
func (s *Store) LoadServiceHost() string {
	path := filepath.Join(s.dir, serviceHostFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// --- Leaf subject defaults ---

const leafSubjectFile = "leaf-subject.json"

// SaveLeafSubjectParams writes the default leaf certificate subject params to disk.
func (s *Store) SaveLeafSubjectParams(p LeafSubjectParams) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal leaf subject: %w", err)
	}
	path := filepath.Join(s.dir, leafSubjectFile)
	return writeFileAtomic(path, data, certPerms)
}

// LoadLeafSubjectParams reads the default leaf subject params from disk.
// Returns params with WithDefaults() applied if the file does not exist.
func (s *Store) LoadLeafSubjectParams() LeafSubjectParams {
	path := filepath.Join(s.dir, leafSubjectFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return LeafSubjectParams{}.WithDefaults()
	}
	var p LeafSubjectParams
	if err := json.Unmarshal(data, &p); err != nil {
		return LeafSubjectParams{}.WithDefaults()
	}
	return p.WithDefaults()
}

// --- SAN sanitization ---

// SanitizeSAN converts a SAN into a safe directory name.
// Replaces * with _wildcard_ to avoid filesystem issues.
func SanitizeSAN(san string) string {
	return strings.ReplaceAll(san, "*", "_wildcard_")
}

// UnsanitizeSAN reverses SanitizeSAN, converting a directory name back
// to the original SAN.
func UnsanitizeSAN(dirName string) string {
	return strings.ReplaceAll(dirName, "_wildcard_", "*")
}

// --- PEM helpers ---

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
