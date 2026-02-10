// Package auth provides optional HTTP Basic Auth for the ShushTLS API.
// Credentials are stored in a JSON file with argon2id-hashed passwords.
// Auth is off by default and can be enabled/disabled via the API.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

const (
	// authFile is the name of the credentials file inside the state directory.
	authFile = "auth.json"

	// Argon2id parameters (OWASP recommended).
	argonMemory      = 64 * 1024 // 64 MB
	argonIterations  = 3
	argonParallelism = 4
	argonSaltLen     = 16
	argonKeyLen      = 32
)

// Credentials holds the stored authentication state.
type Credentials struct {
	// Enabled controls whether authentication is enforced.
	Enabled bool `json:"enabled"`

	// Username is the HTTP Basic Auth username.
	Username string `json:"username"`

	// PasswordHash is the argon2id hash in PHC string format:
	// $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
	PasswordHash string `json:"password_hash"`
}

// Store manages authentication credentials on disk.
type Store struct {
	mu       sync.RWMutex
	stateDir string
	creds    *Credentials // nil means no auth file exists
}

// NewStore creates an auth store, loading existing credentials from disk
// if present. A missing auth.json file is not an error — it means auth
// is disabled.
func NewStore(stateDir string) (*Store, error) {
	s := &Store{stateDir: stateDir}
	if err := s.load(); err != nil {
		return nil, fmt.Errorf("load auth: %w", err)
	}
	return s, nil
}

// IsEnabled returns whether authentication is currently required.
func (s *Store) IsEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.creds != nil && s.creds.Enabled
}

// Verify checks whether the given username and password match the stored
// credentials. Returns true if auth is disabled (no credentials to check)
// or if the credentials are valid.
func (s *Store) Verify(username, password string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.creds == nil || !s.creds.Enabled {
		return true
	}

	if username != s.creds.Username {
		return false
	}

	return verifyArgon2id(s.creds.PasswordHash, password)
}

// Enable sets or updates the authentication credentials and persists them.
func (s *Store) Enable(username, password string) error {
	hash, err := hashArgon2id(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.creds = &Credentials{
		Enabled:      true,
		Username:     username,
		PasswordHash: hash,
	}

	return s.save()
}

// Disable turns off authentication and persists the change. The
// credentials remain on disk but with enabled=false.
func (s *Store) Disable() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.creds == nil {
		return nil // already disabled
	}

	s.creds.Enabled = false
	return s.save()
}

// path returns the full path to the auth.json file.
func (s *Store) path() string {
	return filepath.Join(s.stateDir, authFile)
}

// load reads credentials from disk. A missing file is not an error.
func (s *Store) load() error {
	data, err := os.ReadFile(s.path())
	if os.IsNotExist(err) {
		s.creds = nil
		return nil
	}
	if err != nil {
		return err
	}

	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return fmt.Errorf("parse %s: %w", authFile, err)
	}

	s.creds = &creds
	return nil
}

// save writes the current credentials to disk atomically.
func (s *Store) save() error {
	data, err := json.MarshalIndent(s.creds, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal auth: %w", err)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(s.stateDir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	return os.WriteFile(s.path(), data, 0o600)
}

// --- Argon2id password hashing ---

// hashArgon2id produces a PHC-format string:
// $argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
func hashArgon2id(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory, argonIterations, argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// verifyArgon2id parses a PHC-format hash and compares it against a password.
func verifyArgon2id(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	// Expected: ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}

	var memory uint32
	var iterations uint32
	var parallelism uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	hash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expectedHash)))

	return subtle.ConstantTimeCompare(hash, expectedHash) == 1
}
