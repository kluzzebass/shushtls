// Package auth provides optional HTTP Basic Auth for the ShushTLS API.
// Credentials are stored in a JSON file with bcrypt-hashed passwords.
// Auth is off by default and can be enabled/disabled via the API.
package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

const (
	// authFile is the name of the credentials file inside the state directory.
	authFile = "auth.json"

	// bcryptCost controls the bcrypt hashing cost. 12 is a reasonable
	// balance between security and performance for a LAN service.
	bcryptCost = 12
)

// Credentials holds the stored authentication state.
type Credentials struct {
	// Enabled controls whether authentication is enforced.
	Enabled bool `json:"enabled"`

	// Username is the HTTP Basic Auth username.
	Username string `json:"username"`

	// PasswordHash is the bcrypt hash of the password.
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

	err := bcrypt.CompareHashAndPassword([]byte(s.creds.PasswordHash), []byte(password))
	return err == nil
}

// Enable sets or updates the authentication credentials and persists them.
func (s *Store) Enable(username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.creds = &Credentials{
		Enabled:      true,
		Username:     username,
		PasswordHash: string(hash),
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
