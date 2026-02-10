package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewStore_EmptyDir(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if s.IsEnabled() {
		t.Error("new store should not have auth enabled")
	}
}

func TestStore_EnableAndVerify(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if err := s.Enable("admin", "password123"); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	if !s.IsEnabled() {
		t.Error("auth should be enabled after Enable()")
	}

	// Correct credentials.
	if !s.Verify("admin", "password123") {
		t.Error("Verify should return true for correct credentials")
	}

	// Wrong password.
	if s.Verify("admin", "wrong") {
		t.Error("Verify should return false for wrong password")
	}

	// Wrong username.
	if s.Verify("other", "password123") {
		t.Error("Verify should return false for wrong username")
	}
}

func TestStore_Disable(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if err := s.Enable("admin", "pw"); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	if err := s.Disable(); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	if s.IsEnabled() {
		t.Error("auth should be disabled after Disable()")
	}

	// With auth disabled, Verify should return true for anything.
	if !s.Verify("anyone", "anything") {
		t.Error("Verify should return true when auth is disabled")
	}
}

func TestStore_DisableWhenAlreadyDisabled(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Disabling a store that was never enabled should be a no-op.
	if err := s.Disable(); err != nil {
		t.Fatalf("Disable: %v", err)
	}
}

func TestStore_PersistsToDisk(t *testing.T) {
	dir := t.TempDir()

	// Create and enable.
	s1, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := s1.Enable("user", "pass"); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	// Verify file exists.
	path := filepath.Join(dir, "auth.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("auth.json should exist after Enable()")
	}

	// Load from disk in a new store.
	s2, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore (reload): %v", err)
	}

	if !s2.IsEnabled() {
		t.Error("reloaded store should have auth enabled")
	}
	if !s2.Verify("user", "pass") {
		t.Error("reloaded store should verify correct credentials")
	}
	if s2.Verify("user", "wrong") {
		t.Error("reloaded store should reject wrong password")
	}
}

func TestStore_UpdateCredentials(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Set initial credentials.
	if err := s.Enable("admin", "old"); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	// Update credentials.
	if err := s.Enable("admin", "new"); err != nil {
		t.Fatalf("Enable (update): %v", err)
	}

	if s.Verify("admin", "old") {
		t.Error("old password should no longer work")
	}
	if !s.Verify("admin", "new") {
		t.Error("new password should work")
	}
}

func TestStore_VerifyWhenDisabled(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// No credentials at all — Verify should pass everything.
	if !s.Verify("", "") {
		t.Error("Verify should return true when no creds exist")
	}
	if !s.Verify("anything", "anything") {
		t.Error("Verify should return true when no creds exist")
	}
}
