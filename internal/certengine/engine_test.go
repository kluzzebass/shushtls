package certengine

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- State enum tests ---

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{Uninitialized, "uninitialized"},
		{Initialized, "initialized"},
		{Ready, "ready"},
		{State(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

// --- Engine lifecycle tests ---

func TestEngine_FreshStateIsUninitialized(t *testing.T) {
	e, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e.State() != Uninitialized {
		t.Fatalf("expected Uninitialized, got %s", e.State())
	}
	if e.CA() != nil {
		t.Error("CA should be nil when uninitialized")
	}
	if e.Wildcard() != nil {
		t.Error("Wildcard should be nil when uninitialized")
	}
	if e.ServiceCert() != nil {
		t.Error("ServiceCert should be nil when uninitialized")
	}
}

func TestEngine_InitializeProducesReadyState(t *testing.T) {
	e, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	state, err := e.Initialize([]string{"shushtls.home.arpa", "localhost"})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if state != Ready {
		t.Fatalf("expected Ready, got %s", state)
	}
	if e.CA() == nil {
		t.Fatal("CA is nil after Initialize")
	}
	if e.ServiceCert() == nil {
		t.Fatal("ServiceCert is nil after Initialize")
	}
}

func TestEngine_InitializeIsIdempotent(t *testing.T) {
	e, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	state1, err := e.Initialize([]string{"shushtls.home.arpa"})
	if err != nil {
		t.Fatalf("first Initialize: %v", err)
	}
	caSerial := e.CA().Cert.SerialNumber
	svcSerial := e.ServiceCert().Cert.SerialNumber

	state2, err := e.Initialize([]string{"shushtls.home.arpa"})
	if err != nil {
		t.Fatalf("second Initialize: %v", err)
	}
	if state1 != state2 {
		t.Errorf("states differ: %s vs %s", state1, state2)
	}
	if e.CA().Cert.SerialNumber.Cmp(caSerial) != 0 {
		t.Error("CA was regenerated on second Initialize")
	}
	if e.ServiceCert().Cert.SerialNumber.Cmp(svcSerial) != 0 {
		t.Error("service cert was regenerated on second Initialize")
	}
}

func TestEngine_GenerateWildcardBeforeInitialize(t *testing.T) {
	e, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = e.GenerateWildcard("home.arpa")
	if err == nil {
		t.Fatal("expected error when generating wildcard before Initialize")
	}
}

func TestEngine_GenerateWildcardIsIdempotent(t *testing.T) {
	e, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := e.Initialize([]string{"shushtls.home.arpa"}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	wild1, err := e.GenerateWildcard("home.arpa")
	if err != nil {
		t.Fatalf("first GenerateWildcard: %v", err)
	}
	wild2, err := e.GenerateWildcard("home.arpa")
	if err != nil {
		t.Fatalf("second GenerateWildcard: %v", err)
	}
	if wild1.Cert.SerialNumber.Cmp(wild2.Cert.SerialNumber) != 0 {
		t.Error("second GenerateWildcard returned a different cert")
	}
}

func TestEngine_ReloadFromDisk(t *testing.T) {
	dir := t.TempDir()

	e1, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := e1.Initialize([]string{"shushtls.home.arpa"}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if _, err := e1.GenerateWildcard("home.arpa"); err != nil {
		t.Fatalf("GenerateWildcard: %v", err)
	}

	caSerial := e1.CA().Cert.SerialNumber
	svcSerial := e1.ServiceCert().Cert.SerialNumber
	wildSerial := e1.Wildcard().Cert.SerialNumber

	// Create a completely new engine from the same directory.
	e2, err := New(dir)
	if err != nil {
		t.Fatalf("New (reload): %v", err)
	}
	if e2.State() != Ready {
		t.Fatalf("expected Ready after reload, got %s", e2.State())
	}
	if e2.CA().Cert.SerialNumber.Cmp(caSerial) != 0 {
		t.Error("reloaded CA has different serial")
	}
	if e2.ServiceCert().Cert.SerialNumber.Cmp(svcSerial) != 0 {
		t.Error("reloaded service cert has different serial")
	}
	if e2.Wildcard().Cert.SerialNumber.Cmp(wildSerial) != 0 {
		t.Error("reloaded wildcard has different serial")
	}
}

// --- Root CA certificate property tests ---

func TestCA_IsSelfSigned(t *testing.T) {
	e := initEngine(t)
	ca := e.CA().Cert

	if !ca.IsCA {
		t.Error("CA cert is not marked as CA")
	}
	if ca.BasicConstraintsValid != true {
		t.Error("BasicConstraintsValid is false")
	}
	// Self-signed: issuer and subject should match.
	if ca.Issuer.CommonName != ca.Subject.CommonName {
		t.Errorf("CA issuer CN %q != subject CN %q", ca.Issuer.CommonName, ca.Subject.CommonName)
	}
}

func TestCA_SubjectFields(t *testing.T) {
	e := initEngine(t)
	ca := e.CA().Cert

	if ca.Subject.CommonName != DefaultCACommonName {
		t.Errorf("CA CN = %q, want %q", ca.Subject.CommonName, DefaultCACommonName)
	}
	if len(ca.Subject.Organization) == 0 || ca.Subject.Organization[0] != DefaultCAOrganization {
		t.Errorf("CA Org = %v, want [%q]", ca.Subject.Organization, DefaultCAOrganization)
	}
}

func TestCA_MaxPathLen(t *testing.T) {
	e := initEngine(t)
	ca := e.CA().Cert

	if ca.MaxPathLen != 0 {
		t.Errorf("CA MaxPathLen = %d, want 0", ca.MaxPathLen)
	}
	if !ca.MaxPathLenZero {
		t.Error("CA MaxPathLenZero should be true")
	}
}

func TestCA_KeyUsages(t *testing.T) {
	e := initEngine(t)
	ca := e.CA().Cert

	if ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA missing KeyUsageCertSign")
	}
	if ca.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Error("CA missing KeyUsageCRLSign")
	}
}

func TestCA_ValidityPeriod(t *testing.T) {
	e := initEngine(t)
	ca := e.CA().Cert

	duration := ca.NotAfter.Sub(ca.NotBefore)
	// Should be approximately 25 years. Allow a 1-day margin for test timing.
	expected := RootCAValidity
	if abs(duration-expected) > 24*time.Hour {
		t.Errorf("CA validity = %v, want ~%v", duration, expected)
	}
}

// --- Leaf certificate property tests ---

func TestServiceCert_SignedByCA(t *testing.T) {
	e := initEngine(t)
	svc := e.ServiceCert().Cert
	pool := x509.NewCertPool()
	pool.AddCert(e.CA().Cert)

	if _, err := svc.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("service cert does not verify against CA: %v", err)
	}
}

func TestServiceCert_NotCA(t *testing.T) {
	e := initEngine(t)
	if e.ServiceCert().Cert.IsCA {
		t.Error("service cert should not be a CA")
	}
}

func TestServiceCert_SANsMatchRequested(t *testing.T) {
	e := initEngine(t)
	svc := e.ServiceCert().Cert

	want := map[string]bool{"shushtls.home.arpa": true, "localhost": true}
	got := make(map[string]bool)
	for _, name := range svc.DNSNames {
		got[name] = true
	}
	for name := range want {
		if !got[name] {
			t.Errorf("service cert missing SAN %q, got %v", name, svc.DNSNames)
		}
	}
}

func TestServiceCert_KeyUsages(t *testing.T) {
	e := initEngine(t)
	svc := e.ServiceCert().Cert

	if svc.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("service cert missing DigitalSignature key usage")
	}
	if svc.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("service cert missing KeyEncipherment key usage")
	}
}

func TestServiceCert_ExtKeyUsage(t *testing.T) {
	e := initEngine(t)
	svc := e.ServiceCert().Cert

	found := false
	for _, eku := range svc.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			found = true
			break
		}
	}
	if !found {
		t.Error("service cert missing ExtKeyUsageServerAuth")
	}
}

func TestServiceCert_ValidityPeriod(t *testing.T) {
	e := initEngine(t)
	svc := e.ServiceCert().Cert

	duration := svc.NotAfter.Sub(svc.NotBefore)
	expected := ServiceCertValidity
	if abs(duration-expected) > 24*time.Hour {
		t.Errorf("service cert validity = %v, want ~%v", duration, expected)
	}
}

func TestWildcard_SANs(t *testing.T) {
	e := initEngine(t)
	if _, err := e.GenerateWildcard("home.arpa"); err != nil {
		t.Fatalf("GenerateWildcard: %v", err)
	}
	wild := e.Wildcard().Cert

	wantSANs := map[string]bool{"*.home.arpa": true, "home.arpa": true}
	got := make(map[string]bool)
	for _, name := range wild.DNSNames {
		got[name] = true
	}
	for name := range wantSANs {
		if !got[name] {
			t.Errorf("wildcard cert missing SAN %q, got %v", name, wild.DNSNames)
		}
	}
}

func TestWildcard_VerifiesForSubdomain(t *testing.T) {
	e := initEngine(t)
	if _, err := e.GenerateWildcard("home.arpa"); err != nil {
		t.Fatalf("GenerateWildcard: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(e.CA().Cert)

	for _, name := range []string{"foo.home.arpa", "bar.home.arpa", "grafana.home.arpa"} {
		if _, err := e.Wildcard().Cert.Verify(x509.VerifyOptions{
			Roots:   pool,
			DNSName: name,
		}); err != nil {
			t.Errorf("wildcard cert does not verify for %s: %v", name, err)
		}
	}
}

func TestWildcard_ValidityPeriod(t *testing.T) {
	e := initEngine(t)
	if _, err := e.GenerateWildcard("home.arpa"); err != nil {
		t.Fatalf("GenerateWildcard: %v", err)
	}
	wild := e.Wildcard().Cert

	duration := wild.NotAfter.Sub(wild.NotBefore)
	expected := LeafCertValidity
	if abs(duration-expected) > 24*time.Hour {
		t.Errorf("wildcard validity = %v, want ~%v", duration, expected)
	}
}

// --- IssueServiceCert edge case ---

func TestIssueServiceCert_EmptyHostnames(t *testing.T) {
	e := initEngine(t)
	_, err := IssueServiceCert(e.CA(), /* no hostnames */)
	if err == nil {
		t.Fatal("expected error when issuing service cert with no hostnames")
	}
}

// --- Store tests ---

func TestStore_HasMethods(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if store.HasCA() {
		t.Error("HasCA should be false on empty store")
	}
	if store.HasWildcard() {
		t.Error("HasWildcard should be false on empty store")
	}
	if store.HasServiceCert() {
		t.Error("HasServiceCert should be false on empty store")
	}

	// Generate and save a CA.
	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := store.SaveCA(ca); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}
	if !store.HasCA() {
		t.Error("HasCA should be true after SaveCA")
	}
	if store.HasWildcard() {
		t.Error("HasWildcard should still be false")
	}
}

func TestStore_PathAccessors(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	caPath := store.CACertPath()
	if caPath == "" {
		t.Error("CACertPath returned empty string")
	}

	certPath, keyPath := store.ServiceCertPaths()
	if certPath == "" || keyPath == "" {
		t.Error("ServiceCertPaths returned empty strings")
	}

	certPath, keyPath = store.WildcardCertPaths()
	if certPath == "" || keyPath == "" {
		t.Error("WildcardCertPaths returned empty strings")
	}
}

func TestStore_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	ca, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := store.SaveCA(ca); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}

	// Key file should be 0600.
	keyInfo, err := os.Stat(filepath.Join(dir, caDirName, caKeyFile))
	if err != nil {
		t.Fatalf("stat CA key: %v", err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("CA key permissions = %04o, want 0600", perm)
	}

	// Cert file should be 0644.
	certInfo, err := os.Stat(filepath.Join(dir, caDirName, caCertFile))
	if err != nil {
		t.Fatalf("stat CA cert: %v", err)
	}
	if perm := certInfo.Mode().Perm(); perm != 0644 {
		t.Errorf("CA cert permissions = %04o, want 0644", perm)
	}
}

func TestStore_LoadCA_ReturnsNilForMissingMaterial(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	ca, err := store.LoadCA()
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if ca != nil {
		t.Error("LoadCA should return nil for empty store")
	}
}

func TestStore_LoadCA_ErrorsOnCorruptPEM(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Write garbage to both files.
	keyPath := filepath.Join(dir, caDirName, caKeyFile)
	certPath := filepath.Join(dir, caDirName, caCertFile)
	os.WriteFile(keyPath, []byte("not a pem file"), 0600)
	os.WriteFile(certPath, []byte("also not pem"), 0644)

	_, err = store.LoadCA()
	if err == nil {
		t.Fatal("expected error when loading corrupt PEM files")
	}
}

func TestStore_LoadCA_ErrorsOnMismatchedKeyAndCert(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	// Generate two different CAs.
	ca1, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA 1: %v", err)
	}
	ca2, err := GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA 2: %v", err)
	}

	// Save key from ca1 but cert from ca2.
	if err := store.SaveCA(ca1); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}
	if err := writeCert(filepath.Join(dir, caDirName, caCertFile), ca2.Raw); err != nil {
		t.Fatalf("overwrite cert: %v", err)
	}

	_, err = store.LoadCA()
	if err == nil {
		t.Fatal("expected error when key and cert don't match")
	}
}

// --- Helpers ---

// initEngine creates an initialized engine with service hosts for testing.
func initEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := e.Initialize([]string{"shushtls.home.arpa", "localhost"}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	return e
}

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
