package certengine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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

// --- SAN sanitization tests ---

func TestSanitizeSAN(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"*.example.com", "_wildcard_.example.com"},
		{"nas.example.com", "nas.example.com"},
		{"*.example.com", "_wildcard_.example.com"},
		{"plain.local", "plain.local"},
	}
	for _, tt := range tests {
		got := SanitizeSAN(tt.input)
		if got != tt.want {
			t.Errorf("SanitizeSAN(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestUnsanitizeSAN(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"_wildcard_.example.com", "*.example.com"},
		{"nas.example.com", "nas.example.com"},
	}
	for _, tt := range tests {
		got := UnsanitizeSAN(tt.input)
		if got != tt.want {
			t.Errorf("UnsanitizeSAN(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestSanitizeRoundTrip(t *testing.T) {
	sans := []string{"*.example.com", "nas.example.com", "*.example.com", "localhost"}
	for _, san := range sans {
		if got := UnsanitizeSAN(SanitizeSAN(san)); got != san {
			t.Errorf("round-trip failed for %q: got %q", san, got)
		}
	}
}

// --- Wildcard SAN expansion tests ---

func TestExpandWildcardSANs(t *testing.T) {
	tests := []struct {
		input []string
		want  []string
	}{
		{
			input: []string{"*.example.com"},
			want:  []string{"*.example.com", "example.com"},
		},
		{
			input: []string{"nas.example.com"},
			want:  []string{"nas.example.com"},
		},
		{
			// Bare domain already present — no duplicate.
			input: []string{"*.example.com", "example.com"},
			want:  []string{"*.example.com", "example.com"},
		},
		{
			input: []string{"grafana.example.com", "monitoring.example.com"},
			want:  []string{"grafana.example.com", "monitoring.example.com"},
		},
	}
	for _, tt := range tests {
		got := expandWildcardSANs(tt.input)
		if !strSliceEqual(got, tt.want) {
			t.Errorf("expandWildcardSANs(%v) = %v, want %v", tt.input, got, tt.want)
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
	if e.ServiceCert() != nil {
		t.Error("ServiceCert should be nil when uninitialized")
	}
	if len(e.ListCerts()) != 0 {
		t.Error("ListCerts should be empty when uninitialized")
	}
}

func TestEngine_InitializeProducesReadyState(t *testing.T) {
	e, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	state, err := e.Initialize([]string{"shushtls.local", "localhost"}, CAParams{})
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
	if e.ServiceHost() != "shushtls.local" {
		t.Errorf("ServiceHost = %q, want %q", e.ServiceHost(), "shushtls.local")
	}
}

func TestEngine_InitializeRequiresHostnames(t *testing.T) {
	e, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = e.Initialize(nil, CAParams{})
	if err == nil {
		t.Fatal("expected error with empty serviceHosts")
	}
}

func TestEngine_InitializeIsIdempotent(t *testing.T) {
	e, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	state1, err := e.Initialize([]string{"shushtls.local"}, CAParams{})
	if err != nil {
		t.Fatalf("first Initialize: %v", err)
	}
	caSerial := e.CA().Cert.SerialNumber
	svcSerial := e.ServiceCert().Cert.SerialNumber

	state2, err := e.Initialize([]string{"shushtls.local"}, CAParams{})
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

// --- Configurable CA params tests ---

func TestEngine_InitializeWithCustomCAParams(t *testing.T) {
	e, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	params := CAParams{
		Organization:  "Acme Corp",
		CommonName:    "Acme Internal CA",
		ValidityYears: 10,
	}

	state, err := e.Initialize([]string{"shushtls.local"}, params)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if state != Ready {
		t.Fatalf("expected Ready, got %s", state)
	}

	ca := e.CA().Cert
	if ca.Subject.CommonName != "Acme Internal CA" {
		t.Errorf("CA CN = %q, want %q", ca.Subject.CommonName, "Acme Internal CA")
	}
	if len(ca.Subject.Organization) == 0 || ca.Subject.Organization[0] != "Acme Corp" {
		t.Errorf("CA Org = %v, want [\"Acme Corp\"]", ca.Subject.Organization)
	}

	// Validity should be ~10 years.
	duration := ca.NotAfter.Sub(ca.NotBefore)
	expected := 10 * 365 * 24 * time.Hour
	if abs(duration-expected) > 24*time.Hour {
		t.Errorf("CA validity = %v, want ~%v", duration, expected)
	}
}

func TestEngine_InitializeWithPartialCAParams(t *testing.T) {
	e, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Only set Organization — CN and validity should use defaults.
	params := CAParams{
		Organization: "My Home Lab",
	}

	if _, err := e.Initialize([]string{"shushtls.local"}, params); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	ca := e.CA().Cert
	if len(ca.Subject.Organization) == 0 || ca.Subject.Organization[0] != "My Home Lab" {
		t.Errorf("CA Org = %v, want [\"My Home Lab\"]", ca.Subject.Organization)
	}
	if ca.Subject.CommonName != DefaultCACommonName {
		t.Errorf("CA CN = %q, want default %q", ca.Subject.CommonName, DefaultCACommonName)
	}

	// Validity should be the default ~25 years.
	duration := ca.NotAfter.Sub(ca.NotBefore)
	if abs(duration-RootCAValidity) > 24*time.Hour {
		t.Errorf("CA validity = %v, want ~%v", duration, RootCAValidity)
	}
}

func TestEngine_InitializeIgnoresParamsWhenCAExists(t *testing.T) {
	e, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// First init with defaults.
	if _, err := e.Initialize([]string{"shushtls.local"}, CAParams{}); err != nil {
		t.Fatalf("first Initialize: %v", err)
	}
	origCN := e.CA().Cert.Subject.CommonName

	// Second init with different params — should be ignored (idempotent).
	if _, err := e.Initialize([]string{"shushtls.local"}, CAParams{
		CommonName: "Totally Different CA",
	}); err != nil {
		t.Fatalf("second Initialize: %v", err)
	}

	if e.CA().Cert.Subject.CommonName != origCN {
		t.Errorf("CA CN changed from %q to %q — params should be ignored on re-init",
			origCN, e.CA().Cert.Subject.CommonName)
	}
}

func TestCAParams_WithDefaults(t *testing.T) {
	// All zeros should produce all defaults.
	p := CAParams{}.WithDefaults()
	if p.Organization != DefaultCAOrganization {
		t.Errorf("Organization = %q, want %q", p.Organization, DefaultCAOrganization)
	}
	if p.CommonName != DefaultCACommonName {
		t.Errorf("CommonName = %q, want %q", p.CommonName, DefaultCACommonName)
	}
	if p.ValidityYears != DefaultCAValidityYears {
		t.Errorf("ValidityYears = %d, want %d", p.ValidityYears, DefaultCAValidityYears)
	}

	// Provided values should not be overwritten.
	p2 := CAParams{
		Organization:  "Custom",
		CommonName:    "Custom CA",
		ValidityYears: 5,
	}.WithDefaults()
	if p2.Organization != "Custom" {
		t.Errorf("Organization = %q, want %q", p2.Organization, "Custom")
	}
	if p2.CommonName != "Custom CA" {
		t.Errorf("CommonName = %q, want %q", p2.CommonName, "Custom CA")
	}
	if p2.ValidityYears != 5 {
		t.Errorf("ValidityYears = %d, want %d", p2.ValidityYears, 5)
	}
}

// --- Multi-cert issuance tests ---

func TestEngine_IssueCertBeforeInitialize(t *testing.T) {
	e, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = e.IssueCert([]string{"nas.example.com"}, nil)
	if err == nil {
		t.Fatal("expected error when issuing cert before Initialize")
	}
}

func TestEngine_IssueCertEmptyNames(t *testing.T) {
	e := initEngine(t)
	_, err := e.IssueCert(nil, nil)
	if err == nil {
		t.Fatal("expected error with empty dnsNames")
	}
}

func TestEngine_IssueFQDNCert(t *testing.T) {
	e := initEngine(t)

	item, err := e.IssueCert([]string{"nas.example.com"}, nil)
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	if item.PrimarySAN != "nas.example.com" {
		t.Errorf("PrimarySAN = %q, want %q", item.PrimarySAN, "nas.example.com")
	}

	// Should be retrievable by primary SAN (generated on demand).
	got := e.GetCert("nas.example.com")
	if got == nil {
		t.Fatal("GetCert returned nil")
	}
	if got.PrimarySAN() != "nas.example.com" {
		t.Errorf("GetCert PrimarySAN = %q, want nas.example.com", got.PrimarySAN())
	}
}

func TestEngine_IssueWildcardCert(t *testing.T) {
	e := initEngine(t)

	item, err := e.IssueCert([]string{"*.example.com"}, nil)
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	if item.PrimarySAN != "*.example.com" {
		t.Errorf("PrimarySAN = %q, want %q", item.PrimarySAN, "*.example.com")
	}

	// Wildcard config should expand to include bare domain.
	hasBare := false
	for _, name := range item.DNSNames {
		if name == "example.com" {
			hasBare = true
		}
	}
	if !hasBare {
		t.Errorf("wildcard config missing bare domain SAN, got %v", item.DNSNames)
	}

	// GetCert generates a cert on the fly; it should verify for subdomains.
	leaf := e.GetCert("*.example.com")
	if leaf == nil {
		t.Fatal("GetCert returned nil")
	}
	pool := x509.NewCertPool()
	pool.AddCert(e.CA().Cert)
	for _, name := range []string{"foo.example.com", "bar.example.com"} {
		if _, err := leaf.Cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: name}); err != nil {
			t.Errorf("wildcard cert does not verify for %s: %v", name, err)
		}
	}
}

func TestEngine_IssueMultipleCerts(t *testing.T) {
	e := initEngine(t)

	names := [][]string{
		{"*.example.com"},
		{"nas.example.com"},
		{"pihole.example.com"},
		{"*.lab.example.com"},
	}

	for _, n := range names {
		if _, err := e.IssueCert(n, nil); err != nil {
			t.Fatalf("IssueCert(%v): %v", n, err)
		}
	}

	// ListCerts should include the service cert + all 4 issued certs.
	certs := e.ListCerts()
	if len(certs) != 5 { // 1 service + 4 issued
		t.Errorf("ListCerts returned %d certs, want 5", len(certs))
	}

	// GetCert should find each one.
	for _, n := range names {
		if e.GetCert(n[0]) == nil {
			t.Errorf("GetCert(%q) returned nil", n[0])
		}
	}
}

func TestEngine_IssueCertIsIdempotentPerSAN(t *testing.T) {
	e := initEngine(t)

	item1, err := e.IssueCert([]string{"nas.example.com"}, nil)
	if err != nil {
		t.Fatalf("first IssueCert: %v", err)
	}
	item2, err := e.IssueCert([]string{"nas.example.com"}, nil)
	if err != nil {
		t.Fatalf("second IssueCert: %v", err)
	}
	if item1.PrimarySAN != item2.PrimarySAN {
		t.Error("second IssueCert returned different PrimarySAN (not idempotent)")
	}

	// Different SAN should produce a different list entry.
	item3, err := e.IssueCert([]string{"pihole.example.com"}, nil)
	if err != nil {
		t.Fatalf("IssueCert (different SAN): %v", err)
	}
	if item3.PrimarySAN == item1.PrimarySAN {
		t.Error("different SAN produced the same PrimarySAN")
	}
}

// --- Reload from disk ---

func TestEngine_ReloadFromDisk(t *testing.T) {
	dir := t.TempDir()

	e1, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := e1.Initialize([]string{"shushtls.local"}, CAParams{}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if _, err := e1.IssueCert([]string{"*.example.com"}, nil); err != nil {
		t.Fatalf("IssueCert wildcard: %v", err)
	}
	if _, err := e1.IssueCert([]string{"nas.example.com"}, nil); err != nil {
		t.Fatalf("IssueCert FQDN: %v", err)
	}

	caSerial := e1.CA().Cert.SerialNumber
	svcSerial := e1.ServiceCert().Cert.SerialNumber

	// Create a new engine from the same directory.
	e2, err := New(dir)
	if err != nil {
		t.Fatalf("New (reload): %v", err)
	}

	// CA should reload.
	if e2.CA().Cert.SerialNumber.Cmp(caSerial) != 0 {
		t.Error("reloaded CA has different serial")
	}

	// List: service cert (stored) + wildcard + nas (registered; certs generated on demand).
	if len(e2.ListCerts()) != 3 {
		t.Errorf("reloaded engine has %d certs, want 3", len(e2.ListCerts()))
	}
	// GetCert for registered SANs generates on the fly; we only check they return non-nil.
	if e2.GetCert("*.example.com") == nil {
		t.Error("reloaded: GetCert(*.example.com) returned nil")
	}
	if e2.GetCert("nas.example.com") == nil {
		t.Error("reloaded: GetCert(nas.example.com) returned nil")
	}

	// Service cert needs SetServiceHost after reload to re-associate.
	if e2.ServiceCert() == nil {
		// Before SetServiceHost, State should be Initialized (CA exists but no service host set).
		if e2.State() != Initialized {
			t.Errorf("expected Initialized before SetServiceHost, got %s", e2.State())
		}
		e2.SetServiceHost("shushtls.local")
	}
	if e2.ServiceCert() == nil {
		t.Fatal("ServiceCert is nil after SetServiceHost")
	}
	if e2.ServiceCert().Cert.SerialNumber.Cmp(svcSerial) != 0 {
		t.Error("reloaded service cert has different serial")
	}
	if e2.State() != Ready {
		t.Errorf("expected Ready after SetServiceHost, got %s", e2.State())
	}
}

// --- Root CA certificate property tests ---

func TestCA_IsSelfSigned(t *testing.T) {
	e := initEngine(t)
	ca := e.CA().Cert

	if !ca.IsCA {
		t.Error("CA cert is not marked as CA")
	}
	if !ca.BasicConstraintsValid {
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
	expected := RootCAValidity
	if abs(duration-expected) > 24*time.Hour {
		t.Errorf("CA validity = %v, want ~%v", duration, expected)
	}
}

// --- Leaf certificate property tests ---

func TestLeafCert_SignedByCA(t *testing.T) {
	e := initEngine(t)

	if _, err := e.IssueCert([]string{"nas.example.com"}, nil); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	leaf := e.GetCert("nas.example.com")
	if leaf == nil {
		t.Fatal("GetCert returned nil")
	}

	pool := x509.NewCertPool()
	pool.AddCert(e.CA().Cert)
	if _, err := leaf.Cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Errorf("leaf cert does not verify against CA: %v", err)
	}
}

func TestLeafCert_NotCA(t *testing.T) {
	e := initEngine(t)
	if _, err := e.IssueCert([]string{"nas.example.com"}, nil); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	leaf := e.GetCert("nas.example.com")
	if leaf == nil {
		t.Fatal("GetCert returned nil")
	}
	if leaf.Cert.IsCA {
		t.Error("leaf cert should not be a CA")
	}
}

func TestLeafCert_SANsMatchRequested(t *testing.T) {
	e := initEngine(t)

	if _, err := e.IssueCert([]string{"nas.example.com", "backup.example.com"}, nil); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	leaf := e.GetCert("nas.example.com")
	if leaf == nil {
		t.Fatal("GetCert returned nil")
	}
	want := map[string]bool{"nas.example.com": true, "backup.example.com": true}
	got := make(map[string]bool)
	for _, name := range leaf.Cert.DNSNames {
		got[name] = true
	}
	for name := range want {
		if !got[name] {
			t.Errorf("leaf cert missing SAN %q, got %v", name, leaf.Cert.DNSNames)
		}
	}
}

func TestLeafCert_KeyUsages(t *testing.T) {
	e := initEngine(t)
	if _, err := e.IssueCert([]string{"nas.example.com"}, nil); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	leaf := e.GetCert("nas.example.com")
	if leaf == nil {
		t.Fatal("GetCert returned nil")
	}

	if leaf.Cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("leaf cert missing DigitalSignature key usage")
	}
	if leaf.Cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		t.Error("leaf cert should NOT have KeyEncipherment (invalid for ECDSA)")
	}
}

func TestLeafCert_ExtKeyUsage(t *testing.T) {
	e := initEngine(t)
	if _, err := e.IssueCert([]string{"nas.example.com"}, nil); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	leaf := e.GetCert("nas.example.com")
	if leaf == nil {
		t.Fatal("GetCert returned nil")
	}

	hasServerAuth := false
	hasClientAuth := false
	for _, eku := range leaf.Cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasServerAuth {
		t.Error("leaf cert missing ExtKeyUsageServerAuth")
	}
	if !hasClientAuth {
		t.Error("leaf cert missing ExtKeyUsageClientAuth")
	}
}

func TestLeafCert_ValidityPeriod(t *testing.T) {
	e := initEngine(t)
	if _, err := e.IssueCert([]string{"nas.example.com"}, nil); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	leaf := e.GetCert("nas.example.com")
	if leaf == nil {
		t.Fatal("GetCert returned nil")
	}

	duration := leaf.Cert.NotAfter.Sub(leaf.Cert.NotBefore)
	expected := SC081MaxLeafValidity(time.Now())
	if abs(duration-expected) > 24*time.Hour {
		t.Errorf("leaf validity = %v, want ~%v", duration, expected)
	}
}

func TestServiceCert_SANsMatchRequested(t *testing.T) {
	e := initEngine(t)
	svc := e.ServiceCert().Cert

	want := map[string]bool{"shushtls.local": true, "localhost": true}
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

// --- DesignateServiceCert ---

func TestDesignateServiceCert_Success(t *testing.T) {
	e := initEngine(t)

	// Issue another cert.
	if _, err := e.IssueCert([]string{"mybox.local", "localhost"}, nil); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	// Designate it as the service cert.
	if err := e.DesignateServiceCert("mybox.local"); err != nil {
		t.Fatalf("DesignateServiceCert: %v", err)
	}

	if e.ServiceHost() != "mybox.local" {
		t.Errorf("host = %q, want mybox.local", e.ServiceHost())
	}
	if e.ServiceCert().PrimarySAN() != "mybox.local" {
		t.Errorf("service cert SAN = %q, want mybox.local", e.ServiceCert().PrimarySAN())
	}
	// Old cert should still exist — it's just not the service cert anymore.
	if e.GetCert("shushtls.local") == nil {
		t.Error("old cert should still exist")
	}
	// State should still be Ready.
	if e.State() != Ready {
		t.Errorf("state = %s, want ready", e.State())
	}
}

func TestDesignateServiceCert_NonexistentCert(t *testing.T) {
	e := initEngine(t)

	err := e.DesignateServiceCert("nonexistent.local")
	if err == nil {
		t.Fatal("expected error designating nonexistent cert")
	}
}

func TestDesignateServiceCert_BeforeInit(t *testing.T) {
	dir := t.TempDir()
	e, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = e.DesignateServiceCert("test.local")
	if err == nil {
		t.Fatal("expected error designating service cert before init")
	}
}

func TestDesignateServiceCert_Persists(t *testing.T) {
	e := initEngine(t)

	// Issue and designate.
	if _, err := e.IssueCert([]string{"mybox.local"}, nil); err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	if err := e.DesignateServiceCert("mybox.local"); err != nil {
		t.Fatalf("DesignateServiceCert: %v", err)
	}

	// Reload from disk — should restore the choice automatically.
	e2, err := New(e.Store().dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	if e2.ServiceHost() != "mybox.local" {
		t.Errorf("reloaded host = %q, want mybox.local", e2.ServiceHost())
	}
	if e2.State() != Ready {
		t.Errorf("reloaded state = %s, want ready", e2.State())
	}
}

// --- SignCSR (ACME) ---

func TestCACert_SignCSR(t *testing.T) {
	e := initEngine(t)
	ca := e.CA()
	if ca == nil {
		t.Fatal("CA is nil")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "test.example.com"},
		DNSNames: []string{"test.example.com", "www.test.example.com"},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}

	certDER, err := ca.SignCSR(csr)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("CN = %q, want test.example.com", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 2 {
		t.Errorf("DNSNames len = %d, want 2", len(cert.DNSNames))
	}
	if err := cert.CheckSignatureFrom(ca.Cert); err != nil {
		t.Errorf("cert not signed by CA: %v", err)
	}
}

// --- IssueCertificate edge case ---

func TestIssueCertificate_EmptyNames(t *testing.T) {
	e := initEngine(t)
	_, err := IssueCertificate(e.CA(), nil)
	if err == nil {
		t.Fatal("expected error when issuing cert with no names")
	}
}

func TestLeafCert_SubjectParams(t *testing.T) {
	e := initEngine(t)
	subject := LeafSubjectParams{
		Organization:       "Acme Labs",
		OrganizationalUnit: "IT",
		Country:            "US",
		Locality:           "Boston",
		Province:           "MA",
	}
	leaf, err := IssueCertificateWithValidityAndSubject(e.CA(), []string{"host.example.com"}, LeafCertValidity, subject)
	if err != nil {
		t.Fatalf("IssueCertificateWithValidityAndSubject: %v", err)
	}
	cert := leaf.Cert
	if cert.Subject.CommonName != "host.example.com" {
		t.Errorf("CN = %q, want host.example.com", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != "Acme Labs" {
		t.Errorf("O = %v, want [Acme Labs]", cert.Subject.Organization)
	}
	if len(cert.Subject.OrganizationalUnit) == 0 || cert.Subject.OrganizationalUnit[0] != "IT" {
		t.Errorf("OU = %v, want [IT]", cert.Subject.OrganizationalUnit)
	}
	if len(cert.Subject.Country) == 0 || cert.Subject.Country[0] != "US" {
		t.Errorf("C = %v, want [US]", cert.Subject.Country)
	}
	if len(cert.Subject.Locality) == 0 || cert.Subject.Locality[0] != "Boston" {
		t.Errorf("L = %v, want [Boston]", cert.Subject.Locality)
	}
	if len(cert.Subject.Province) == 0 || cert.Subject.Province[0] != "MA" {
		t.Errorf("ST = %v, want [MA]", cert.Subject.Province)
	}
}

// --- Store tests ---

func TestStore_HasCert(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if store.HasCA() {
		t.Error("HasCA should be false on empty store")
	}
	if store.HasCert("nas.example.com") {
		t.Error("HasCert should be false for nonexistent cert")
	}
	if store.HasCert("*.example.com") {
		t.Error("HasCert should be false for nonexistent wildcard")
	}

	// Generate and save a CA, then issue a cert.
	ca, err := GenerateCA(CAParams{})
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := store.SaveCA(ca); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}
	if !store.HasCA() {
		t.Error("HasCA should be true after SaveCA")
	}

	leaf, err := IssueCertificate(ca, []string{"nas.example.com"})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	if err := store.SaveCert(leaf); err != nil {
		t.Fatalf("SaveCert: %v", err)
	}
	if !store.HasCert("nas.example.com") {
		t.Error("HasCert should be true after SaveCert")
	}
	if store.HasCert("*.example.com") {
		t.Error("HasCert should still be false for a different SAN")
	}
}

func TestStore_CertPaths(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	certPath, keyPath := store.CertPaths("*.example.com")
	if certPath == "" || keyPath == "" {
		t.Error("CertPaths returned empty strings")
	}
	// Path should contain the sanitized SAN.
	if !filepath.IsAbs(certPath) {
		t.Error("certPath should be absolute")
	}
}

func TestStore_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	ca, err := GenerateCA(CAParams{})
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := store.SaveCA(ca); err != nil {
		t.Fatalf("SaveCA: %v", err)
	}

	// CA key should be 0600.
	keyInfo, err := os.Stat(filepath.Join(dir, caDirName, caKeyFile))
	if err != nil {
		t.Fatalf("stat CA key: %v", err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("CA key permissions = %04o, want 0600", perm)
	}

	// CA cert should be 0644.
	certInfo, err := os.Stat(filepath.Join(dir, caDirName, caCertFile))
	if err != nil {
		t.Fatalf("stat CA cert: %v", err)
	}
	if perm := certInfo.Mode().Perm(); perm != 0644 {
		t.Errorf("CA cert permissions = %04o, want 0644", perm)
	}

	// Leaf cert file permissions.
	leaf, err := IssueCertificate(ca, []string{"nas.example.com"})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	if err := store.SaveCert(leaf); err != nil {
		t.Fatalf("SaveCert: %v", err)
	}

	leafDir := filepath.Join(dir, certDirName, "nas.example.com")
	leafKeyInfo, err := os.Stat(filepath.Join(leafDir, leafKeyFile))
	if err != nil {
		t.Fatalf("stat leaf key: %v", err)
	}
	if perm := leafKeyInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("leaf key permissions = %04o, want 0600", perm)
	}

	leafCertInfo, err := os.Stat(filepath.Join(leafDir, leafCertFile))
	if err != nil {
		t.Fatalf("stat leaf cert: %v", err)
	}
	if perm := leafCertInfo.Mode().Perm(); perm != 0644 {
		t.Errorf("leaf cert permissions = %04o, want 0644", perm)
	}
}

func TestStore_WildcardCertDiskLayout(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	ca, err := GenerateCA(CAParams{})
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	leaf, err := IssueCertificate(ca, []string{"*.example.com"})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	if err := store.SaveCert(leaf); err != nil {
		t.Fatalf("SaveCert: %v", err)
	}

	// Should use sanitized directory name.
	expectedDir := filepath.Join(dir, certDirName, "_wildcard_.example.com")
	if _, err := os.Stat(expectedDir); os.IsNotExist(err) {
		t.Errorf("expected directory %s to exist", expectedDir)
	}
}

func TestStore_LoadAllCerts(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	ca, err := GenerateCA(CAParams{})
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	sans := []string{"nas.example.com", "*.example.com", "pihole.example.com"}
	for _, san := range sans {
		leaf, err := IssueCertificate(ca, []string{san})
		if err != nil {
			t.Fatalf("IssueCertificate(%s): %v", san, err)
		}
		if err := store.SaveCert(leaf); err != nil {
			t.Fatalf("SaveCert(%s): %v", san, err)
		}
	}

	certs, err := store.LoadAllCerts()
	if err != nil {
		t.Fatalf("LoadAllCerts: %v", err)
	}
	if len(certs) != 3 {
		t.Errorf("LoadAllCerts returned %d certs, want 3", len(certs))
	}
	for _, san := range sans {
		if _, ok := certs[san]; !ok {
			t.Errorf("LoadAllCerts missing cert for %s", san)
		}
	}
}

func TestStore_LoadCA_ReturnsNilForMissingMaterial(t *testing.T) {
	store, err := NewStore(t.TempDir())
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

func TestStore_LoadCert_ReturnsNilForMissing(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	leaf, err := store.LoadCert("nonexistent.example.com")
	if err != nil {
		t.Fatalf("LoadCert: %v", err)
	}
	if leaf != nil {
		t.Error("LoadCert should return nil for nonexistent cert")
	}
}

func TestStore_LoadCA_ErrorsOnCorruptPEM(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

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

	ca1, err := GenerateCA(CAParams{})
	if err != nil {
		t.Fatalf("GenerateCA 1: %v", err)
	}
	ca2, err := GenerateCA(CAParams{})
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

// --- LeafCert.PrimarySAN tests ---

func TestLeafCert_PrimarySAN(t *testing.T) {
	e := initEngine(t)

	// FQDN cert
	fqdn, _ := e.IssueCert([]string{"nas.example.com", "backup.example.com"}, nil)
	if fqdn.PrimarySAN != "nas.example.com" {
		t.Errorf("FQDN PrimarySAN = %q, want %q", fqdn.PrimarySAN, "nas.example.com")
	}

	// Wildcard cert
	wild, _ := e.IssueCert([]string{"*.example.com"}, nil)
	if wild.PrimarySAN != "*.example.com" {
		t.Errorf("wildcard PrimarySAN = %q, want %q", wild.PrimarySAN, "*.example.com")
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
	if _, err := e.Initialize([]string{"shushtls.local", "localhost"}, CAParams{}); err != nil {
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

func strSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
