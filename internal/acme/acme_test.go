package acme

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"shushtls/internal/certengine"
)

// newTestEngine returns an initialized engine rooted at a temp dir.
func newTestEngine(t *testing.T) *certengine.Engine {
	t.Helper()
	e, err := certengine.New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := e.Initialize([]string{"shushtls.test"}, certengine.CAParams{}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	return e
}

// newTestServer builds a Server serving the given base URL. Passing the
// same engine to more than one call models several ShushTLS processes
// sharing a state directory, which is how the reference deployment runs
// (a loopback-only bootstrap sidecar beside the main server).
func newTestServer(t *testing.T, e *certengine.Engine, base string) *Server {
	t.Helper()
	return NewServer(e, func(r *http.Request) string { return base }, nil)
}

// addAccount registers an account directly in memory, standing in for a
// completed newAccount request without needing a signed JWS.
func addAccount(s *Server, key, url string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	acct := &account{key: key, url: url, jwk: []byte(`{"kty":"RSA"}`)}
	s.accounts[key] = acct
	s.accountsByURL[url] = acct
}

func persistedURLs(t *testing.T, s *Server) map[string]bool {
	t.Helper()
	entries, err := readAccountsFile(s.accountsPath())
	if err != nil {
		t.Fatalf("readAccountsFile: %v", err)
	}
	urls := make(map[string]bool, len(entries))
	for _, e := range entries {
		urls[e.URL] = true
	}
	return urls
}

func TestACME_Directory(t *testing.T) {
	dir := t.TempDir()
	e, err := certengine.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = e.Initialize([]string{"shushtls.test"}, certengine.CAParams{})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	srv := NewServer(e, func(r *http.Request) string { return "https://shushtls.test:8443" }, nil)
	mux := http.NewServeMux()
	srv.Register(mux)

	req := httptest.NewRequest("GET", "https://shushtls.test:8443/acme/directory", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	if body == "" {
		t.Error("empty body")
	}
	if body != "" && body[0] != '{' {
		t.Errorf("body should be JSON object, got %q", body[:min(50, len(body))])
	}
}

func TestRandomID_FixedLength(t *testing.T) {
	srv := &Server{}
	for range 100000 {
		id := srv.randomID()
		if got := len(id); got != 22 {
			t.Fatalf("randomID len = %d, want 22 (id=%q)", got, id)
		}
	}
}

// Two servers sharing a state directory must not delete each other's
// registrations. Each holds its own account map, so a save that
// serialized only that map would drop everything the sibling registered
// after we last read the file — the client keeps presenting the kid it
// cached and gets "unknown account" forever, with nothing logged,
// because the save itself succeeded.
func TestSaveAccounts_PreservesSiblingRegistrations(t *testing.T) {
	e := newTestEngine(t)
	main := newTestServer(t, e, "https://shushtls.test")
	sidecar := newTestServer(t, e, "https://localhost:8443")

	mainURL := "https://shushtls.test/acme/acct/keyA"
	sidecarURL := "https://localhost:8443/acme/acct/keyB"

	addAccount(main, "keyA", mainURL)
	if err := main.saveAccounts(); err != nil {
		t.Fatalf("main saveAccounts: %v", err)
	}

	// The sidecar loaded its map before keyA existed, so this is the save
	// that used to clobber it.
	addAccount(sidecar, "keyB", sidecarURL)
	if err := sidecar.saveAccounts(); err != nil {
		t.Fatalf("sidecar saveAccounts: %v", err)
	}

	urls := persistedURLs(t, main)
	if !urls[mainURL] {
		t.Errorf("main server's account was dropped by the sidecar's save; on disk: %v", urls)
	}
	if !urls[sidecarURL] {
		t.Errorf("sidecar's own account is missing; on disk: %v", urls)
	}

	// A restarting process must see both, since that reload is where the
	// bug actually surfaced as "unknown account".
	reloaded := newTestServer(t, e, "https://shushtls.test")
	reloaded.mu.Lock()
	defer reloaded.mu.Unlock()
	for _, u := range []string{mainURL, sidecarURL} {
		if reloaded.accountsByURL[u] == nil {
			t.Errorf("account %q not resolvable after reload", u)
		}
	}
}

// The same key registered against two base URLs must keep both entries:
// they're distinct accounts from each client's point of view, and
// collapsing them by thumbprint strands whichever one loses.
func TestSaveAccounts_SameKeyDistinctBaseURLs(t *testing.T) {
	e := newTestEngine(t)
	main := newTestServer(t, e, "https://shushtls.test")
	sidecar := newTestServer(t, e, "https://localhost:8443")

	mainURL := "https://shushtls.test/acme/acct/shared"
	sidecarURL := "https://localhost:8443/acme/acct/shared"

	addAccount(main, "shared", mainURL)
	if err := main.saveAccounts(); err != nil {
		t.Fatalf("main saveAccounts: %v", err)
	}
	addAccount(sidecar, "shared", sidecarURL)
	if err := sidecar.saveAccounts(); err != nil {
		t.Fatalf("sidecar saveAccounts: %v", err)
	}

	urls := persistedURLs(t, main)
	if !urls[mainURL] || !urls[sidecarURL] {
		t.Errorf("both URLs for a shared key should persist; on disk: %v", urls)
	}
}

// Concurrent savers must serialize on the lockfile rather than
// read-modify-write over each other.
func TestSaveAccounts_ConcurrentSavesDoNotLoseAccounts(t *testing.T) {
	e := newTestEngine(t)
	const n = 8

	// Build every server before adding any account, so none of them has
	// seen the others' registrations — the lost-update setup.
	servers := make([]*Server, n)
	for i := range servers {
		servers[i] = newTestServer(t, e, fmt.Sprintf("https://node%d.test", i))
	}

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i, s := range servers {
		addAccount(s, fmt.Sprintf("key%d", i), fmt.Sprintf("https://node%d.test/acme/acct/key%d", i, i))
		wg.Add(1)
		go func(i int, s *Server) {
			defer wg.Done()
			errs[i] = s.saveAccounts()
		}(i, s)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("server %d saveAccounts: %v", i, err)
		}
	}

	urls := persistedURLs(t, servers[0])
	if len(urls) != n {
		t.Errorf("persisted %d accounts, want %d: %v", len(urls), n, urls)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
