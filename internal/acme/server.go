// Package acme implements a minimal ACME server (RFC 8555) for ShushTLS.
// Challenges are not validated — the server responds positively to all challenges.
package acme

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"shushtls/internal/certengine"
)

const acmePathPrefix = "/acme/"

// BaseURLFunc returns the base URL (scheme://host) for the request.
type BaseURLFunc func(r *http.Request) string

// Server implements ACME directory and endpoints.
type Server struct {
	engine    *certengine.Engine
	baseURL   BaseURLFunc
	logger    *slog.Logger
	nonces   map[string]bool
	accounts   map[string]*account
	accountsByURL map[string]*account
	orders   map[string]*order
	auths    map[string]*authz
	challs   map[string]*challenge
	certs    map[string][]byte
	mu       sync.Mutex
}

type account struct {
	key  string
	url  string
	jwk  []byte // stored for kid-based auth
}

type order struct {
	status        string
	identifiers   []identifier
	authzURLs     []string
	finalizeURL   string
	certURL       string
	cert          []byte
}

type identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type authz struct {
	status      string
	identifier  identifier
	challengeURLs []string
}

type challenge struct {
	authzURL string
}

// NewServer creates an ACME server. baseURL returns the scheme://host for each request.
func NewServer(engine *certengine.Engine, baseURL BaseURLFunc, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		engine:   engine,
		baseURL:  baseURL,
		logger:   logger,
		nonces:       make(map[string]bool),
		accounts:     make(map[string]*account),
		accountsByURL: make(map[string]*account),
		orders:       make(map[string]*order),
		auths:    make(map[string]*authz),
		challs:   make(map[string]*challenge),
		certs:    make(map[string][]byte),
	}
}

// Register adds ACME routes to the mux under /acme/.
func (s *Server) Register(mux *http.ServeMux) {
	dir := acmePathPrefix + "directory"
	mux.HandleFunc("GET "+dir, s.handleDirectory)
	mux.HandleFunc("GET "+acmePathPrefix+"newNonce", s.handleNewNonce)
	mux.HandleFunc("HEAD "+acmePathPrefix+"newNonce", s.handleNewNonce)
	mux.HandleFunc("POST "+acmePathPrefix+"newAccount", s.handleNewAccount)
	mux.HandleFunc("POST "+acmePathPrefix+"newOrder", s.handleNewOrder)

	// Dynamic routes: account, order, authz, challenge, finalize, cert
	mux.HandleFunc("POST /acme/", s.handleACME)
	mux.HandleFunc("GET /acme/", s.handleACME)
}

func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != acmePathPrefix+"directory" {
		http.NotFound(w, r)
		return
	}
	base := strings.TrimSuffix(s.baseURL(r), "/")
	dir := map[string]string{
		"newNonce":   base + "/acme/newNonce",
		"newAccount": base + "/acme/newAccount",
		"newOrder":   base + "/acme/newOrder",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dir)
}

func (s *Server) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	nonce := s.newNonce()
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	if s.engine.State() < certengine.Initialized {
		s.acmeError(w, "Server not initialized", "serverInternal", http.StatusServiceUnavailable)
		return
	}
	payload, err := s.parseJWS(r, "")
	if err != nil {
		s.acmeError(w, err.Error(), "malformed", http.StatusBadRequest)
		return
	}
	// newAccount can have empty payload (create) or contact/terms (update)
	// We accept any account; create or return existing
	keyID := s.jwkThumbprint(payload.Key)
	jwkBytes, _ := json.Marshal(payload.Key)
	base := strings.TrimSuffix(s.baseURL(r), "/")
	s.mu.Lock()
	acct, exists := s.accounts[keyID]
	if !exists {
		acct = &account{key: keyID, url: base + "/acme/acct/" + keyID, jwk: jwkBytes}
		s.accounts[keyID] = acct
		s.accountsByURL[acct.url] = acct
	}
	acctURL := acct.url
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", acctURL)
	w.Header().Set("Replay-Nonce", s.newNonce())
	if !exists {
		w.WriteHeader(http.StatusCreated)
	}
	acctObj := map[string]interface{}{
		"status": "valid",
		"orders": base + "/acme/orders/" + keyID,
	}
	json.NewEncoder(w).Encode(acctObj)
}

func (s *Server) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	if s.engine.State() < certengine.Initialized {
		s.acmeError(w, "Server not initialized", "serverInternal", http.StatusServiceUnavailable)
		return
	}
	payload, err := s.parseJWS(r, "")
	if err != nil {
		s.acmeError(w, err.Error(), "malformed", http.StatusBadRequest)
		return
	}

	var req struct {
		Identifiers []identifier `json:"identifiers"`
	}
	if len(payload.Body) > 0 {
		if err := json.Unmarshal(payload.Body, &req); err != nil {
			s.acmeError(w, "invalid newOrder body", "malformed", http.StatusBadRequest)
			return
		}
	}
	if len(req.Identifiers) == 0 {
		s.acmeError(w, "identifiers required", "malformed", http.StatusBadRequest)
		return
	}

	base := strings.TrimSuffix(s.baseURL(r), "/")
	orderID := s.randomID()
	orderURL := base + "/acme/order/" + orderID
	finalizeURL := base + "/acme/order/" + orderID + "/finalize"

	var authzURLs []string
	for _, id := range req.Identifiers {
		if id.Type != "dns" {
			continue
		}
		authzID := s.randomID()
		authzURL := base + "/acme/authz/" + authzID
		authzURLs = append(authzURLs, authzURL)

		challID := s.randomID()
		challURL := base + "/acme/chall/" + challID

		s.mu.Lock()
		s.auths[authzURL] = &authz{
			status:        "pending",
			identifier:    id,
			challengeURLs: []string{challURL},
		}
		s.challs[challURL] = &challenge{authzURL: authzURL}
		s.mu.Unlock()
	}

	expires := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	s.mu.Lock()
	s.orders[orderURL] = &order{
		status:      "pending",
		identifiers: req.Identifiers,
		authzURLs:   authzURLs,
		finalizeURL: finalizeURL,
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Location", orderURL)
	w.Header().Set("Replay-Nonce", s.newNonce())
	w.WriteHeader(http.StatusCreated)

	resp := map[string]interface{}{
		"status":      "pending",
		"expires":     expires,
		"identifiers": req.Identifiers,
		"authorizations": authzURLs,
		"finalize":    finalizeURL,
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleACME(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if !strings.HasPrefix(path, acmePathPrefix) {
		http.NotFound(w, r)
		return
	}
	path = strings.TrimPrefix(path, acmePathPrefix)
	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 2 {
		http.NotFound(w, r)
		return
	}

	switch parts[0] {
	case "acct":
		s.handleAccount(w, r, path)
	case "order":
		s.handleOrder(w, r, path)
	case "authz":
		s.handleAuthz(w, r, path)
	case "chall":
		s.handleChallenge(w, r, path)
	case "cert":
		// GET or POST-as-GET /acme/cert/{id} - return certificate chain
		if len(parts) >= 2 && (r.Method == "GET" || (r.Method == "POST" && r.Header.Get("Content-Type") == "application/jose+json")) {
			if r.Method == "POST" {
				if _, err := s.parseJWS(r, ""); err != nil {
					s.acmeError(w, err.Error(), "malformed", http.StatusBadRequest)
					return
				}
			}
			s.handleCert(w, r, parts[1])
		} else {
			http.NotFound(w, r)
		}
	case "orders":
		s.handleOrdersList(w, r, path)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request, path string) {
	_, err := s.parseJWS(r, "")
	if err != nil {
		s.acmeError(w, err.Error(), "malformed", http.StatusBadRequest)
		return
	}
	keyID := strings.TrimPrefix(path, "acct/")
	base := strings.TrimSuffix(s.baseURL(r), "/")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", s.newNonce())
	acctObj := map[string]interface{}{
		"status": "valid",
		"orders": base + "/acme/orders/" + keyID,
	}
	json.NewEncoder(w).Encode(acctObj)
}

func (s *Server) handleAuthz(w http.ResponseWriter, r *http.Request, authzURL string) {
	base := strings.TrimSuffix(s.baseURL(r), "/")
	fullURL := base + "/acme/" + authzURL
	s.mu.Lock()
	a, ok := s.auths[fullURL]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}

	if r.Method == "POST" && r.Header.Get("Content-Type") == "application/jose+json" {
		_, err := s.parseJWS(r, "")
		if err != nil {
			s.acmeError(w, err.Error(), "malformed", http.StatusBadRequest)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", s.newNonce())
	resp := map[string]interface{}{
		"status":     a.status,
		"identifier": a.identifier,
		"challenges": []map[string]interface{}{
			{
				"type":   "http-01",
				"url":    a.challengeURLs[0],
				"status": "pending",
				"token":  s.randomID(),
			},
		},
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request, path string) {
	if r.Method != "POST" {
		s.acmeError(w, "method not allowed", "malformed", http.StatusMethodNotAllowed)
		return
	}
	base := strings.TrimSuffix(s.baseURL(r), "/")
	fullURL := base + "/acme/" + path
	s.mu.Lock()
	c, ok := s.challs[fullURL]
	if !ok {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	// Don't care about challenges — mark valid immediately
	a := s.auths[c.authzURL]
	a.status = "valid"
	s.mu.Unlock()

	_, err := s.parseJWS(r, "")
	if err != nil {
		s.acmeError(w, err.Error(), "malformed", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", s.newNonce())
	resp := map[string]interface{}{
		"type":   "http-01",
		"url":    fullURL,
		"status": "valid",
		"token":  s.randomID(),
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleOrder(w http.ResponseWriter, r *http.Request, path string) {
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		http.NotFound(w, r)
		return
	}
	base := strings.TrimSuffix(s.baseURL(r), "/")
	orderURL := base + "/acme/order/" + parts[1]

	s.mu.Lock()
	o, ok := s.orders[orderURL]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}

	if len(parts) >= 3 && parts[2] == "finalize" {
		// Finalize: POST CSR
		s.handleFinalize(w, r, orderURL, o)
		return
	}

	if r.Method == "POST" && r.Header.Get("Content-Type") == "application/jose+json" {
		_, err := s.parseJWS(r, "")
		if err != nil {
			s.acmeError(w, err.Error(), "malformed", http.StatusBadRequest)
			return
		}
	}

	// Check if all authz are valid
	allValid := true
	s.mu.Lock()
	for _, aURL := range o.authzURLs {
		if a := s.auths[aURL]; a == nil || a.status != "valid" {
			allValid = false
			break
		}
	}
	s.mu.Unlock()

	if allValid && o.status == "pending" {
		s.mu.Lock()
		o.status = "ready"
		s.mu.Unlock()
	}

	expires := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", s.newNonce())
	resp := map[string]interface{}{
		"status":        o.status,
		"expires":       expires,
		"identifiers":   o.identifiers,
		"authorizations": o.authzURLs,
		"finalize":      o.finalizeURL,
	}
	if o.certURL != "" {
		resp["certificate"] = o.certURL
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleFinalize(w http.ResponseWriter, r *http.Request, orderURL string, o *order) {
	if o.status != "ready" && o.status != "pending" {
		s.acmeError(w, "order not ready for finalize", "orderNotReady", http.StatusBadRequest)
		return
	}
	payload, err := s.parseJWS(r, "")
	if err != nil {
		s.acmeError(w, err.Error(), "malformed", http.StatusBadRequest)
		return
	}
	var req struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payload.Body, &req); err != nil || req.CSR == "" {
		s.acmeError(w, "csr required", "malformed", http.StatusBadRequest)
		return
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		s.acmeError(w, "invalid csr encoding", "badCSR", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		s.acmeError(w, "invalid csr", "badCSR", http.StatusBadRequest)
		return
	}
	if err := csr.CheckSignature(); err != nil {
		s.acmeError(w, "invalid csr signature", "badCSR", http.StatusBadRequest)
		return
	}

	ca := s.engine.CA()
	if ca == nil {
		s.acmeError(w, "CA not initialized", "serverInternal", http.StatusInternalServerError)
		return
	}
	certDER, err := ca.SignCSR(csr)
	if err != nil {
		s.logger.Error("ACME sign CSR failed", "error", err)
		s.acmeError(w, "failed to sign CSR", "serverInternal", http.StatusInternalServerError)
		return
	}

	base := strings.TrimSuffix(s.baseURL(r), "/")
	certID := s.randomID()
	certURL := base + "/acme/cert/" + certID
	s.mu.Lock()
	o.status = "valid"
	o.certURL = certURL
	o.cert = certDER
	s.certs[certID] = certDER // key by certID to avoid base-URL mismatch on retrieval
	s.mu.Unlock()

	expires := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", s.newNonce())
	resp := map[string]interface{}{
		"status":        "valid",
		"expires":       expires,
		"identifiers":   o.identifiers,
		"authorizations": o.authzURLs,
		"finalize":      o.finalizeURL,
		"certificate":   certURL,
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleOrdersList(w http.ResponseWriter, r *http.Request, _ string) {
	// POST-as-GET for orders list
	_, err := s.parseJWS(r, "")
	if err != nil {
		s.acmeError(w, err.Error(), "malformed", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", s.newNonce())
	json.NewEncoder(w).Encode(map[string]interface{}{"orders": []string{}})
}

func (s *Server) handleCert(w http.ResponseWriter, r *http.Request, certID string) {
	s.mu.Lock()
	certDER, ok := s.certs[certID]
	s.mu.Unlock()
	if !ok || len(certDER) == 0 {
		http.NotFound(w, r)
		return
	}
	ca := s.engine.CA()
	if ca == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Write(pemEncodeChain(certDER, ca.Raw))
}
