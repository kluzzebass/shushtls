package acme

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
)

func (s *Server) newNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) randomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func pemEncodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pemEncodeChain(leafDER, caDER []byte) []byte {
	return append(pemEncodeCert(leafDER), pemEncodeCert(caDER)...)
}

func (s *Server) acmeError(w http.ResponseWriter, detail, acmeType string, status int) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Replay-Nonce", s.newNonce())
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"type":   "urn:ietf:params:acme:error:" + acmeType,
		"detail": detail,
	})
}
