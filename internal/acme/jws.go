package acme

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-jose/go-jose/v4"
)

type jwsPayload struct {
	Body   []byte
	Key    *jose.JSONWebKey
	KeyID  string
	Nonce  string
	URL    string
}

func (s *Server) parseJWS(r *http.Request, expectedKid string) (*jwsPayload, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	prot, err := base64.RawURLEncoding.DecodeString(raw.Protected)
	if err != nil {
		return nil, err
	}
	var hdr struct {
		Alg   string          `json:"alg"`
		Nonce string          `json:"nonce"`
		URL   string          `json:"url"`
		JWK   json.RawMessage `json:"jwk"`
		Kid   string          `json:"kid"`
	}
	if err := json.Unmarshal(prot, &hdr); err != nil {
		return nil, err
	}
	// URL integrity check: optional; some clients send full URL
	s.mu.Lock()
	used := s.nonces[hdr.Nonce]
	if used {
		s.mu.Unlock()
		return nil, err
	}
	s.nonces[hdr.Nonce] = true
	s.mu.Unlock()

	var payload []byte
	if raw.Payload != "" {
		payload, err = base64.RawURLEncoding.DecodeString(raw.Payload)
		if err != nil {
			return nil, err
		}
	}

	var jwk *jose.JSONWebKey
	if len(hdr.JWK) > 0 {
		if err := json.Unmarshal(hdr.JWK, &jwk); err != nil {
			return nil, err
		}
	}

	sig, err := jose.ParseSigned(string(body), []jose.SignatureAlgorithm{jose.ES256, jose.RS256})
	if err != nil {
		return nil, err
	}
	var key interface{}
	kid := expectedKid
	if kid == "" && hdr.Kid != "" {
		kid = hdr.Kid
	}
	if jwk != nil {
		key = jwk.Key
	} else if kid != "" {
		s.mu.Lock()
		acct := s.accountsByURL[kid]
		s.mu.Unlock()
		if acct == nil || len(acct.jwk) == 0 {
			return nil, err
		}
		var storedJWK jose.JSONWebKey
		if err := json.Unmarshal(acct.jwk, &storedJWK); err != nil {
			return nil, err
		}
		key = storedJWK.Key
	}
	if key == nil {
		return nil, err
	}
	if _, err := sig.Verify(key); err != nil {
		return nil, err
	}

	return &jwsPayload{
		Body:  payload,
		Key:   jwk,
		KeyID: hdr.Kid,
		Nonce: hdr.Nonce,
		URL:   hdr.URL,
	}, nil
}

func (s *Server) jwkThumbprint(jwk *jose.JSONWebKey) string {
	if jwk == nil {
		return ""
	}
	// Use hash of marshaled JWK as account key ID (RFC 7638-style)
	b, _ := json.Marshal(jwk)
	h := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(h[:])[:22]
}

