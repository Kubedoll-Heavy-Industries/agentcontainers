package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
)

// Issuer is an embedded OIDC-compliant HTTP server that mints JWTs for
// container workloads to federate with cloud identity providers (AWS STS,
// GCP Workload Identity, Azure AD, etc.).
type Issuer struct {
	key       *ecdsa.PrivateKey
	kid       string
	issuerURL string
	addr      string
	server    *http.Server
	listener  net.Listener
}

// IssuerOption configures an Issuer.
type IssuerOption func(*issuerConfig)

type issuerConfig struct {
	addr      string
	issuerURL string
}

// WithAddr sets the listen address for the OIDC server.
func WithAddr(addr string) IssuerOption {
	return func(c *issuerConfig) {
		c.addr = addr
	}
}

// WithIssuerURL sets the issuer URL included in discovery documents and JWTs.
func WithIssuerURL(url string) IssuerOption {
	return func(c *issuerConfig) {
		c.issuerURL = url
	}
}

// NewIssuer creates a new OIDC issuer with an ephemeral ECDSA P-256 key pair.
func NewIssuer(opts ...IssuerOption) (*Issuer, error) {
	cfg := &issuerConfig{
		addr: "127.0.0.1:0",
	}
	for _, o := range opts {
		o(cfg)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ecdsa key: %w", err)
	}

	kid := thumbprint(&key.PublicKey)

	iss := &Issuer{
		key:       key,
		kid:       kid,
		issuerURL: cfg.issuerURL,
		addr:      cfg.addr,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", iss.discoveryHandler)
	mux.HandleFunc("GET /jwks", iss.jwksHandler)

	iss.server = &http.Server{
		Addr:    cfg.addr,
		Handler: mux,
	}

	return iss, nil
}

// Start begins serving the OIDC endpoints. It is non-blocking.
func (iss *Issuer) Start() error {
	ln, err := net.Listen("tcp", iss.addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	iss.listener = ln

	// If issuerURL was not explicitly set, derive it from the listener address.
	if iss.issuerURL == "" {
		iss.issuerURL = "http://" + ln.Addr().String()
	}

	go func() {
		if err := iss.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("oidc issuer: unexpected serve error: %v", err)
		}
	}()
	return nil
}

// Stop gracefully shuts down the OIDC server.
func (iss *Issuer) Stop(ctx context.Context) error {
	if iss.server == nil {
		return nil
	}
	if err := iss.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown oidc server: %w", err)
	}
	return nil
}

// URL returns the issuer URL. Only valid after Start.
func (iss *Issuer) URL() string {
	return iss.issuerURL
}

// discoveryHandler serves the OIDC discovery document.
func (iss *Issuer) discoveryHandler(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"issuer":                                iss.issuerURL,
		"jwks_uri":                              iss.issuerURL + "/jwks",
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"subject_types_supported":               []string{"public"},
		"response_types_supported":              []string{"id_token"},
		"grant_types_supported":                 []string{"implicit"},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// jwksHandler serves the JSON Web Key Set.
func (iss *Issuer) jwksHandler(w http.ResponseWriter, r *http.Request) {
	jwk := NewJWKFromECDSA(&iss.key.PublicKey, iss.kid)
	jwks := &JWKS{Keys: []JWK{*jwk}}
	data, err := marshalJWKS(jwks)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}
