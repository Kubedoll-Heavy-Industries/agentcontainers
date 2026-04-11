package oidc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// MaxTTL is the maximum allowed token TTL (1 hour).
const MaxTTL = time.Hour

// Claims represents the payload of a JWT issued by the OIDC issuer.
type Claims struct {
	Iss         string   `json:"iss"`
	Sub         string   `json:"sub"`
	Aud         []string `json:"aud"`
	Exp         int64    `json:"exp"`
	Iat         int64    `json:"iat"`
	Nbf         int64    `json:"nbf"`
	SessionID   string   `json:"session_id,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	ContainerID string   `json:"container_id,omitempty"`
}

// MintOptions configures a JWT to be minted.
type MintOptions struct {
	Subject     string
	Audience    []string
	Scopes      []string
	SessionID   string
	ContainerID string
	TTL         time.Duration
}

// Mint creates and signs a JWT with the given options.
// The token is signed with ES256 (ECDSA P-256 + SHA-256).
func (iss *Issuer) Mint(opts MintOptions) (string, error) {
	if opts.Subject == "" {
		return "", fmt.Errorf("mint jwt: subject must not be empty")
	}
	if len(opts.Audience) == 0 {
		return "", fmt.Errorf("mint jwt: audience must not be empty")
	}
	if opts.TTL <= 0 {
		return "", fmt.Errorf("mint jwt: TTL must be positive")
	}
	if opts.TTL > MaxTTL {
		return "", fmt.Errorf("mint jwt: TTL %v exceeds maximum %v", opts.TTL, MaxTTL)
	}

	now := time.Now()
	claims := Claims{
		Iss:         iss.issuerURL,
		Sub:         opts.Subject,
		Aud:         opts.Audience,
		Exp:         now.Add(opts.TTL).Unix(),
		Iat:         now.Unix(),
		Nbf:         now.Unix(),
		SessionID:   opts.SessionID,
		Scopes:      opts.Scopes,
		ContainerID: opts.ContainerID,
	}

	header := map[string]string{
		"alg": "ES256",
		"typ": "JWT",
		"kid": iss.kid,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("mint jwt: marshal header: %w", err)
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("mint jwt: marshal payload: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	hash := sha256.Sum256([]byte(signingInput))
	derSig, err := ecdsa.SignASN1(rand.Reader, iss.key, hash[:])
	if err != nil {
		return "", fmt.Errorf("mint jwt: sign: %w", err)
	}

	sig, err := encodeECDSASignature(derSig, iss.key.Params().BitSize)
	if err != nil {
		return "", fmt.Errorf("mint jwt: encode signature: %w", err)
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64, nil
}
