package oidc

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNewIssuer(t *testing.T) {
	iss, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer() error: %v", err)
	}
	if iss.key == nil {
		t.Fatal("expected non-nil key")
	}
	if iss.kid == "" {
		t.Fatal("expected non-empty kid")
	}
}

func TestIssuerStartStop(t *testing.T) {
	iss, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer() error: %v", err)
	}
	if err := iss.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer func() { _ = iss.Stop(context.Background()) }()

	// Verify the server responds.
	resp, err := http.Get(iss.URL() + "/jwks")
	if err != nil {
		t.Fatalf("GET /jwks error: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /jwks status = %d, want 200", resp.StatusCode)
	}

	if err := iss.Stop(context.Background()); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
}

func TestOIDCDiscovery(t *testing.T) {
	iss, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer() error: %v", err)
	}
	if err := iss.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer func() { _ = iss.Stop(context.Background()) }()

	resp, err := http.Get(iss.URL() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal discovery: %v", err)
	}

	// Required fields.
	for _, field := range []string{"issuer", "jwks_uri", "id_token_signing_alg_values_supported"} {
		if _, ok := doc[field]; !ok {
			t.Errorf("missing required field %q", field)
		}
	}
	if got := doc["issuer"].(string); got != iss.URL() {
		t.Errorf("issuer = %q, want %q", got, iss.URL())
	}
	if got := doc["jwks_uri"].(string); got != iss.URL()+"/jwks" {
		t.Errorf("jwks_uri = %q, want %q", got, iss.URL()+"/jwks")
	}
}

func TestJWKS(t *testing.T) {
	iss, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer() error: %v", err)
	}
	if err := iss.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	defer func() { _ = iss.Stop(context.Background()) }()

	resp, err := http.Get(iss.URL() + "/jwks")
	if err != nil {
		t.Fatalf("GET /jwks error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}

	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	key := jwks.Keys[0]
	if key.Kty != "EC" {
		t.Errorf("kty = %q, want EC", key.Kty)
	}
	if key.Crv != "P-256" {
		t.Errorf("crv = %q, want P-256", key.Crv)
	}
	if key.Alg != "ES256" {
		t.Errorf("alg = %q, want ES256", key.Alg)
	}
	if key.Use != "sig" {
		t.Errorf("use = %q, want sig", key.Use)
	}
	if key.Kid == "" {
		t.Error("expected non-empty kid")
	}
}

func TestMintJWT(t *testing.T) {
	iss, err := NewIssuer(WithIssuerURL("https://agent.example.com"))
	if err != nil {
		t.Fatalf("NewIssuer() error: %v", err)
	}

	token, err := iss.Mint(MintOptions{
		Subject:     "container:abc123",
		Audience:    []string{"https://sts.amazonaws.com"},
		Scopes:      []string{"s3:read"},
		SessionID:   "sess-1",
		ContainerID: "abc123",
		TTL:         15 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Mint() error: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	// Decode and verify header.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var header map[string]string
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if header["alg"] != "ES256" {
		t.Errorf("header alg = %q, want ES256", header["alg"])
	}
	if header["typ"] != "JWT" {
		t.Errorf("header typ = %q, want JWT", header["typ"])
	}
	if header["kid"] == "" {
		t.Error("expected non-empty kid in header")
	}

	// Decode and verify payload.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	if claims.Iss != "https://agent.example.com" {
		t.Errorf("iss = %q, want https://agent.example.com", claims.Iss)
	}
	if claims.Sub != "container:abc123" {
		t.Errorf("sub = %q, want container:abc123", claims.Sub)
	}
	if len(claims.Aud) != 1 || claims.Aud[0] != "https://sts.amazonaws.com" {
		t.Errorf("aud = %v, want [https://sts.amazonaws.com]", claims.Aud)
	}
	if claims.SessionID != "sess-1" {
		t.Errorf("session_id = %q, want sess-1", claims.SessionID)
	}
	if claims.ContainerID != "abc123" {
		t.Errorf("container_id = %q, want abc123", claims.ContainerID)
	}
	if claims.Exp <= claims.Iat {
		t.Error("exp should be after iat")
	}
}

func TestMintJWTMaxTTL(t *testing.T) {
	iss, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer() error: %v", err)
	}
	_, err = iss.Mint(MintOptions{
		Subject:  "test",
		Audience: []string{"aud"},
		TTL:      2 * time.Hour,
	})
	if err == nil {
		t.Fatal("expected error for TTL > 1h")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("error = %q, want contains 'exceeds maximum'", err.Error())
	}
}

func TestMintJWTEmptySubject(t *testing.T) {
	iss, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer() error: %v", err)
	}
	_, err = iss.Mint(MintOptions{
		Subject:  "",
		Audience: []string{"aud"},
		TTL:      5 * time.Minute,
	})
	if err == nil {
		t.Fatal("expected error for empty subject")
	}
	if !strings.Contains(err.Error(), "subject") {
		t.Errorf("error = %q, want contains 'subject'", err.Error())
	}
}

func TestMintJWTEmptyAudience(t *testing.T) {
	iss, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer() error: %v", err)
	}
	_, err = iss.Mint(MintOptions{
		Subject: "test",
		TTL:     5 * time.Minute,
	})
	if err == nil {
		t.Fatal("expected error for empty audience")
	}
	if !strings.Contains(err.Error(), "audience") {
		t.Errorf("error = %q, want contains 'audience'", err.Error())
	}
}

func TestMintJWTVerifySignature(t *testing.T) {
	iss, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer() error: %v", err)
	}

	token, err := iss.Mint(MintOptions{
		Subject:  "verify-test",
		Audience: []string{"test-aud"},
		TTL:      10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Mint() error: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d", len(parts))
	}

	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	// sigBytes is R||S, each 32 bytes for P-256.
	if len(sigBytes) != 64 {
		t.Fatalf("signature length = %d, want 64", len(sigBytes))
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	hash := sha256.Sum256([]byte(signingInput))
	if !ecdsa.Verify(&iss.key.PublicKey, hash[:], r, s) {
		t.Fatal("signature verification failed")
	}
}

func TestJWKFromECDSA(t *testing.T) {
	key := iss_testKey(t)
	kid := "test-kid"
	jwk := NewJWKFromECDSA(&key.PublicKey, kid)

	if jwk.Kty != "EC" {
		t.Errorf("kty = %q, want EC", jwk.Kty)
	}
	if jwk.Crv != "P-256" {
		t.Errorf("crv = %q, want P-256", jwk.Crv)
	}
	if jwk.Alg != "ES256" {
		t.Errorf("alg = %q, want ES256", jwk.Alg)
	}
	if jwk.Use != "sig" {
		t.Errorf("use = %q, want sig", jwk.Use)
	}
	if jwk.Kid != kid {
		t.Errorf("kid = %q, want %q", jwk.Kid, kid)
	}
	if jwk.X == "" {
		t.Error("expected non-empty X")
	}
	if jwk.Y == "" {
		t.Error("expected non-empty Y")
	}

	// Verify X and Y decode to valid coordinates by constructing an
	// uncompressed SEC 1 point (0x04 || X || Y) and parsing it with
	// crypto/ecdh, which validates the point is on the P-256 curve.
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		t.Fatalf("decode X: %v", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		t.Fatalf("decode Y: %v", err)
	}
	uncompressed := make([]byte, 1+len(xBytes)+len(yBytes))
	uncompressed[0] = 0x04
	copy(uncompressed[1:], xBytes)
	copy(uncompressed[1+len(xBytes):], yBytes)
	if _, err := ecdh.P256().NewPublicKey(uncompressed); err != nil {
		t.Fatalf("decoded coordinates are not on the P-256 curve: %v", err)
	}
}

func TestIssuerOptions(t *testing.T) {
	t.Run("WithAddr", func(t *testing.T) {
		iss, err := NewIssuer(WithAddr("127.0.0.1:0"))
		if err != nil {
			t.Fatalf("NewIssuer() error: %v", err)
		}
		if iss.addr != "127.0.0.1:0" {
			t.Errorf("addr = %q, want 127.0.0.1:0", iss.addr)
		}
	})

	t.Run("WithIssuerURL", func(t *testing.T) {
		iss, err := NewIssuer(WithIssuerURL("https://custom.example.com"))
		if err != nil {
			t.Fatalf("NewIssuer() error: %v", err)
		}
		if iss.issuerURL != "https://custom.example.com" {
			t.Errorf("issuerURL = %q, want https://custom.example.com", iss.issuerURL)
		}
	})

	t.Run("DefaultAddr", func(t *testing.T) {
		iss, err := NewIssuer()
		if err != nil {
			t.Fatalf("NewIssuer() error: %v", err)
		}
		if iss.addr != "127.0.0.1:0" {
			t.Errorf("default addr = %q, want 127.0.0.1:0", iss.addr)
		}
	})
}

func iss_testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), strings.NewReader(strings.Repeat("deterministic-seed-for-testing!!", 10)))
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}
