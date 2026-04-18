package oidc

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// JWK represents a JSON Web Key (RFC 7517) for an ECDSA public key.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// JWKS represents a JSON Web Key Set (RFC 7517 Section 5).
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// ecdsaCoordinates extracts the X and Y coordinates from an ECDSA P-256
// public key using the uncompressed point encoding (0x04 || X || Y),
// avoiding the deprecated key.X/key.Y fields.
func ecdsaCoordinates(key *ecdsa.PublicKey) (x, y []byte) {
	// Bytes returns the uncompressed point encoding: 0x04 || X || Y.
	// For a valid P-256 key this cannot fail.
	raw, _ := key.Bytes()
	byteLen := (key.Params().BitSize + 7) / 8
	return raw[1 : 1+byteLen], raw[1+byteLen:]
}

// NewJWKFromECDSA converts an ECDSA P-256 public key to JWK format.
// The kid is a SHA-256 thumbprint of the JWK canonical form (RFC 7638).
func NewJWKFromECDSA(key *ecdsa.PublicKey, kid string) *JWK {
	x, y := ecdsaCoordinates(key)
	return &JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(x),
		Y:   base64.RawURLEncoding.EncodeToString(y),
		Kid: kid,
		Use: "sig",
		Alg: "ES256",
	}
}

// thumbprint computes the JWK thumbprint (RFC 7638) for an ECDSA P-256 key.
// The canonical form for EC keys is: {"crv":"P-256","kty":"EC","x":"...","y":"..."}
func thumbprint(key *ecdsa.PublicKey) string {
	x, y := ecdsaCoordinates(key)
	xEnc := base64.RawURLEncoding.EncodeToString(x)
	yEnc := base64.RawURLEncoding.EncodeToString(y)
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, xEnc, yEnc)
	h := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// marshalJWKS serializes a JWKS to JSON.
func marshalJWKS(jwks *JWKS) ([]byte, error) {
	data, err := json.Marshal(jwks)
	if err != nil {
		return nil, fmt.Errorf("marshal jwks: %w", err)
	}
	return data, nil
}

// encodeECDSASignature converts an ASN.1 DER-encoded ECDSA signature to the
// R||S fixed-size format required by JWS (RFC 7518 Section 3.4).
func encodeECDSASignature(derSig []byte, keySize int) ([]byte, error) {
	// ASN.1 SEQUENCE { INTEGER r, INTEGER s }
	r, s, err := parseASN1Signature(derSig)
	if err != nil {
		return nil, fmt.Errorf("parse asn1 signature: %w", err)
	}
	byteLen := (keySize + 7) / 8
	out := make([]byte, 2*byteLen)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(out[byteLen-len(rBytes):byteLen], rBytes)
	copy(out[2*byteLen-len(sBytes):], sBytes)
	return out, nil
}

// parseASN1Signature extracts r and s from a DER-encoded ECDSA signature.
func parseASN1Signature(der []byte) (*big.Int, *big.Int, error) {
	if len(der) < 6 {
		return nil, nil, fmt.Errorf("signature too short")
	}
	if der[0] != 0x30 {
		return nil, nil, fmt.Errorf("expected SEQUENCE tag")
	}
	// Skip the SEQUENCE tag and length
	pos := 2
	if der[1]&0x80 != 0 {
		// Long form length (unlikely for ECDSA signatures but handle it)
		lenBytes := int(der[1] & 0x7f)
		pos = 2 + lenBytes
	}

	r, newPos, err := parseASN1Integer(der, pos)
	if err != nil {
		return nil, nil, fmt.Errorf("parse r: %w", err)
	}
	s, _, err := parseASN1Integer(der, newPos)
	if err != nil {
		return nil, nil, fmt.Errorf("parse s: %w", err)
	}
	return r, s, nil
}

// parseASN1Integer parses a DER INTEGER at the given position.
func parseASN1Integer(der []byte, pos int) (*big.Int, int, error) {
	if pos >= len(der) || der[pos] != 0x02 {
		return nil, 0, fmt.Errorf("expected INTEGER tag at position %d", pos)
	}
	pos++
	if pos >= len(der) {
		return nil, 0, fmt.Errorf("unexpected end of data")
	}
	length := int(der[pos])
	pos++
	if pos+length > len(der) {
		return nil, 0, fmt.Errorf("integer length exceeds data")
	}
	val := new(big.Int).SetBytes(der[pos : pos+length])
	return val, pos + length, nil
}
