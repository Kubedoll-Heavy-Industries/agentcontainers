package oci

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// OrgSignature is the JSON structure stored in AnnotationOrgPolicySigner.
// It binds the org signing key identity to the specific policy layer descriptor.
type OrgSignature struct {
	// KeyID is the hex-encoded SHA-256 fingerprint of the raw Ed25519 public key bytes.
	KeyID string `json:"keyid"`
	// Sig is the base64-encoded Ed25519 signature over the descriptor canonical form.
	Sig string `json:"sig"`
	// Algo is the signing algorithm; always "ed25519".
	Algo string `json:"algo"`
}

// descriptorSignInput returns the canonical byte slice signed/verified for a
// policy layer descriptor: "DIGEST\nMEDIATYPE\nSIZE".
// Signing over digest+mediaType+size prevents an attacker from reusing a valid
// signature from one descriptor on a different descriptor with the same digest
// but different media type (type confusion) or size (length extension).
func descriptorSignInput(digest, mediaType string, size int64) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%d", digest, mediaType, size))
}

// OrgKeyID computes the key ID for an Ed25519 public key as the hex-encoded
// SHA-256 of the raw 32-byte public key material.
func OrgKeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}

// SignDescriptor signs the policy layer descriptor with the given Ed25519 private
// key and returns the JSON-encoded OrgSignature ready for use as the
// AnnotationOrgPolicySigner annotation value.
func SignDescriptor(privKey ed25519.PrivateKey, desc ociDescriptor) (string, error) {
	input := descriptorSignInput(desc.Digest, desc.MediaType, desc.Size)
	sig := ed25519.Sign(privKey, input)
	pub := privKey.Public().(ed25519.PublicKey)

	osig := OrgSignature{
		KeyID: OrgKeyID(pub),
		Sig:   base64.StdEncoding.EncodeToString(sig),
		Algo:  "ed25519",
	}

	data, err := json.Marshal(osig)
	if err != nil {
		return "", fmt.Errorf("marshaling org signature: %w", err)
	}
	return string(data), nil
}

// VerifyDescriptor verifies the AnnotationOrgPolicySigner annotation on a
// descriptor against a set of trusted org public keys (keyed by keyid).
// Returns nil if the descriptor carries a valid signature by any trusted key,
// or an error describing the failure.
func VerifyDescriptor(desc ociDescriptor, trustedKeys map[string]ed25519.PublicKey) error {
	raw, ok := desc.Annotations[AnnotationOrgPolicySigner]
	if !ok {
		return fmt.Errorf("descriptor %q has no %s annotation", desc.Digest, AnnotationOrgPolicySigner)
	}

	var osig OrgSignature
	if err := json.Unmarshal([]byte(raw), &osig); err != nil {
		return fmt.Errorf("descriptor %q: malformed %s annotation: %w",
			desc.Digest, AnnotationOrgPolicySigner, err)
	}

	if osig.Algo != "ed25519" {
		return fmt.Errorf("descriptor %q: unsupported signing algo %q (want ed25519)", desc.Digest, osig.Algo)
	}

	sig, err := base64.StdEncoding.DecodeString(osig.Sig)
	if err != nil {
		return fmt.Errorf("descriptor %q: malformed sig in annotation: %w", desc.Digest, err)
	}

	pub, ok := trustedKeys[osig.KeyID]
	if !ok {
		return fmt.Errorf("descriptor %q: key id %q is not in the trusted org keys", desc.Digest, osig.KeyID)
	}

	input := descriptorSignInput(desc.Digest, desc.MediaType, desc.Size)
	if !ed25519.Verify(pub, input, sig) {
		return fmt.Errorf("descriptor %q: org-signer signature verification failed (key %s)", desc.Digest, osig.KeyID)
	}

	return nil
}

// SignPolicyDescriptorDigest is a convenience function for backward-compat tests:
// signs only the digest string (old format). Prefer SignDescriptor for new code.
func SignPolicyDescriptorDigest(privKey ed25519.PrivateKey, descriptorDigest string) string {
	sig := ed25519.Sign(privKey, []byte(descriptorDigest))
	return base64.StdEncoding.EncodeToString(sig)
}
