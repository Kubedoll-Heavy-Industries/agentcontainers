// Package signing provides OCI artifact signing via Sigstore cosign.
package signing

import (
	"context"
	"time"
)

// Signer signs OCI artifact references (images, SBOMs, etc.) and returns
// the result including the signature digest and optional transparency log entry.
type Signer interface {
	// Sign signs the OCI artifact at the given reference. The reference must
	// include a digest (e.g. "registry.io/image@sha256:abc...").
	Sign(ctx context.Context, ref string, opts SignOptions) (*SignResult, error)
}

// SignOptions configures how an artifact is signed.
type SignOptions struct {
	// KeyPath is the path to a private key for key-based signing.
	// If empty, keyless (Fulcio + Rekor) signing is used.
	KeyPath string

	// KeylessIssuer is the OIDC issuer for keyless signing (e.g. "https://accounts.google.com").
	// Only used when KeyPath is empty.
	KeylessIssuer string

	// KeylessIdentity is the expected OIDC identity for keyless signing
	// (e.g. "user@example.com"). Only used when KeyPath is empty.
	KeylessIdentity string

	// RekorURL is the Rekor transparency log URL. Defaults to the public
	// Rekor instance if empty.
	RekorURL string

	// RegistryAuth is the registry authentication credentials in
	// "username:password" or base64-encoded format.
	RegistryAuth string

	// Annotations are key-value pairs attached to the signature.
	Annotations map[string]string
}

// SignResult contains the outcome of a signing operation.
type SignResult struct {
	// Ref is the original artifact reference that was signed.
	Ref string

	// Digest is the digest of the signed artifact.
	Digest string

	// SignatureDigest is the digest of the signature artifact stored in the registry.
	SignatureDigest string

	// RekorLogIndex is the Rekor transparency log entry index, if applicable.
	// -1 indicates no Rekor entry was created.
	RekorLogIndex int64

	// Certificate is the PEM-encoded Fulcio certificate, if keyless signing was used.
	Certificate string

	// SignedAt is the timestamp when the signing occurred.
	SignedAt time.Time
}
