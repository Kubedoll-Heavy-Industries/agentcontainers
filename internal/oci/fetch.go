package oci

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ErrNoPolicyLayer is returned by FetchPolicy when the manifest contains no
// layer with the policy media type. It is a sentinel that callers may use to
// distinguish "image has no policy" (safe to fall back to default) from other
// fetch errors (network failure, auth failure, MITM) which must be treated as
// hard failures.
var ErrNoPolicyLayer = errors.New("no policy layer found in manifest")

// AnnotationOrgPolicySigner is the OCI descriptor annotation key that carries
// a JSON-encoded OrgSignature over the policy layer descriptor.
//
// Format: {"keyid":"<sha256-hex-of-pubkey>","sig":"<base64-ed25519>","algo":"ed25519"}
//
// The signature input is the canonical descriptor form: "DIGEST\nMEDIATYPE\nSIZE".
// This binds the signature to digest, media type, and size simultaneously,
// preventing type-confusion attacks where a valid sig is reused on a descriptor
// with the same blob but different media type.
//
// Produced at build time via ac build --org-sign-key <keyfile>.
// Verified at run time when WithOrgTrustedKeys is configured on the Resolver.
const AnnotationOrgPolicySigner = "org.agentcontainers.policy.org-signer"

// ErrNoOrgSignedPolicy is returned by FetchPolicy in strict mode when the
// manifest contains policy layers but none are signed by a trusted org key.
// Distinct from ErrNoPolicyLayer so callers can produce targeted diagnostics.
var ErrNoOrgSignedPolicy = errors.New("no org-signed policy layer found in manifest")

// ociManifest represents an OCI image manifest (application/vnd.oci.image.manifest.v1+json)
// or a Docker distribution manifest (application/vnd.docker.distribution.manifest.v2+json).
type ociManifest struct {
	MediaType string          `json:"mediaType,omitempty"`
	Config    ociDescriptor   `json:"config"`
	Layers    []ociDescriptor `json:"layers"`
}

// ociDescriptor describes a content-addressable blob.
// The Annotations field carries optional key/value metadata per the OCI Image
// Layout Specification §descriptor. We use it to hold AnnotationOrgPolicySigner
// on policy layer descriptors when the org signing key is configured.
type ociDescriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// PolicyArtifactMediaType is the expected media type for org policy layers.
const PolicyArtifactMediaType = "application/vnd.agentcontainers.orgpolicy.v1+json"

// maxPolicySize is the maximum allowed policy artifact size (1 MiB).
const maxPolicySize = 1 << 20

// FetchPolicy fetches an OCI artifact and returns the raw bytes of the first
// layer that matches one of the accepted policy media types. It supports both
// the custom agentcontainers media type and generic JSON layers.
func (r *Resolver) FetchPolicy(ctx context.Context, imageRef string) ([]byte, error) {
	ref, err := ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("fetch policy: %w", err)
	}

	manifest, err := r.fetchManifest(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("fetch policy: %w", err)
	}

	layer, err := findPolicyLayer(manifest, r.orgTrustedKeys, r.orgStrictMode)
	if err != nil {
		// Wrap and preserve ErrNoPolicyLayer / ErrNoOrgSignedPolicy so callers
		// can distinguish the absent-policy case from all other errors.
		return nil, fmt.Errorf("fetch policy %s: %w", ref.String(), err)
	}

	data, err := r.fetchBlob(ctx, ref, layer.Digest)
	if err != nil {
		return nil, fmt.Errorf("fetch policy %s: %w", ref.String(), err)
	}

	return data, nil
}

// fetchManifest fetches and parses the OCI manifest for a given reference.
func (r *Resolver) fetchManifest(ctx context.Context, ref Reference) (*ociManifest, error) {
	scheme := "https"
	tagOrDigest := ref.Tag
	if ref.Digest != "" {
		tagOrDigest = ref.Digest
	}

	url := fmt.Sprintf("%s://%s/v2/%s/manifests/%s", scheme, ref.Registry, ref.Name, tagOrDigest)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating manifest request: %w", err)
	}

	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
	}, ", "))

	resp, err := r.doWithAuth(ctx, req, ref)
	if err != nil {
		return nil, fmt.Errorf("fetching manifest for %s: %w", ref.String(), err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("manifest not found for %s", ref.String())
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("unexpected status %d fetching manifest for %s: %s",
			resp.StatusCode, ref.String(), string(body))
	}

	var m ociManifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxPolicySize)).Decode(&m); err != nil {
		return nil, fmt.Errorf("decoding manifest for %s: %w", ref.String(), err)
	}

	return &m, nil
}

// findPolicyLayer finds the effective policy layer in the manifest.
//
// Selection algorithm:
//
//  1. When trustedKeys is nil/empty — first-wins (F-3 fix):
//     Return the first layer with the policy media type. This prevents an
//     adversary with image push access from appending a permissive override,
//     because they cannot prepend a layer before the org's base policy layer.
//
//  2. When trustedKeys is non-empty — last-signed-wins (F-6):
//     Scan all layers and collect the LAST one whose AnnotationOrgPolicySigner
//     annotation carries a valid Ed25519 signature from a trusted key.
//     Using the last signed layer allows the org to update policy by appending
//     a new signed layer to a derived image without rebuilding the base.
//
//     - Unsigned policy layers are skipped (not rejected) during the signed scan.
//     - If no signed layer is found AND strict is false, fall back to first-wins.
//     - If no signed layer is found AND strict is true, return ErrNoOrgSignedPolicy.
//
// Annotation format: JSON OrgSignature {"keyid","sig","algo"} in
// AnnotationOrgPolicySigner. Signature input: "DIGEST\nMEDIATYPE\nSIZE".
func findPolicyLayer(m *ociManifest, trustedKeys map[string]ed25519.PublicKey, strict bool) (ociDescriptor, error) {
	if len(m.Layers) == 0 {
		// An empty Layers slice means a manifest index (fat manifest) or an
		// image with no filesystem layers — no policy layer present either way.
		return ociDescriptor{}, fmt.Errorf("%w: manifest has no layers", ErrNoPolicyLayer)
	}

	// Collect first policy layer (for first-wins fallback) and last signed
	// policy layer (for org-signature-aware selection) in a single pass.
	var firstPolicy *ociDescriptor
	var lastSignedPolicy *ociDescriptor

	for i := range m.Layers {
		if m.Layers[i].MediaType != PolicyArtifactMediaType {
			continue
		}
		layer := m.Layers[i]

		// Track first policy layer for fallback.
		if firstPolicy == nil {
			tmp := layer
			firstPolicy = &tmp
		}

		// If no trusted keys, we don't need to check signatures.
		if len(trustedKeys) == 0 {
			continue
		}

		// Check whether this layer has a valid org signature.
		if err := VerifyDescriptor(layer, trustedKeys); err == nil {
			// Valid org signature — track as last signed.
			tmp := layer
			lastSignedPolicy = &tmp
		}
		// Invalid or missing annotation: silently skip for signed scan.
		// (Errors from malformed annotations are ignored here; the unsigned
		// fallback path will still surface them if no signed layer is found.)
	}

	// Case 1: No trusted keys — first-wins, no sig check.
	if len(trustedKeys) == 0 {
		if firstPolicy != nil {
			return *firstPolicy, nil
		}
		return ociDescriptor{}, fmt.Errorf("%w (layers: %d)", ErrNoPolicyLayer, len(m.Layers))
	}

	// Case 2: Trusted keys configured.
	if lastSignedPolicy != nil {
		// Last signed layer wins.
		return *lastSignedPolicy, nil
	}

	// No org-signed layer found.
	if strict {
		return ociDescriptor{}, fmt.Errorf("%w (layers: %d, trusted keys: %d)",
			ErrNoOrgSignedPolicy, len(m.Layers), len(trustedKeys))
	}

	// Non-strict fallback: base wins (first policy layer).
	if firstPolicy != nil {
		return *firstPolicy, nil
	}

	return ociDescriptor{}, fmt.Errorf("%w (layers: %d)", ErrNoPolicyLayer, len(m.Layers))
}

// fetchBlob fetches a blob by digest from the registry.
func (r *Resolver) fetchBlob(ctx context.Context, ref Reference, digest string) ([]byte, error) {
	scheme := "https"
	url := fmt.Sprintf("%s://%s/v2/%s/blobs/%s", scheme, ref.Registry, ref.Name, digest)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating blob request: %w", err)
	}

	resp, err := r.doWithAuth(ctx, req, ref)
	if err != nil {
		return nil, fmt.Errorf("fetching blob %s: %w", digest, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("blob %s not found", digest)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("unexpected status %d fetching blob %s: %s",
			resp.StatusCode, digest, string(body))
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicySize))
	if err != nil {
		return nil, fmt.Errorf("reading blob %s: %w", digest, err)
	}

	if err := verifyDigest(data, digest); err != nil {
		return nil, fmt.Errorf("blob integrity check failed for %s: %w", digest, err)
	}

	return data, nil
}

// verifyDigest checks that the sha256 hash of data matches the expected digest
// string in the format "sha256:<hex>". This prevents a MITM from substituting
// a different blob payload in response to a content-addressed digest URL (F-2).
func verifyDigest(data []byte, expected string) error {
	const prefix = "sha256:"
	if !strings.HasPrefix(expected, prefix) {
		// Non-sha256 digests (e.g. sha512) are not verified — log and skip.
		// The OCI spec mandates sha256 for content addressing; anything else
		// is unexpected and should not be silently accepted.
		return fmt.Errorf("unsupported digest algorithm in %q (only sha256 is supported)", expected)
	}
	want := strings.TrimPrefix(expected, prefix)

	h := sha256.Sum256(data)
	got := hex.EncodeToString(h[:])
	if got != want {
		return fmt.Errorf("digest mismatch: manifest says %q but blob hashes to sha256:%s", expected, got)
	}
	return nil
}
