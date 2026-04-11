package oci

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// sha256hex returns the hex-encoded SHA-256 digest of data.
func sha256hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// uploadBlob performs a monolithic blob upload (POST to get upload URL, then
// PUT to complete) following the OCI Distribution Spec.
func (r *Resolver) uploadBlob(ctx context.Context, ref Reference, data []byte, digest string) error {
	base := r.registryBaseURL(ref)

	// Start upload session.
	startURL := fmt.Sprintf("%s/v2/%s/blobs/uploads/", base, ref.Name)
	startReq, err := http.NewRequestWithContext(ctx, http.MethodPost, startURL, nil)
	if err != nil {
		return err
	}
	startReq.Header.Set("Content-Length", "0")

	startResp, err := r.doWithAuth(ctx, startReq, ref)
	if err != nil {
		return err
	}
	defer startResp.Body.Close() //nolint:errcheck
	_, _ = io.Copy(io.Discard, startResp.Body)

	if startResp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("upload start: status %d", startResp.StatusCode)
	}

	// Complete upload with PUT.
	location := startResp.Header.Get("Location")
	if location == "" {
		return fmt.Errorf("upload start: no Location header")
	}

	// Append digest query parameter.
	sep := "?"
	if strings.Contains(location, "?") {
		sep = "&"
	}
	putURL := location + sep + "digest=" + digest

	// If the location is relative, make it absolute.
	if strings.HasPrefix(location, "/") {
		putURL = base + location + sep + "digest=" + digest
	}

	putReq, err := http.NewRequestWithContext(ctx, http.MethodPut, putURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	putReq.Header.Set("Content-Type", "application/octet-stream")
	putReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))

	putResp, err := r.doWithAuth(ctx, putReq, ref)
	if err != nil {
		return err
	}
	defer putResp.Body.Close() //nolint:errcheck

	if putResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(putResp.Body, 1024))
		return fmt.Errorf("upload complete: status %d: %s", putResp.StatusCode, body)
	}

	return nil
}

// uploadManifest pushes the manifest to the registry using the tag (if present)
// or the manifest digest as the reference.
func (r *Resolver) uploadManifest(ctx context.Context, ref Reference, manifest []byte, digest string) error {
	base := r.registryBaseURL(ref)

	// Prefer to push by tag, fall back to digest.
	reference := ref.Tag
	if reference == "" {
		reference = digest
	}
	url := fmt.Sprintf("%s/v2/%s/manifests/%s", base, ref.Name, reference)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(manifest))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")

	resp, err := r.doWithAuth(ctx, req, ref)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("manifest upload: status %d: %s", resp.StatusCode, body)
	}

	return nil
}

// AppendPolicyLayer fetches the current manifest for imageRef, appends a
// policy layer (mediaType application/vnd.agentcontainers.orgpolicy.v1+json),
// uploads the policy blob, and re-pushes the manifest under the same tag.
// The updated manifest digest is returned.
//
// This implements the PRD-017 "policy as final OCI image layer" design: the
// policy is baked into the image at build time, so policy pinning and policy
// freshness are identical to image pinning and image freshness.
//
// If orgSignerKey is non-nil, the policy layer descriptor is annotated with
// AnnotationOrgPolicySigner — a base64-encoded Ed25519 signature over the
// descriptor's digest string. This enables signer-aware policy selection at
// run time (WithOrgSignerPublicKey) and directly addresses the F-3 / F-6 attack
// where an adversary with image write access appends a permissive policy layer:
// they cannot forge the org's Ed25519 signature, so their layer is ignored.
func (r *Resolver) AppendPolicyLayer(ctx context.Context, imageRef string, policyJSON []byte, orgSignerKey ed25519.PrivateKey) (string, error) {
	ref, err := ParseReference(imageRef)
	if err != nil {
		return "", fmt.Errorf("append policy layer: %w", err)
	}

	// Fetch current manifest to extend it.
	manifest, err := r.fetchManifest(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("append policy layer: fetching manifest: %w", err)
	}

	// Upload policy blob.
	blobDigest := fmt.Sprintf("sha256:%s", sha256hex(policyJSON))
	if err := r.uploadBlob(ctx, ref, policyJSON, blobDigest); err != nil {
		return "", fmt.Errorf("append policy layer: uploading policy blob: %w", err)
	}

	// Build the policy descriptor, optionally annotating it with the org signature.
	desc := ociDescriptor{
		MediaType: PolicyArtifactMediaType,
		Digest:    blobDigest,
		Size:      int64(len(policyJSON)),
	}
	if orgSignerKey != nil {
		annotationValue, err := SignDescriptor(orgSignerKey, desc)
		if err != nil {
			return "", fmt.Errorf("append policy layer: signing descriptor: %w", err)
		}
		desc.Annotations = map[string]string{
			AnnotationOrgPolicySigner: annotationValue,
		}
	}

	// Append policy descriptor to layers. Any existing policy layers in the
	// manifest are preserved. The last org-signed layer wins at verification
	// time, so appending a new signed layer naturally updates the effective org
	// policy (the new signed layer becomes the last one, taking precedence).
	manifest.Layers = append(manifest.Layers, desc)

	// Re-marshal the manifest and push it.
	updatedManifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("append policy layer: marshaling manifest: %w", err)
	}

	manifestDigest := fmt.Sprintf("sha256:%s", sha256hex(updatedManifestJSON))
	if err := r.uploadManifest(ctx, ref, updatedManifestJSON, manifestDigest); err != nil {
		return "", fmt.Errorf("append policy layer: pushing updated manifest: %w", err)
	}

	return manifestDigest, nil
}

// registryBaseURL returns the https base URL for the registry in a parsed
// Reference. Tests using httptest.NewTLSServer pass the address as the
// registry (e.g., "127.0.0.1:PORT"), and the TLS client already trusts the
// test certificate, so we always use https.
func (r *Resolver) registryBaseURL(ref Reference) string {
	return "https://" + ref.Registry
}
