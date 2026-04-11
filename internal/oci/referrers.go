package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// SigstoreBundleArtifactType is the OCI artifact type for Sigstore bundles.
const SigstoreBundleArtifactType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// maxReferrersSize is the maximum allowed referrers response size (1 MiB).
const maxReferrersSize = 1 << 20

// Referrer describes an artifact referencing an OCI manifest.
type Referrer struct {
	MediaType    string `json:"mediaType"`
	Digest       string `json:"digest"`
	Size         int64  `json:"size"`
	ArtifactType string `json:"artifactType"`
}

// ociIndex represents an OCI Image Index response from the Referrers API.
type ociIndex struct {
	MediaType string     `json:"mediaType"`
	Manifests []Referrer `json:"manifests"`
}

// ListReferrers queries the OCI Referrers API (GET /v2/<name>/referrers/<digest>)
// and returns matching referrers, optionally filtered by artifactType.
func (r *Resolver) ListReferrers(ctx context.Context, ref Reference, artifactType string) ([]Referrer, error) {
	if ref.Digest == "" {
		return nil, fmt.Errorf("referrers: digest is required")
	}

	scheme := "https"
	url := fmt.Sprintf("%s://%s/v2/%s/referrers/%s", scheme, ref.Registry, ref.Name, ref.Digest)
	if artifactType != "" {
		url += "?artifactType=" + artifactType
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("referrers: creating request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.oci.image.index.v1+json")

	resp, err := r.doWithAuth(ctx, req, ref)
	if err != nil {
		return nil, fmt.Errorf("referrers %s: %w", ref.String(), err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode == http.StatusNotFound {
		// No referrers or API not supported — return empty list.
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("referrers %s: unexpected status %d: %s",
			ref.String(), resp.StatusCode, string(body))
	}

	var idx ociIndex
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxReferrersSize)).Decode(&idx); err != nil {
		return nil, fmt.Errorf("referrers %s: decoding response: %w", ref.String(), err)
	}

	return idx.Manifests, nil
}

// FetchReferrerBlob fetches the raw content of a referrer's manifest and extracts
// the first layer's blob content. For Sigstore bundles, the bundle JSON is stored
// as a layer blob referenced by the referrer's manifest.
func (r *Resolver) FetchReferrerBlob(ctx context.Context, ref Reference, digest string) ([]byte, error) {
	// Fetch the referrer's manifest to find its layers.
	refWithDigest := Reference{
		Registry: ref.Registry,
		Name:     ref.Name,
		Digest:   digest,
	}

	manifest, err := r.fetchManifest(ctx, refWithDigest)
	if err != nil {
		return nil, fmt.Errorf("fetch referrer blob: %w", err)
	}

	if len(manifest.Layers) == 0 {
		return nil, fmt.Errorf("fetch referrer blob: referrer manifest has no layers")
	}

	// Fetch the first layer blob.
	data, err := r.fetchBlob(ctx, ref, manifest.Layers[0].Digest)
	if err != nil {
		return nil, fmt.Errorf("fetch referrer blob: %w", err)
	}

	return data, nil
}

// FetchSigstoreBundle fetches the first Sigstore bundle attached to the given
// image reference via the OCI Referrers API. Returns the raw bundle JSON and
// the referrer's digest.
func (r *Resolver) FetchSigstoreBundle(ctx context.Context, imageRef string) ([]byte, string, error) {
	ref, err := ParseReference(imageRef)
	if err != nil {
		return nil, "", fmt.Errorf("fetch sigstore bundle: %w", err)
	}

	// If the reference has a tag but no digest, resolve the tag first.
	if ref.Digest == "" {
		digest, err := r.resolveTag(ctx, ref)
		if err != nil {
			return nil, "", fmt.Errorf("fetch sigstore bundle: resolving tag: %w", err)
		}
		ref.Digest = digest
	}

	referrers, err := r.ListReferrers(ctx, ref, SigstoreBundleArtifactType)
	if err != nil {
		return nil, "", fmt.Errorf("fetch sigstore bundle: %w", err)
	}

	if len(referrers) == 0 {
		return nil, "", fmt.Errorf("fetch sigstore bundle: no Sigstore bundle found for %s", imageRef)
	}

	// Pick the first matching referrer.
	bundleRef := referrers[0]

	data, err := r.FetchReferrerBlob(ctx, ref, bundleRef.Digest)
	if err != nil {
		return nil, "", fmt.Errorf("fetch sigstore bundle: %w", err)
	}

	// Validate that the bundle is valid JSON.
	if !json.Valid(data) {
		return nil, "", fmt.Errorf("fetch sigstore bundle: bundle content is not valid JSON")
	}

	return data, bundleRef.Digest, nil
}

// BundlePath computes the filesystem path for saving a bundle, given a
// base directory and an image reference with a digest.
// Format: <baseDir>/<registry>/<name>/<digest>.sigstore.json
// Colons in the digest are replaced with hyphens for filesystem safety.
func BundlePath(baseDir, registry, name, digest string) string {
	safeDigest := strings.ReplaceAll(digest, ":", "-")
	return fmt.Sprintf("%s/%s/%s/%s.sigstore.json", baseDir, registry, name, safeDigest)
}
