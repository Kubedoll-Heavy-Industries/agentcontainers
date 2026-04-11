package oci

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListReferrers(t *testing.T) {
	wantDigest := "sha256:abc123"
	referrers := []Referrer{
		{
			MediaType:    "application/vnd.oci.image.manifest.v1+json",
			Digest:       "sha256:bundle1",
			Size:         1234,
			ArtifactType: SigstoreBundleArtifactType,
		},
		{
			MediaType:    "application/vnd.oci.image.manifest.v1+json",
			Digest:       "sha256:sbom1",
			Size:         5678,
			ArtifactType: "application/spdx+json",
		},
	}

	idx := ociIndex{
		MediaType: "application/vnd.oci.image.index.v1+json",
		Manifests: referrers,
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Verify the path matches /v2/<name>/referrers/<digest>
		if !strings.Contains(r.URL.Path, "/referrers/"+wantDigest) {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		_ = json.NewEncoder(w).Encode(idx)
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	ref := Reference{
		Registry: srv.Listener.Addr().String(),
		Name:     "myorg/myimage",
		Digest:   wantDigest,
	}

	got, err := resolver.ListReferrers(context.Background(), ref, "")
	if err != nil {
		t.Fatalf("ListReferrers() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListReferrers() returned %d referrers, want 2", len(got))
	}
	if got[0].Digest != "sha256:bundle1" {
		t.Errorf("referrer[0].Digest = %q, want %q", got[0].Digest, "sha256:bundle1")
	}
	if got[0].ArtifactType != SigstoreBundleArtifactType {
		t.Errorf("referrer[0].ArtifactType = %q, want %q", got[0].ArtifactType, SigstoreBundleArtifactType)
	}
}

func TestListReferrers_NoResults(t *testing.T) {
	idx := ociIndex{
		MediaType: "application/vnd.oci.image.index.v1+json",
		Manifests: []Referrer{},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		_ = json.NewEncoder(w).Encode(idx)
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	ref := Reference{
		Registry: srv.Listener.Addr().String(),
		Name:     "myorg/myimage",
		Digest:   "sha256:abc123",
	}

	got, err := resolver.ListReferrers(context.Background(), ref, SigstoreBundleArtifactType)
	if err != nil {
		t.Fatalf("ListReferrers() error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("ListReferrers() returned %d referrers, want 0", len(got))
	}
}

func TestListReferrers_NotFound(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	ref := Reference{
		Registry: srv.Listener.Addr().String(),
		Name:     "myorg/myimage",
		Digest:   "sha256:abc123",
	}

	got, err := resolver.ListReferrers(context.Background(), ref, "")
	if err != nil {
		t.Fatalf("ListReferrers() error = %v", err)
	}
	if got != nil {
		t.Errorf("ListReferrers() = %v, want nil for 404", got)
	}
}

func TestListReferrers_RequiresDigest(t *testing.T) {
	resolver := NewResolver()
	ref := Reference{
		Registry: "registry.example.com",
		Name:     "myorg/myimage",
		Tag:      "latest",
	}

	_, err := resolver.ListReferrers(context.Background(), ref, "")
	if err == nil {
		t.Fatal("ListReferrers() = nil error, want error for missing digest")
	}
	if !strings.Contains(err.Error(), "digest is required") {
		t.Errorf("error = %q, want it to contain 'digest is required'", err.Error())
	}
}

func TestListReferrers_AuthRequired(t *testing.T) {
	wantToken := "referrer-token"
	referrers := []Referrer{
		{
			MediaType:    "application/vnd.oci.image.manifest.v1+json",
			Digest:       "sha256:bundle1",
			Size:         100,
			ArtifactType: SigstoreBundleArtifactType,
		},
	}

	idx := ociIndex{
		MediaType: "application/vnd.oci.image.index.v1+json",
		Manifests: referrers,
	}

	var srvURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(tokenResponse{Token: wantToken})
			return
		}

		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+wantToken {
			w.Header().Set("Www-Authenticate",
				`Bearer realm="`+srvURL+`/token",service="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
		_ = json.NewEncoder(w).Encode(idx)
	}))
	defer srv.Close()
	srvURL = srv.URL

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	ref := Reference{
		Registry: srv.Listener.Addr().String(),
		Name:     "myorg/myimage",
		Digest:   "sha256:abc123",
	}

	got, err := resolver.ListReferrers(context.Background(), ref, SigstoreBundleArtifactType)
	if err != nil {
		t.Fatalf("ListReferrers() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("ListReferrers() returned %d referrers, want 1", len(got))
	}
	if got[0].Digest != "sha256:bundle1" {
		t.Errorf("referrer[0].Digest = %q, want %q", got[0].Digest, "sha256:bundle1")
	}
}

func TestFetchSigstoreBundle(t *testing.T) {
	bundleJSON := `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{}}`
	// Use a real sha256 digest so verifyDigest passes.
	bundleBlobDigest := policyDigestOf(bundleJSON)
	referrerDigest := "sha256:" + strings.Repeat("1", 64)
	imageDigest := "sha256:" + strings.Repeat("a", 64)

	// The referrer manifest points to the bundle blob as a layer.
	referrerManifest := ociManifest{
		MediaType: "application/vnd.oci.image.manifest.v1+json",
		Config:    ociDescriptor{MediaType: "application/vnd.oci.empty.v1+json"},
		Layers: []ociDescriptor{
			{
				MediaType: SigstoreBundleArtifactType,
				Digest:    bundleBlobDigest,
				Size:      int64(len(bundleJSON)),
			},
		},
	}

	// Referrers index.
	idx := ociIndex{
		MediaType: "application/vnd.oci.image.index.v1+json",
		Manifests: []Referrer{
			{
				MediaType:    "application/vnd.oci.image.manifest.v1+json",
				Digest:       referrerDigest,
				Size:         500,
				ArtifactType: SigstoreBundleArtifactType,
			},
		},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		// Referrers API.
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/referrers/"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			_ = json.NewEncoder(w).Encode(idx)

		// Referrer manifest (by digest).
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/"+referrerDigest):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(referrerManifest)

		// Image manifest (HEAD for tag resolution).
		case r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Docker-Content-Digest", imageDigest)
			w.WriteHeader(http.StatusOK)

		// Bundle blob.
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/"+bundleBlobDigest):
			_, _ = w.Write([]byte(bundleJSON))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	imageRef := srv.Listener.Addr().String() + "/myorg/myimage:v1"

	data, digest, err := resolver.FetchSigstoreBundle(context.Background(), imageRef)
	if err != nil {
		t.Fatalf("FetchSigstoreBundle() error = %v", err)
	}

	if string(data) != bundleJSON {
		t.Errorf("FetchSigstoreBundle() data = %q, want %q", string(data), bundleJSON)
	}
	if digest != referrerDigest {
		t.Errorf("FetchSigstoreBundle() digest = %q, want %q", digest, referrerDigest)
	}
}

func TestFetchSigstoreBundle_NoBundleFound(t *testing.T) {
	idx := ociIndex{
		MediaType: "application/vnd.oci.image.index.v1+json",
		Manifests: []Referrer{},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/referrers/"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.index.v1+json")
			_ = json.NewEncoder(w).Encode(idx)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	imageRef := srv.Listener.Addr().String() + "/myorg/myimage@sha256:abc123"

	_, _, err := resolver.FetchSigstoreBundle(context.Background(), imageRef)
	if err == nil {
		t.Fatal("FetchSigstoreBundle() = nil error, want error for no bundle")
	}
	if !strings.Contains(err.Error(), "no Sigstore bundle found") {
		t.Errorf("error = %q, want it to contain 'no Sigstore bundle found'", err.Error())
	}
}

func TestFetchSigstoreBundle_EmptyReference(t *testing.T) {
	resolver := NewResolver()
	_, _, err := resolver.FetchSigstoreBundle(context.Background(), "")
	if err == nil {
		t.Fatal("FetchSigstoreBundle() = nil error, want error for empty reference")
	}
}

func TestBundlePath(t *testing.T) {
	tests := []struct {
		name     string
		baseDir  string
		registry string
		repoName string
		digest   string
		want     string
	}{
		{
			name:     "standard ghcr.io reference",
			baseDir:  "/tmp/bundles",
			registry: "ghcr.io",
			repoName: "myorg/mcp-server",
			digest:   "sha256:abc123",
			want:     "/tmp/bundles/ghcr.io/myorg/mcp-server/sha256-abc123.sigstore.json",
		},
		{
			name:     "docker hub reference",
			baseDir:  "/tmp/bundles",
			registry: "registry-1.docker.io",
			repoName: "library/alpine",
			digest:   "sha256:deadbeef",
			want:     "/tmp/bundles/registry-1.docker.io/library/alpine/sha256-deadbeef.sigstore.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BundlePath(tt.baseDir, tt.registry, tt.repoName, tt.digest)
			if got != tt.want {
				t.Errorf("BundlePath() = %q, want %q", got, tt.want)
			}
		})
	}
}
