package orgpolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/oci"
)

// testManifest and testDescriptor mirror the internal oci types for test fixtures.
type testManifest struct {
	MediaType string           `json:"mediaType,omitempty"`
	Config    testDescriptor   `json:"config"`
	Layers    []testDescriptor `json:"layers"`
}

type testDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// digestOf returns the sha256:<hex> digest of a string, for test fixtures.
func digestOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}

// newExtractPolicyServer creates a TLS test server that serves a manifest with
// a policy layer (mediaType application/vnd.agentcontainers.orgpolicy.v1+json).
func newExtractPolicyServer(t *testing.T, policyJSON string) *httptest.Server {
	t.Helper()
	policyDigest := digestOf(policyJSON)

	manifest := testManifest{
		Config: testDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []testDescriptor{
			{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:" + strings.Repeat("f", 64), Size: 100},
			{
				MediaType: "application/vnd.agentcontainers.orgpolicy.v1+json",
				Digest:    policyDigest,
				Size:      int64(len(policyJSON)),
			},
		},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(manifest)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/"):
			_, _ = w.Write([]byte(policyJSON))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return srv
}

// newNoPolicyLayerServer creates a TLS test server that serves a manifest with
// only filesystem layers (no policy layer).
func newNoPolicyLayerServer(t *testing.T) *httptest.Server {
	t.Helper()

	manifest := testManifest{
		Config: testDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []testDescriptor{
			{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:" + strings.Repeat("a", 64), Size: 200},
			{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:" + strings.Repeat("b", 64), Size: 300},
		},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/") {
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(manifest)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	return srv
}

func TestExtractPolicy_Found(t *testing.T) {
	policyJSON := `{"requireSignatures": true, "minSLSALevel": 2}`
	srv := newExtractPolicyServer(t, policyJSON)
	defer srv.Close()

	ref := srv.Listener.Addr().String() + "/myorg/agent-base:latest"
	p, err := ExtractPolicy(context.Background(), ref, oci.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("ExtractPolicy() error = %v", err)
	}

	if !p.RequireSignatures {
		t.Error("RequireSignatures = false, want true")
	}
	if p.MinSLSALevel != 2 {
		t.Errorf("MinSLSALevel = %d, want 2", p.MinSLSALevel)
	}
}

func TestExtractPolicy_NotFound(t *testing.T) {
	// Image with no policy layer should return DefaultPolicy(), not an error.
	srv := newNoPolicyLayerServer(t)
	defer srv.Close()

	ref := srv.Listener.Addr().String() + "/myorg/agent-base:latest"
	p, err := ExtractPolicy(context.Background(), ref, oci.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("ExtractPolicy() error = %v, want nil (default policy)", err)
	}

	// Should be the permissive default.
	if p.RequireSignatures {
		t.Error("RequireSignatures = true, want false (default policy)")
	}
	if p.MinSLSALevel != 0 {
		t.Errorf("MinSLSALevel = %d, want 0 (default policy)", p.MinSLSALevel)
	}
}

func TestExtractPolicy_InvalidJSON(t *testing.T) {
	srv := newExtractPolicyServer(t, `{not valid json!!!}`)
	defer srv.Close()

	ref := srv.Listener.Addr().String() + "/myorg/agent-base:latest"
	_, err := ExtractPolicy(context.Background(), ref, oci.WithHTTPClient(srv.Client()))
	if err == nil {
		t.Fatal("ExtractPolicy() error = nil, want error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "parsing org policy") {
		t.Errorf("error = %q, want it to contain 'parsing org policy'", err.Error())
	}
}

func TestExtractPolicy_InvalidPolicy(t *testing.T) {
	// SLSA level 99 is out of range (must be 0-4).
	srv := newExtractPolicyServer(t, `{"minSLSALevel": 99}`)
	defer srv.Close()

	ref := srv.Listener.Addr().String() + "/myorg/agent-base:latest"
	_, err := ExtractPolicy(context.Background(), ref, oci.WithHTTPClient(srv.Client()))
	if err == nil {
		t.Fatal("ExtractPolicy() error = nil, want error for invalid SLSA level")
	}
	if !strings.Contains(err.Error(), "minSLSALevel") {
		t.Errorf("error = %q, want it to mention 'minSLSALevel'", err.Error())
	}
}

func TestExtractPolicy_EmptyRef(t *testing.T) {
	// Empty ref returns default policy, not an error.
	p, err := ExtractPolicy(context.Background(), "")
	if err != nil {
		t.Fatalf("ExtractPolicy(\"\") error = %v, want nil", err)
	}
	if p.RequireSignatures {
		t.Error("RequireSignatures = true, want false (default policy)")
	}
}

// newMultiPolicyLayerServer creates a TLS test server that serves a manifest
// with two policy layers to verify the first-wins behavior (F-3 fix).
func newMultiPolicyLayerServer(t *testing.T, basePolicy, derivedPolicy string) *httptest.Server {
	t.Helper()
	baseDigest := digestOf(basePolicy)
	derivedDigest := digestOf(derivedPolicy)

	manifest := testManifest{
		Config: testDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []testDescriptor{
			{MediaType: "application/vnd.agentcontainers.orgpolicy.v1+json", Digest: baseDigest, Size: int64(len(basePolicy))},
			{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:" + strings.Repeat("f", 64), Size: 100},
			{MediaType: "application/vnd.agentcontainers.orgpolicy.v1+json", Digest: derivedDigest, Size: int64(len(derivedPolicy))},
		},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(manifest)
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/blobs/"+baseDigest):
			_, _ = w.Write([]byte(basePolicy))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/blobs/"+derivedDigest):
			_, _ = w.Write([]byte(derivedPolicy))
		default:
			w.WriteHeader(404)
		}
	}))
	return srv
}

func TestExtractPolicy_MultiplePolicyLayers(t *testing.T) {
	// When a base image has a policy layer and a derived image adds another,
	// the FIRST one (org-controlled base) should win (F-3 fix).
	// Last-wins was an attack vector: a developer with push access could append
	// a permissive {} layer and neutralize the org's restrictive policy.
	basePolicy := `{"requireSignatures": true, "minSLSALevel": 2}`
	derivedPolicy := `{"requireSignatures": false}` // attacker's permissive override attempt

	srv := newMultiPolicyLayerServer(t, basePolicy, derivedPolicy)
	defer srv.Close()

	ref := srv.Listener.Addr().String() + "/myorg/agent-base:v2"
	p, err := ExtractPolicy(context.Background(), ref, oci.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("ExtractPolicy() error = %v", err)
	}

	// Should have the BASE (first) policy, not the derived (last) one.
	if !p.RequireSignatures {
		t.Error("RequireSignatures = false, want true (base/org policy should win, F-3)")
	}
	if p.MinSLSALevel != 2 {
		t.Errorf("MinSLSALevel = %d, want 2 (base/org policy should win, F-3)", p.MinSLSALevel)
	}
}

func TestExtractPolicy_RegistryErrorFails(t *testing.T) {
	// Registry returning 500 must NOT fall back to DefaultPolicy — it must fail closed (F-1).
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`internal server error`))
	}))
	defer srv.Close()

	ref := srv.Listener.Addr().String() + "/myorg/agent-base:latest"
	_, err := ExtractPolicy(context.Background(), ref, oci.WithHTTPClient(srv.Client()))
	if err == nil {
		t.Error("ExtractPolicy() error = nil on registry 500; want hard failure (F-1: fail-closed)")
	}
}
