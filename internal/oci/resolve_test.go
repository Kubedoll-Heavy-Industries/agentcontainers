package oci

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseReference(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Reference
		wantErr bool
	}{
		{
			name:  "official image with tag",
			input: "alpine:3.19",
			want: Reference{
				Registry: "registry-1.docker.io",
				Name:     "library/alpine",
				Tag:      "3.19",
			},
		},
		{
			name:  "official image no tag defaults to latest",
			input: "ubuntu",
			want: Reference{
				Registry: "registry-1.docker.io",
				Name:     "library/ubuntu",
				Tag:      "latest",
			},
		},
		{
			name:  "docker hub user image",
			input: "myuser/myrepo:v1",
			want: Reference{
				Registry: "registry-1.docker.io",
				Name:     "myuser/myrepo",
				Tag:      "v1",
			},
		},
		{
			name:  "ghcr.io image",
			input: "ghcr.io/devcontainers/features/node:1",
			want: Reference{
				Registry: "ghcr.io",
				Name:     "devcontainers/features/node",
				Tag:      "1",
			},
		},
		{
			name:  "mcr.microsoft.com image",
			input: "mcr.microsoft.com/devcontainers/base:ubuntu",
			want: Reference{
				Registry: "mcr.microsoft.com",
				Name:     "devcontainers/base",
				Tag:      "ubuntu",
			},
		},
		{
			name:  "image with digest",
			input: "ghcr.io/org/repo@sha256:abcdef1234567890",
			want: Reference{
				Registry: "ghcr.io",
				Name:     "org/repo",
				Digest:   "sha256:abcdef1234567890",
			},
		},
		{
			name:  "image with tag and digest (digest wins)",
			input: "ghcr.io/org/repo:v1@sha256:abcdef1234567890",
			want: Reference{
				Registry: "ghcr.io",
				Name:     "org/repo",
				Digest:   "sha256:abcdef1234567890",
			},
		},
		{
			name:  "docker.io rewritten to registry-1",
			input: "docker.io/library/alpine:3",
			want: Reference{
				Registry: "registry-1.docker.io",
				Name:     "library/alpine",
				Tag:      "3",
			},
		},
		{
			name:  "localhost registry",
			input: "localhost:5000/myimage:latest",
			want: Reference{
				Registry: "localhost:5000",
				Name:     "myimage",
				Tag:      "latest",
			},
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseReference(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Registry != tt.want.Registry {
				t.Errorf("Registry = %q, want %q", got.Registry, tt.want.Registry)
			}
			if got.Name != tt.want.Name {
				t.Errorf("Name = %q, want %q", got.Name, tt.want.Name)
			}
			if got.Tag != tt.want.Tag {
				t.Errorf("Tag = %q, want %q", got.Tag, tt.want.Tag)
			}
			if got.Digest != tt.want.Digest {
				t.Errorf("Digest = %q, want %q", got.Digest, tt.want.Digest)
			}
		})
	}
}

func TestResolveDigestPassthrough(t *testing.T) {
	// If the reference already has a digest, resolve should return it
	// without hitting the network.
	r := NewResolver()
	digest, err := r.Resolve(context.Background(), "ghcr.io/org/repo@sha256:abc123def456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if digest != "sha256:abc123def456" {
		t.Errorf("digest = %q, want %q", digest, "sha256:abc123def456")
	}
}

func TestResolveTagNoAuth(t *testing.T) {
	// Mock a registry that returns a digest on HEAD without requiring auth.
	wantDigest := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && strings.HasSuffix(r.URL.Path, "/manifests/3.19") {
			w.Header().Set("Docker-Content-Digest", wantDigest)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))

	// Override the reference to point at our test server.
	ref := Reference{
		Registry: srv.Listener.Addr().String(),
		Name:     "library/alpine",
		Tag:      "3.19",
	}

	url := "https://" + ref.Registry + "/v2/" + ref.Name + "/manifests/" + ref.Tag
	req, err := http.NewRequestWithContext(context.Background(), http.MethodHead, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/vnd.oci.image.index.v1+json")

	resp, err := resolver.doWithAuth(context.Background(), req, ref)
	if err != nil {
		t.Fatalf("doWithAuth error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	got := resp.Header.Get("Docker-Content-Digest")
	if got != wantDigest {
		t.Errorf("digest = %q, want %q", got, wantDigest)
	}
}

func TestResolveTagWithBearerAuth(t *testing.T) {
	wantDigest := "sha256:aabbccdd11223344"
	wantToken := "test-bearer-token-12345"

	// Token server.
	tokenSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := r.URL.Query().Get("scope")
		if scope != "repository:myorg/myrepo:pull" {
			t.Errorf("unexpected scope: %s", scope)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse{Token: wantToken})
	}))
	defer tokenSrv.Close()

	// Registry server — requires bearer auth.
	registrySrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+wantToken {
			w.Header().Set("Www-Authenticate",
				`Bearer realm="`+tokenSrv.URL+`/token",service="test-registry",scope="repository:myorg/myrepo:pull"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodHead && strings.HasSuffix(r.URL.Path, "/manifests/latest") {
			w.Header().Set("Docker-Content-Digest", wantDigest)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer registrySrv.Close()

	// The TLS test servers each have their own certs; we need a client that
	// trusts both. Use the registry server's client which trusts itself, but
	// the token server is different. Use a custom transport that skips TLS verify
	// for simplicity in testing.
	client := registrySrv.Client()
	// Install the token server's CA into the transport too.
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.InsecureSkipVerify = true
	client.Transport = transport

	resolver := NewResolver(WithHTTPClient(client))

	ref := Reference{
		Registry: registrySrv.Listener.Addr().String(),
		Name:     "myorg/myrepo",
		Tag:      "latest",
	}

	url := "https://" + ref.Registry + "/v2/" + ref.Name + "/manifests/" + ref.Tag
	req, err := http.NewRequestWithContext(context.Background(), http.MethodHead, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "application/vnd.oci.image.index.v1+json")

	resp, err := resolver.doWithAuth(context.Background(), req, ref)
	if err != nil {
		t.Fatalf("doWithAuth error: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	got := resp.Header.Get("Docker-Content-Digest")
	if got != wantDigest {
		t.Errorf("digest = %q, want %q", got, wantDigest)
	}
}

func TestResolveTag404(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))

	// Build a reference pointing at the test server.
	ref := Reference{
		Registry: srv.Listener.Addr().String(),
		Name:     "library/nonexistent",
		Tag:      "missing",
	}

	_, err := resolver.resolveTag(context.Background(), ref)
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want it to contain 'not found'", err.Error())
	}
}

func TestResolveMissingDigestHeader(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 200 but no Docker-Content-Digest header.
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))

	ref := Reference{
		Registry: srv.Listener.Addr().String(),
		Name:     "library/bad",
		Tag:      "v1",
	}

	_, err := resolver.resolveTag(context.Background(), ref)
	if err == nil {
		t.Fatal("expected error for missing digest header, got nil")
	}
	if !strings.Contains(err.Error(), "Docker-Content-Digest") {
		t.Errorf("error = %q, want mention of Docker-Content-Digest", err.Error())
	}
}

func TestParseChallenge(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect map[string]string
	}{
		{
			name:  "docker hub style",
			input: `Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull"`,
			expect: map[string]string{
				"realm":   "https://auth.docker.io/token",
				"service": "registry.docker.io",
				"scope":   "repository:library/alpine:pull",
			},
		},
		{
			name:  "ghcr style",
			input: `Bearer realm="https://ghcr.io/token",service="ghcr.io"`,
			expect: map[string]string{
				"realm":   "https://ghcr.io/token",
				"service": "ghcr.io",
			},
		},
		{
			name:   "empty",
			input:  "",
			expect: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseChallenge(tt.input)
			for k, v := range tt.expect {
				if got[k] != v {
					t.Errorf("key %q = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestReferenceString(t *testing.T) {
	tests := []struct {
		ref  Reference
		want string
	}{
		{
			ref:  Reference{Registry: "ghcr.io", Name: "org/repo", Tag: "v1"},
			want: "ghcr.io/org/repo:v1",
		},
		{
			ref:  Reference{Registry: "ghcr.io", Name: "org/repo", Digest: "sha256:abc"},
			want: "ghcr.io/org/repo@sha256:abc",
		},
		{
			ref:  Reference{Registry: "registry-1.docker.io", Name: "library/alpine", Tag: "latest"},
			want: "registry-1.docker.io/library/alpine:latest",
		},
	}

	for _, tt := range tests {
		got := tt.ref.String()
		if got != tt.want {
			t.Errorf("String() = %q, want %q", got, tt.want)
		}
	}
}

func TestResolveFullFlowWithTestServer(t *testing.T) {
	// End-to-end test: set up a fake registry that requires auth, then
	// use resolveTag() with a synthetic reference that targets it.
	wantDigest := "sha256:full-flow-test-digest"
	wantToken := "full-flow-token"

	// We need the server URL in the handler, so use a placeholder that we
	// replace after the server starts.
	var srvURL string

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: wantToken})
			return
		}

		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+wantToken {
			w.Header().Set("Www-Authenticate",
				`Bearer realm="`+srvURL+`/token",service="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/manifests/") {
			w.Header().Set("Docker-Content-Digest", wantDigest)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	srvURL = srv.URL

	resolver := NewResolver(WithHTTPClient(srv.Client()))

	ref := Reference{
		Registry: srv.Listener.Addr().String(),
		Name:     "testorg/testrepo",
		Tag:      "v2",
	}

	got, err := resolver.resolveTag(context.Background(), ref)
	if err != nil {
		t.Fatalf("resolveTag error: %v", err)
	}
	if got != wantDigest {
		t.Errorf("digest = %q, want %q", got, wantDigest)
	}
}

func TestResolveContextCancellation(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response — the context should cancel before this returns.
		select {}
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	ref := Reference{
		Registry: srv.Listener.Addr().String(),
		Name:     "library/test",
		Tag:      "v1",
	}

	_, err := resolver.resolveTag(ctx, ref)
	if err == nil {
		t.Fatal("expected error from cancelled context, got nil")
	}
}
