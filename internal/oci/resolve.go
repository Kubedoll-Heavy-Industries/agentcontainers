// Package oci implements OCI Distribution Spec client operations for
// resolving image references to content-addressable digests.
package oci

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// orgStrictMode controls whether FetchPolicy fails hard when no org-signed
// layer is found (strict=true) or falls back to first-wins (strict=false).

// Resolver resolves OCI image references to manifest digests using the
// OCI Distribution Spec v2 API.
type Resolver struct {
	client         *http.Client
	orgTrustedKeys map[string]ed25519.PublicKey // keyid → public key; nil means no sig check
	orgStrictMode  bool                         // if true, reject images with no org-signed policy layer
}

// NewResolver creates a Resolver with a default HTTP client. Use
// WithHTTPClient to override.
func NewResolver(opts ...ResolverOption) *Resolver {
	r := &Resolver{
		client: &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// ResolverOption configures a Resolver.
type ResolverOption func(*Resolver)

// WithHTTPClient overrides the default HTTP client.
func WithHTTPClient(c *http.Client) ResolverOption {
	return func(r *Resolver) { r.client = c }
}

// WithOrgTrustedKeys configures the Resolver with a set of trusted org public
// keys (keyid → public key). When set, FetchPolicy uses signature-aware
// last-signed-wins selection: only policy layers signed by a trusted key are
// considered, and among those the last one in the manifest wins.
//
// If no trusted keys are configured, FetchPolicy falls back to first-wins
// (F-3 fix) without signature checking.
//
// This addresses the F-6 attack: an adversary with image push rights cannot
// forge the org's Ed25519 signature, so they cannot inject a policy layer that
// passes the signer check regardless of where they append it.
func WithOrgTrustedKeys(keys map[string]ed25519.PublicKey) ResolverOption {
	return func(r *Resolver) { r.orgTrustedKeys = keys }
}

// WithOrgSignerPublicKey is a convenience wrapper for a single trusted key.
// Deprecated: use WithOrgTrustedKeys for multi-key trust stores.
func WithOrgSignerPublicKey(pub ed25519.PublicKey) ResolverOption {
	return func(r *Resolver) {
		if r.orgTrustedKeys == nil {
			r.orgTrustedKeys = make(map[string]ed25519.PublicKey)
		}
		r.orgTrustedKeys[OrgKeyID(pub)] = pub
	}
}

// WithOrgStrictMode configures the Resolver to fail hard (return an error)
// when no org-signed policy layer is found, rather than falling back to
// first-wins. Use this in production runtimes where the org always bakes
// signed policy layers into images.
func WithOrgStrictMode(strict bool) ResolverOption {
	return func(r *Resolver) { r.orgStrictMode = strict }
}

// Reference is a parsed OCI image reference.
type Reference struct {
	Registry string // e.g. "registry-1.docker.io"
	Name     string // e.g. "library/alpine"
	Tag      string // e.g. "3.19" (empty if digest is set)
	Digest   string // e.g. "sha256:abc..." (empty if tag is set)
}

// String returns the canonical string form of the reference.
func (ref Reference) String() string {
	s := ref.Registry + "/" + ref.Name
	if ref.Digest != "" {
		s += "@" + ref.Digest
	} else if ref.Tag != "" {
		s += ":" + ref.Tag
	}
	return s
}

// ParseReference parses an image reference string into its components.
// It handles Docker Hub shorthand (e.g. "alpine:3" → registry-1.docker.io/library/alpine:3).
func ParseReference(raw string) (Reference, error) {
	if raw == "" {
		return Reference{}, fmt.Errorf("empty image reference")
	}

	var ref Reference

	// Split off digest first (@sha256:...).
	if idx := strings.Index(raw, "@"); idx != -1 {
		ref.Digest = raw[idx+1:]
		raw = raw[:idx]
	}

	// Strip any tag portion when a digest is present (e.g. "repo:v1@sha256:...")
	// or extract the tag when no digest is given.
	if idx := strings.LastIndex(raw, ":"); idx != -1 {
		// Make sure the colon isn't part of the registry host:port.
		afterColon := raw[idx+1:]
		if !strings.Contains(afterColon, "/") {
			if ref.Digest == "" {
				ref.Tag = afterColon
			}
			raw = raw[:idx]
		}
	}

	// Default tag if neither tag nor digest specified.
	if ref.Tag == "" && ref.Digest == "" {
		ref.Tag = "latest"
	}

	// Split registry from name.
	parts := strings.SplitN(raw, "/", 2)
	if len(parts) == 1 {
		// No slash → Docker Hub official image: "alpine" → "library/alpine".
		ref.Registry = "registry-1.docker.io"
		ref.Name = "library/" + parts[0]
	} else if isRegistryHost(parts[0]) {
		ref.Registry = parts[0]
		ref.Name = parts[1]
	} else {
		// Docker Hub user image: "user/repo" → "library" prefix not added.
		ref.Registry = "registry-1.docker.io"
		ref.Name = raw
	}

	// Rewrite docker.io to the actual registry host.
	if ref.Registry == "docker.io" {
		ref.Registry = "registry-1.docker.io"
	}

	if ref.Name == "" {
		return Reference{}, fmt.Errorf("empty repository name in %q", raw)
	}

	return ref, nil
}

// isRegistryHost returns true if s looks like a registry hostname
// (contains a dot or colon, or is "localhost").
func isRegistryHost(s string) bool {
	return strings.ContainsAny(s, ".:") || s == "localhost"
}

// Resolve resolves an image reference to its manifest digest. If the
// reference already contains a digest, it is returned directly without
// querying the registry.
func (r *Resolver) Resolve(ctx context.Context, imageRef string) (string, error) {
	ref, err := ParseReference(imageRef)
	if err != nil {
		return "", fmt.Errorf("resolve: %w", err)
	}

	// If already pinned by digest, return it directly.
	if ref.Digest != "" {
		return ref.Digest, nil
	}

	return r.resolveTag(ctx, ref)
}

// resolveTag queries the registry to resolve a tag to a digest.
func (r *Resolver) resolveTag(ctx context.Context, ref Reference) (string, error) {
	scheme := "https"

	// Build the manifest URL per OCI Distribution Spec.
	url := fmt.Sprintf("%s://%s/v2/%s/manifests/%s", scheme, ref.Registry, ref.Name, ref.Tag)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", fmt.Errorf("resolve: creating request: %w", err)
	}

	// Accept manifest list (fat manifest) first, then single-arch manifests.
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.docker.distribution.manifest.v2+json",
	}, ", "))

	resp, err := r.doWithAuth(ctx, req, ref)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", ref.String(), err)
	}
	defer resp.Body.Close() //nolint:errcheck
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("resolve %s: tag %q not found", ref.String(), ref.Tag)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("resolve %s: unexpected status %d", ref.String(), resp.StatusCode)
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("resolve %s: registry did not return Docker-Content-Digest header", ref.String())
	}

	return digest, nil
}

// doWithAuth performs an HTTP request, handling the anonymous→bearer token
// auth flow used by most OCI registries.
func (r *Resolver) doWithAuth(ctx context.Context, req *http.Request, ref Reference) (*http.Response, error) {
	// First attempt without auth.
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	// Parse the WWW-Authenticate challenge to get the token endpoint.
	challenge := resp.Header.Get("Www-Authenticate")
	_ = resp.Body.Close()

	if challenge == "" {
		return nil, fmt.Errorf("registry returned 401 with no WWW-Authenticate header")
	}

	token, err := r.fetchToken(ctx, challenge, ref)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}

	// Retry with the bearer token.
	// Re-use GetBody if available (set by callers that provide a request body)
	// so the body can be replayed on the retried request.
	var retryBody io.Reader
	if req.GetBody != nil {
		retryBody, err = req.GetBody()
		if err != nil {
			return nil, fmt.Errorf("auth retry: re-reading request body: %w", err)
		}
	}

	req2, err := http.NewRequestWithContext(ctx, req.Method, req.URL.String(), retryBody)
	if err != nil {
		return nil, err
	}
	for k, vs := range req.Header {
		for _, v := range vs {
			req2.Header.Add(k, v)
		}
	}
	req2.Header.Set("Authorization", "Bearer "+token)

	return r.client.Do(req2)
}

// tokenResponse is the JSON response from a token endpoint.
type tokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
}

// fetchToken exchanges a WWW-Authenticate challenge for a bearer token.
func (r *Resolver) fetchToken(ctx context.Context, challenge string, ref Reference) (string, error) {
	params := parseChallenge(challenge)

	realm, ok := params["realm"]
	if !ok {
		return "", fmt.Errorf("WWW-Authenticate missing realm: %s", challenge)
	}

	// Build token request URL.
	tokenURL := realm + "?"
	if svc, ok := params["service"]; ok {
		tokenURL += "service=" + svc + "&"
	}
	tokenURL += "scope=repository:" + ref.Name + ":pull"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}

	// Docker Hub returns "token", others may return "access_token".
	if tr.Token != "" {
		return tr.Token, nil
	}
	if tr.AccessToken != "" {
		return tr.AccessToken, nil
	}

	return "", fmt.Errorf("token response contained neither token nor access_token")
}

// parseChallenge parses a Bearer WWW-Authenticate challenge header value
// into a map of key=value pairs. Example:
//
//	Bearer realm="https://auth.example.com/token",service="registry.example.com",scope="repository:foo/bar:pull"
func parseChallenge(header string) map[string]string {
	params := make(map[string]string)

	// Strip "Bearer " prefix (case-insensitive).
	if len(header) > 7 && strings.EqualFold(header[:7], "bearer ") {
		header = header[7:]
	}

	// Parse key="value" pairs.
	for header != "" {
		header = strings.TrimLeft(header, " ,")
		eqIdx := strings.Index(header, "=")
		if eqIdx == -1 {
			break
		}
		key := strings.TrimSpace(header[:eqIdx])
		header = header[eqIdx+1:]

		var value string
		if len(header) > 0 && header[0] == '"' {
			// Quoted value.
			header = header[1:]
			endQuote := strings.Index(header, "\"")
			if endQuote == -1 {
				value = header
				header = ""
			} else {
				value = header[:endQuote]
				header = header[endQuote+1:]
			}
		} else {
			// Unquoted value — ends at comma or end of string.
			commaIdx := strings.Index(header, ",")
			if commaIdx == -1 {
				value = header
				header = ""
			} else {
				value = header[:commaIdx]
				header = header[commaIdx+1:]
			}
		}

		params[key] = value
	}

	return params
}
