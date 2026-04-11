package secrets

import (
	"context"
	"fmt"
	"time"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/oidc"
)

const (
	// oidcProviderName is the provider identifier for OIDC-based secrets.
	oidcProviderName = "oidc"

	// defaultOIDCTTL is the default token TTL when not specified in params.
	defaultOIDCTTL = time.Hour
)

// OIDCProvider mints short-lived JWTs using the OIDC issuer. It produces
// tokens suitable for workload identity federation with cloud providers
// (AWS STS, GCP Workload Identity, Azure AD, etc.).
type OIDCProvider struct {
	issuer      *oidc.Issuer
	containerID string
}

// OIDCProviderOption configures an OIDCProvider.
type OIDCProviderOption func(*OIDCProvider)

// WithContainerID sets the default subject (container ID) for minted tokens.
func WithContainerID(id string) OIDCProviderOption {
	return func(p *OIDCProvider) {
		p.containerID = id
	}
}

// NewOIDCProvider creates a new OIDC secret provider that mints JWTs via
// the given issuer. The containerID is used as the default subject claim.
func NewOIDCProvider(issuer *oidc.Issuer, opts ...OIDCProviderOption) *OIDCProvider {
	p := &OIDCProvider{
		issuer: issuer,
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Name returns "oidc".
func (p *OIDCProvider) Name() string {
	return oidcProviderName
}

// Resolve mints a JWT with the claims derived from the SecretRef params.
//
// Required params:
//   - "audience": the target service audience (e.g., "https://sts.amazonaws.com")
//
// Optional params:
//   - "subject": override the default subject (defaults to container ID)
//   - "ttl": token TTL as a Go duration string (defaults to 1h, max 1h)
func (p *OIDCProvider) Resolve(_ context.Context, ref SecretRef) (*Secret, error) {
	audience := ref.Params["audience"]
	if audience == "" {
		return nil, fmt.Errorf("secrets: oidc: audience param is required")
	}

	subject := ref.Params["subject"]
	if subject == "" {
		subject = p.containerID
	}
	if subject == "" {
		subject = ref.Name
	}

	ttl := defaultOIDCTTL
	if ttlStr := ref.Params["ttl"]; ttlStr != "" {
		var err error
		ttl, err = time.ParseDuration(ttlStr)
		if err != nil {
			return nil, fmt.Errorf("secrets: oidc: invalid ttl %q: %w", ttlStr, err)
		}
	}
	// Clamp to max TTL.
	if ttl > oidc.MaxTTL {
		ttl = oidc.MaxTTL
	}

	token, err := p.issuer.Mint(oidc.MintOptions{
		Subject:     subject,
		Audience:    []string{audience},
		ContainerID: p.containerID,
		TTL:         ttl,
	})
	if err != nil {
		return nil, fmt.Errorf("secrets: oidc: mint: %w", err)
	}

	return &Secret{
		Name:      ref.Name,
		Value:     []byte(token),
		ExpiresAt: time.Now().Add(ttl),
		Metadata: map[string]string{
			"provider": oidcProviderName,
			"audience": audience,
			"subject":  subject,
			"issuer":   p.issuer.URL(),
		},
	}, nil
}

// Close is a no-op for the OIDC provider; the issuer lifecycle is managed
// externally.
func (p *OIDCProvider) Close() error {
	return nil
}
