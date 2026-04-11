package container

import (
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/sandbox"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/secrets"
)

func TestBuildCredentialSources(t *testing.T) {
	tests := []struct {
		name     string
		resolved map[string]*secrets.Secret
		want     map[string]sandbox.CredentialSource
	}{
		{
			name:     "nil secrets returns nil",
			resolved: nil,
			want:     nil,
		},
		{
			name:     "empty map returns nil",
			resolved: map[string]*secrets.Secret{},
			want:     nil,
		},
		{
			name: "env provider secret",
			resolved: map[string]*secrets.Secret{
				"api-key": {
					Name:  "api-key",
					Value: []byte("sk-test-123"),
					Metadata: map[string]string{
						"provider": "env",
						"env_var":  "API_KEY",
					},
				},
			},
			want: map[string]sandbox.CredentialSource{
				"api-key": {
					Source: "env",
					Path:   "/run/secrets/api-key",
				},
			},
		},
		{
			name: "oidc provider secret",
			resolved: map[string]*secrets.Secret{
				"cloud-token": {
					Name:  "cloud-token",
					Value: []byte("eyJhbGciOi..."),
					Metadata: map[string]string{
						"provider": "oidc",
						"audience": "https://sts.amazonaws.com",
					},
				},
			},
			want: map[string]sandbox.CredentialSource{
				"cloud-token": {
					Source: "oidc",
					Path:   "/run/secrets/cloud-token",
				},
			},
		},
		{
			name: "no metadata falls back to file",
			resolved: map[string]*secrets.Secret{
				"plain-secret": {
					Name:  "plain-secret",
					Value: []byte("secret-value"),
				},
			},
			want: map[string]sandbox.CredentialSource{
				"plain-secret": {
					Source: "file",
					Path:   "/run/secrets/plain-secret",
				},
			},
		},
		{
			name: "multiple secrets",
			resolved: map[string]*secrets.Secret{
				"anthropic-key": {
					Name:     "anthropic-key",
					Value:    []byte("sk-ant-123"),
					Metadata: map[string]string{"provider": "env"},
				},
				"github-token": {
					Name:     "github-token",
					Value:    []byte("ghp_abc123"),
					Metadata: map[string]string{"provider": "vault"},
				},
			},
			want: map[string]sandbox.CredentialSource{
				"anthropic-key": {
					Source: "env",
					Path:   "/run/secrets/anthropic-key",
				},
				"github-token": {
					Source: "vault",
					Path:   "/run/secrets/github-token",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildCredentialSources(tt.resolved)
			if tt.want == nil {
				if got != nil {
					t.Errorf("buildCredentialSources() = %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("buildCredentialSources() returned %d entries, want %d", len(got), len(tt.want))
			}
			for name, wantCS := range tt.want {
				gotCS, ok := got[name]
				if !ok {
					t.Errorf("missing credential source %q", name)
					continue
				}
				if gotCS.Source != wantCS.Source {
					t.Errorf("credential source %q: Source = %q, want %q", name, gotCS.Source, wantCS.Source)
				}
				if gotCS.Path != wantCS.Path {
					t.Errorf("credential source %q: Path = %q, want %q", name, gotCS.Path, wantCS.Path)
				}
			}
		})
	}
}

func TestBuildServiceAuthConfig(t *testing.T) {
	tests := []struct {
		name     string
		resolved map[string]*secrets.Secret
		want     map[string]sandbox.ServiceAuthConfig
	}{
		{
			name:     "nil secrets returns nil",
			resolved: nil,
			want:     nil,
		},
		{
			name:     "empty map returns nil",
			resolved: map[string]*secrets.Secret{},
			want:     nil,
		},
		{
			name: "anthropic key maps to x-api-key",
			resolved: map[string]*secrets.Secret{
				"anthropic-api-key": {
					Name:  "anthropic-api-key",
					Value: []byte("sk-ant-123"),
				},
			},
			want: map[string]sandbox.ServiceAuthConfig{
				"api.anthropic.com": {HeaderName: "x-api-key"},
			},
		},
		{
			name: "openai key maps to Authorization",
			resolved: map[string]*secrets.Secret{
				"openai-key": {
					Name:  "openai-key",
					Value: []byte("sk-openai-123"),
				},
			},
			want: map[string]sandbox.ServiceAuthConfig{
				"api.openai.com": {HeaderName: "Authorization"},
			},
		},
		{
			name: "github token maps to Authorization",
			resolved: map[string]*secrets.Secret{
				"github-token": {
					Name:  "github-token",
					Value: []byte("ghp_abc123"),
				},
			},
			want: map[string]sandbox.ServiceAuthConfig{
				"api.github.com": {HeaderName: "Authorization"},
			},
		},
		{
			name: "case insensitive matching",
			resolved: map[string]*secrets.Secret{
				"ANTHROPIC_API_KEY": {
					Name:  "ANTHROPIC_API_KEY",
					Value: []byte("sk-ant-456"),
				},
			},
			want: map[string]sandbox.ServiceAuthConfig{
				"api.anthropic.com": {HeaderName: "x-api-key"},
			},
		},
		{
			name: "unrecognized secret has no auth config",
			resolved: map[string]*secrets.Secret{
				"database-password": {
					Name:  "database-password",
					Value: []byte("p@ssw0rd"),
				},
			},
			want: nil,
		},
		{
			name: "multiple recognized secrets",
			resolved: map[string]*secrets.Secret{
				"anthropic-key": {
					Name:  "anthropic-key",
					Value: []byte("sk-ant-123"),
				},
				"github-token": {
					Name:  "github-token",
					Value: []byte("ghp_abc"),
				},
			},
			want: map[string]sandbox.ServiceAuthConfig{
				"api.anthropic.com": {HeaderName: "x-api-key"},
				"api.github.com":    {HeaderName: "Authorization"},
			},
		},
		{
			name: "first match wins per domain",
			resolved: map[string]*secrets.Secret{
				"anthropic-primary": {
					Name:  "anthropic-primary",
					Value: []byte("sk-ant-1"),
				},
				"anthropic-backup": {
					Name:  "anthropic-backup",
					Value: []byte("sk-ant-2"),
				},
			},
			want: map[string]sandbox.ServiceAuthConfig{
				"api.anthropic.com": {HeaderName: "x-api-key"},
			},
		},
		{
			name: "huggingface token via hf_ prefix",
			resolved: map[string]*secrets.Secret{
				"hf_token": {
					Name:  "hf_token",
					Value: []byte("hf_abc123"),
				},
			},
			want: map[string]sandbox.ServiceAuthConfig{
				"huggingface.co": {HeaderName: "Authorization"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildServiceAuthConfig(tt.resolved)
			if tt.want == nil {
				if got != nil {
					t.Errorf("buildServiceAuthConfig() = %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("buildServiceAuthConfig() returned %d entries, want %d", len(got), len(tt.want))
			}
			for domain, wantCfg := range tt.want {
				gotCfg, ok := got[domain]
				if !ok {
					t.Errorf("missing service auth config for domain %q", domain)
					continue
				}
				if gotCfg.HeaderName != wantCfg.HeaderName {
					t.Errorf("domain %q: HeaderName = %q, want %q", domain, gotCfg.HeaderName, wantCfg.HeaderName)
				}
			}
		})
	}
}

func TestProviderFromMetadata(t *testing.T) {
	tests := []struct {
		name   string
		secret *secrets.Secret
		want   string
	}{
		{
			name:   "nil metadata returns file",
			secret: &secrets.Secret{Name: "test"},
			want:   "file",
		},
		{
			name: "empty metadata returns file",
			secret: &secrets.Secret{
				Name:     "test",
				Metadata: map[string]string{},
			},
			want: "file",
		},
		{
			name: "empty provider returns file",
			secret: &secrets.Secret{
				Name:     "test",
				Metadata: map[string]string{"provider": ""},
			},
			want: "file",
		},
		{
			name: "env provider",
			secret: &secrets.Secret{
				Name:     "test",
				Metadata: map[string]string{"provider": "env"},
			},
			want: "env",
		},
		{
			name: "oidc provider",
			secret: &secrets.Secret{
				Name:     "test",
				Metadata: map[string]string{"provider": "oidc"},
			},
			want: "oidc",
		},
		{
			name: "vault provider",
			secret: &secrets.Secret{
				Name:     "test",
				Metadata: map[string]string{"provider": "vault"},
			},
			want: "vault",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := providerFromMetadata(tt.secret)
			if got != tt.want {
				t.Errorf("providerFromMetadata() = %q, want %q", got, tt.want)
			}
		})
	}
}
