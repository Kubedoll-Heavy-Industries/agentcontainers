package container

import (
	"strings"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/sandbox"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/secrets"
)

// knownAPIKeyDomain maps well-known API key secret names (or substrings) to
// the domain and HTTP header where the Sandbox MITM proxy should inject them.
// The Sandbox proxy intercepts HTTPS requests to these domains and adds the
// credential as the specified header.
type apiKeyMapping struct {
	// NamePattern is a case-insensitive substring matched against the secret name.
	NamePattern string
	// Domain is the target domain for ServiceAuthConfig.
	Domain string
	// HeaderName is the HTTP header used for injection (e.g., "x-api-key", "Authorization").
	HeaderName string
}

// knownAPIKeyMappings defines recognized API key patterns for automatic
// ServiceAuthConfig generation. Order matters: first match wins.
var knownAPIKeyMappings = []apiKeyMapping{
	{NamePattern: "anthropic", Domain: "api.anthropic.com", HeaderName: "x-api-key"},
	{NamePattern: "openai", Domain: "api.openai.com", HeaderName: "Authorization"},
	{NamePattern: "github", Domain: "api.github.com", HeaderName: "Authorization"},
	{NamePattern: "huggingface", Domain: "huggingface.co", HeaderName: "Authorization"},
	{NamePattern: "hf_", Domain: "huggingface.co", HeaderName: "Authorization"},
	{NamePattern: "cohere", Domain: "api.cohere.ai", HeaderName: "Authorization"},
}

// buildCredentialSources maps resolved secrets to Sandbox CredentialSource
// entries for the VMCreateRequest. Each secret is represented as a credential
// source with the provider as the source type.
func buildCredentialSources(resolved map[string]*secrets.Secret) map[string]sandbox.CredentialSource {
	if len(resolved) == 0 {
		return nil
	}

	sources := make(map[string]sandbox.CredentialSource, len(resolved))
	for name, secret := range resolved {
		source := providerFromMetadata(secret)
		sources[name] = sandbox.CredentialSource{
			Source: source,
			Path:   "/run/secrets/" + name,
		}
	}
	return sources
}

// buildServiceAuthConfig examines resolved secrets and generates
// ServiceAuthConfig entries for well-known API domains. This enables the
// Sandbox MITM proxy to inject credentials as HTTP headers automatically.
func buildServiceAuthConfig(resolved map[string]*secrets.Secret) map[string]sandbox.ServiceAuthConfig {
	if len(resolved) == 0 {
		return nil
	}

	configs := make(map[string]sandbox.ServiceAuthConfig)
	for name := range resolved {
		lowerName := strings.ToLower(name)
		for _, mapping := range knownAPIKeyMappings {
			if strings.Contains(lowerName, mapping.NamePattern) {
				// Only set if not already configured (first match wins per domain).
				if _, exists := configs[mapping.Domain]; !exists {
					configs[mapping.Domain] = sandbox.ServiceAuthConfig{
						HeaderName: mapping.HeaderName,
					}
				}
				break
			}
		}
	}

	if len(configs) == 0 {
		return nil
	}
	return configs
}

// providerFromMetadata extracts the provider name from a secret's metadata.
// Falls back to "file" if no provider metadata is present, which tells the
// Sandbox to read the credential from the file path.
func providerFromMetadata(secret *secrets.Secret) string {
	if secret.Metadata != nil {
		if p, ok := secret.Metadata["provider"]; ok && p != "" {
			return p
		}
	}
	return "file"
}
