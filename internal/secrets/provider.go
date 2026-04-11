// Package secrets manages secret resolution, lifecycle, and injection for
// agent containers. It provides a pluggable Provider interface for secret
// backends (OIDC, environment, vault, etc.), TTL-based rotation, and tmpfs
// mount generation for secure in-container secret access.
package secrets

import (
	"context"
	"encoding/json"
	"time"
)

// extractErrorMessage parses a JSON error response from a secrets backend
// and returns only the error message field. This avoids leaking raw response
// bodies (which may contain credential hints or path details) into error
// strings and logs.
//
// Supports Vault ({"errors": [...]}), Infisical ({"message": "..."}),
// and 1Password Connect ({"message": "..."}).
// Falls back to the HTTP status code alone if parsing fails.
func extractErrorMessage(body []byte) string {
	// Try Vault format: {"errors": ["message1", "message2"]}
	var vaultErr struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(body, &vaultErr) == nil && len(vaultErr.Errors) > 0 {
		return vaultErr.Errors[0]
	}

	// Try generic {"message": "..."} (Infisical, 1Password Connect)
	var genericErr struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &genericErr) == nil && genericErr.Message != "" {
		return genericErr.Message
	}

	// Unparseable — return nothing. The caller already includes the status code.
	return "(unparseable error response)"
}

// Provider is the interface for pluggable secret backends. Each provider
// knows how to resolve (fetch or generate) secrets from a specific source.
type Provider interface {
	// Name returns the provider identifier (e.g., "oidc", "env", "vault").
	Name() string

	// Resolve fetches or generates a secret value for the given reference.
	Resolve(ctx context.Context, ref SecretRef) (*Secret, error)

	// Close cleans up provider resources (connections, keys, etc.).
	Close() error
}

// SecretRef describes a secret to resolve. It is typically derived from the
// agent.secrets configuration in agentcontainer.json.
type SecretRef struct {
	// Name is the secret name/identifier used as the filename under /run/secrets/.
	Name string

	// Provider is the name of the Provider to use for resolution.
	Provider string

	// Params holds provider-specific parameters (e.g., "audience" for OIDC,
	// "env_var" for env provider).
	Params map[string]string
}

// Secret holds a resolved secret value with metadata.
type Secret struct {
	// Name is the secret identifier, matching the SecretRef.Name that produced it.
	Name string

	// Value is the raw secret material. For JWTs this is the encoded token;
	// for env vars it is the variable value.
	Value []byte

	// ExpiresAt indicates when this secret expires. A zero value means no expiry.
	ExpiresAt time.Time

	// Metadata holds optional provider-specific metadata (e.g., token claims,
	// issuer URL).
	Metadata map[string]string
}
