package secrets

import (
	"context"
	"fmt"
	"os"
	"time"
)

const (
	// envProviderName is the provider identifier for environment variable secrets.
	envProviderName = "env"
)

// EnvProvider resolves secrets from environment variables. It is intended for
// development and testing scenarios where secrets are passed directly via the
// host environment.
type EnvProvider struct{}

// NewEnvProvider creates a new environment variable secret provider.
func NewEnvProvider() *EnvProvider {
	return &EnvProvider{}
}

// Name returns "env".
func (p *EnvProvider) Name() string {
	return envProviderName
}

// Resolve reads the secret value from the environment variable specified by
// the "env_var" param.
//
// Required params:
//   - "env_var": the name of the environment variable to read
//
// The resolved secret has no expiry (environment variables are static).
func (p *EnvProvider) Resolve(_ context.Context, ref SecretRef) (*Secret, error) {
	envVar := ref.Params["env_var"]
	if envVar == "" {
		return nil, fmt.Errorf("secrets: env: env_var param is required")
	}

	value, ok := os.LookupEnv(envVar)
	if !ok {
		return nil, fmt.Errorf("secrets: env: environment variable %q not set", envVar)
	}

	return &Secret{
		Name:      ref.Name,
		Value:     []byte(value),
		ExpiresAt: time.Time{}, // No expiry for env vars.
		Metadata: map[string]string{
			"provider": envProviderName,
			"env_var":  envVar,
		},
	}, nil
}

// Close is a no-op for the env provider.
func (p *EnvProvider) Close() error {
	return nil
}
