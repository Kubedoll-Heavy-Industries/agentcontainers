package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// vaultProviderName is the provider identifier for HashiCorp Vault secrets.
	vaultProviderName = "vault"

	// defaultVaultMount is the default KV v2 mount path.
	defaultVaultMount = "secret"
)

// VaultProvider resolves secrets from a HashiCorp Vault KV v2 secrets engine.
// It communicates with Vault via its HTTP API using a static token for
// authentication. No external dependencies are required beyond net/http.
type VaultProvider struct {
	addr   string       // Vault server address (e.g., "https://vault.example.com:8200")
	token  string       // Vault token for auth
	client *http.Client // HTTP client (injectable for testing)
}

// VaultProviderOption configures a VaultProvider.
type VaultProviderOption func(*VaultProvider)

// WithVaultAddr sets the Vault server address.
func WithVaultAddr(addr string) VaultProviderOption {
	return func(p *VaultProvider) {
		p.addr = addr
	}
}

// WithVaultToken sets the Vault authentication token.
func WithVaultToken(token string) VaultProviderOption {
	return func(p *VaultProvider) {
		p.token = token
	}
}

// WithVaultSocket configures the provider to connect via a Unix domain socket
// (e.g. Vault Agent's listener). When set, the addr is used only for URL
// construction; the transport dials the socket directly. This avoids putting
// VAULT_TOKEN in the process environment.
func WithVaultSocket(socketPath string) VaultProviderOption {
	return func(p *VaultProvider) {
		p.client = unixSocketClient(socketPath)
		if p.addr == "" {
			p.addr = "http://localhost:8200"
		}
	}
}

// WithVaultHTTPClient sets a custom HTTP client, primarily for testing.
func WithVaultHTTPClient(c *http.Client) VaultProviderOption {
	return func(p *VaultProvider) {
		p.client = c
	}
}

// NewVaultProvider creates a new HashiCorp Vault secret provider.
func NewVaultProvider(opts ...VaultProviderOption) *VaultProvider {
	p := &VaultProvider{
		client: &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Name returns "vault".
func (p *VaultProvider) Name() string {
	return vaultProviderName
}

// vaultKVResponse represents the Vault KV v2 read response structure.
type vaultKVResponse struct {
	Data struct {
		Data     map[string]any `json:"data"`
		Metadata map[string]any `json:"metadata"`
	} `json:"data"`
}

// Resolve fetches a secret from Vault's KV v2 secrets engine.
//
// Required params:
//   - "path": the secret path (e.g., "myapp/config")
//
// Optional params:
//   - "mount": the KV v2 mount path (defaults to "secret")
//   - "key": a specific key within the secret data (defaults to returning all data as JSON)
//   - "version": a specific version number to retrieve
func (p *VaultProvider) Resolve(ctx context.Context, ref SecretRef) (*Secret, error) {
	path := ref.Params["path"]
	if path == "" {
		return nil, fmt.Errorf("secrets: vault: path param is required")
	}
	// Reject path traversal attempts that could redirect to arbitrary Vault API endpoints.
	// A path like "../../v1/sys/seal" would construct /v1/{mount}/data/../../v1/sys/seal.
	cleanedPath := strings.TrimLeft(path, "/")
	if strings.Contains(cleanedPath, "..") {
		return nil, fmt.Errorf("secrets: vault: path %q contains path traversal sequence", path)
	}

	mount := ref.Params["mount"]
	if mount == "" {
		mount = defaultVaultMount
	}

	// Build the KV v2 read URL: /v1/{mount}/data/{path}
	url := strings.TrimRight(p.addr, "/") + "/v1/" + mount + "/data/" + strings.TrimLeft(path, "/")

	// Add version query parameter if specified.
	if version := ref.Params["version"]; version != "" {
		url += "?version=" + version
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("secrets: vault: create request: %w", err)
	}
	req.Header.Set("X-Vault-Token", p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("secrets: vault: request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("secrets: vault: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("secrets: vault: HTTP %d: %s", resp.StatusCode, extractErrorMessage(body))
	}

	var kvResp vaultKVResponse
	if err := json.Unmarshal(body, &kvResp); err != nil {
		return nil, fmt.Errorf("secrets: vault: decode response: %w", err)
	}

	var value []byte
	key := ref.Params["key"]
	if key != "" {
		// Extract a specific key from the secret data.
		v, ok := kvResp.Data.Data[key]
		if !ok {
			return nil, fmt.Errorf("secrets: vault: key %q not found in secret data", key)
		}
		// Convert the value to string. JSON numbers, booleans, etc. are formatted via Sprintf.
		switch tv := v.(type) {
		case string:
			value = []byte(tv)
		default:
			value = []byte(fmt.Sprintf("%v", tv))
		}
	} else {
		// Return the entire data map as JSON.
		value, err = json.Marshal(kvResp.Data.Data)
		if err != nil {
			return nil, fmt.Errorf("secrets: vault: marshal data: %w", err)
		}
	}

	return &Secret{
		Name:      ref.Name,
		Value:     value,
		ExpiresAt: time.Time{}, // Vault manages its own leases.
		Metadata: map[string]string{
			"provider": vaultProviderName,
			"path":     path,
			"mount":    mount,
		},
	}, nil
}

// Close is a no-op for the Vault provider.
func (p *VaultProvider) Close() error {
	return nil
}
