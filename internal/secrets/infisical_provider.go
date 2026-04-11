package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	// infisicalProviderName is the provider identifier for Infisical secrets.
	infisicalProviderName = "infisical"

	// defaultInfisicalAddr is the default Infisical Cloud API address.
	defaultInfisicalAddr = "https://app.infisical.com"

	// tokenExpiryBuffer is subtracted from the token expiry to ensure
	// re-authentication happens before the token actually expires.
	tokenExpiryBuffer = 30 * time.Second
)

// InfisicalProvider resolves secrets from Infisical using Machine Identity
// Universal Auth. It communicates with Infisical via its HTTP API and caches
// the access token until near-expiry. No external dependencies are required
// beyond net/http.
type InfisicalProvider struct {
	addr         string       // API address (default: "https://app.infisical.com")
	clientID     string       // Machine identity client ID
	clientSecret string       // Machine identity client secret
	client       *http.Client // HTTP client (injectable for testing)

	mu          sync.Mutex
	accessToken string
	tokenExpiry time.Time
}

// InfisicalProviderOption configures an InfisicalProvider.
type InfisicalProviderOption func(*InfisicalProvider)

// WithInfisicalAddr sets the Infisical API address.
func WithInfisicalAddr(addr string) InfisicalProviderOption {
	return func(p *InfisicalProvider) {
		p.addr = addr
	}
}

// WithInfisicalAuth sets the Machine Identity Universal Auth credentials.
func WithInfisicalAuth(clientID, clientSecret string) InfisicalProviderOption {
	return func(p *InfisicalProvider) {
		p.clientID = clientID
		p.clientSecret = clientSecret
	}
}

// WithInfisicalSocket configures the provider to connect via a Unix domain
// socket. When set, the addr is used only for URL construction; the transport
// dials the socket directly.
func WithInfisicalSocket(socketPath string) InfisicalProviderOption {
	return func(p *InfisicalProvider) {
		p.client = unixSocketClient(socketPath)
		if p.addr == "" {
			p.addr = "http://localhost:8080"
		}
	}
}

// WithInfisicalHTTPClient sets a custom HTTP client, primarily for testing.
func WithInfisicalHTTPClient(c *http.Client) InfisicalProviderOption {
	return func(p *InfisicalProvider) {
		p.client = c
	}
}

// NewInfisicalProvider creates a new Infisical secret provider.
func NewInfisicalProvider(opts ...InfisicalProviderOption) *InfisicalProvider {
	p := &InfisicalProvider{
		addr:   defaultInfisicalAddr,
		client: &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Name returns "infisical".
func (p *InfisicalProvider) Name() string {
	return infisicalProviderName
}

// infisicalLoginResponse represents the Universal Auth login response.
type infisicalLoginResponse struct {
	AccessToken       string `json:"accessToken"`
	ExpiresIn         int64  `json:"expiresIn"` // seconds
	AccessTokenMaxTTL int64  `json:"accessTokenMaxTTL"`
	TokenType         string `json:"tokenType"`
}

// infisicalSecretResponse represents the raw secret retrieval response.
type infisicalSecretResponse struct {
	Secret struct {
		ID          string `json:"id"`
		SecretKey   string `json:"secretKey"`
		SecretValue string `json:"secretValue"`
		Version     int    `json:"version"`
		Environment string `json:"environment"`
		WorkspaceID string `json:"workspace"`
		SecretPath  string `json:"secretPath"`
	} `json:"secret"`
}

// authenticate performs Universal Auth login if the current token is expired
// or missing. The caller must NOT hold p.mu.
func (p *InfisicalProvider) authenticate(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Return cached token if still valid.
	if p.accessToken != "" && time.Now().Before(p.tokenExpiry) {
		return p.accessToken, nil
	}

	loginURL := p.addr + "/api/v1/auth/universal-auth/login"

	payload, err := json.Marshal(map[string]string{
		"clientId":     p.clientID,
		"clientSecret": p.clientSecret,
	})
	if err != nil {
		return "", fmt.Errorf("secrets: infisical: marshal login payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, loginURL, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("secrets: infisical: create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("secrets: infisical: login request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("secrets: infisical: read login response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("secrets: infisical: login HTTP %d: %s", resp.StatusCode, extractErrorMessage(body))
	}

	var loginResp infisicalLoginResponse
	if err := json.Unmarshal(body, &loginResp); err != nil {
		return "", fmt.Errorf("secrets: infisical: decode login response: %w", err)
	}

	p.accessToken = loginResp.AccessToken
	// Set expiry with a buffer so we re-authenticate before the token expires.
	p.tokenExpiry = time.Now().Add(time.Duration(loginResp.ExpiresIn)*time.Second - tokenExpiryBuffer)

	return p.accessToken, nil
}

// Resolve fetches a secret from Infisical.
//
// Required params:
//   - "secretName": the name of the secret to retrieve
//   - "environment": the environment slug (e.g., "dev", "staging", "prod")
//
// Optional params:
//   - "projectID": the workspace/project ID
//   - "path": the folder path (defaults to "/")
func (p *InfisicalProvider) Resolve(ctx context.Context, ref SecretRef) (*Secret, error) {
	secretName := ref.Params["secretName"]
	if secretName == "" {
		return nil, fmt.Errorf("secrets: infisical: secretName param is required")
	}

	environment := ref.Params["environment"]
	if environment == "" {
		return nil, fmt.Errorf("secrets: infisical: environment param is required")
	}

	token, err := p.authenticate(ctx)
	if err != nil {
		return nil, err
	}

	// Build the secret retrieval URL.
	secretURL := p.addr + "/api/v3/secrets/raw/" + url.PathEscape(secretName)

	query := url.Values{}
	query.Set("environment", environment)
	if projectID := ref.Params["projectID"]; projectID != "" {
		query.Set("workspaceId", projectID)
	}
	secretPath := ref.Params["path"]
	if secretPath == "" {
		secretPath = "/"
	}
	query.Set("secretPath", secretPath)

	secretURL += "?" + query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, secretURL, nil)
	if err != nil {
		return nil, fmt.Errorf("secrets: infisical: create secret request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("secrets: infisical: secret request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("secrets: infisical: read secret response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("secrets: infisical: HTTP %d: %s", resp.StatusCode, extractErrorMessage(respBody))
	}

	var secretResp infisicalSecretResponse
	if err := json.Unmarshal(respBody, &secretResp); err != nil {
		return nil, fmt.Errorf("secrets: infisical: decode secret response: %w", err)
	}

	return &Secret{
		Name:      ref.Name,
		Value:     []byte(secretResp.Secret.SecretValue),
		ExpiresAt: time.Time{}, // No inherent expiry for Infisical secrets.
		Metadata: map[string]string{
			"provider":    infisicalProviderName,
			"secretName":  secretName,
			"environment": environment,
			"path":        secretPath,
		},
	}, nil
}

// Close is a no-op for the Infisical provider.
func (p *InfisicalProvider) Close() error {
	return nil
}
