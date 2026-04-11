package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

const (
	// onePasswordProviderName is the provider identifier for 1Password.
	onePasswordProviderName = "1password"

	// defaultOnePasswordField is the default field label to extract.
	defaultOnePasswordField = "password"
)

// OnePasswordProvider resolves secrets from 1Password. By default it shells
// out to the `op` CLI, which authenticates via the 1Password desktop app's
// agent socket (~/.1password/agent.sock). No tokens or credentials are needed
// in the process environment.
//
// For enterprise deployments using 1Password Connect Server, set WithOnePasswordAddr
// and WithOnePasswordToken to switch to the Connect REST API.
type OnePasswordProvider struct {
	// Connect Server fields (enterprise mode).
	addr   string       // Connect Server address (empty = use op CLI)
	token  string       // Connect Server token
	client *http.Client // HTTP client for Connect mode

	// opPath overrides the `op` binary path (for testing).
	opPath string
}

// OnePasswordProviderOption configures a OnePasswordProvider.
type OnePasswordProviderOption func(*OnePasswordProvider)

// WithOnePasswordAddr sets the 1Password Connect Server address, enabling
// Connect mode instead of the default `op` CLI mode.
func WithOnePasswordAddr(addr string) OnePasswordProviderOption {
	return func(p *OnePasswordProvider) {
		p.addr = addr
	}
}

// WithOnePasswordToken sets the 1Password Connect Server token.
func WithOnePasswordToken(token string) OnePasswordProviderOption {
	return func(p *OnePasswordProvider) {
		p.token = token
	}
}

// WithOnePasswordSocket configures the Connect mode to use a Unix domain
// socket transport instead of TCP.
func WithOnePasswordSocket(socketPath string) OnePasswordProviderOption {
	return func(p *OnePasswordProvider) {
		p.client = unixSocketClient(socketPath)
		if p.addr == "" {
			p.addr = "http://localhost:8080"
		}
	}
}

// WithOnePasswordHTTPClient sets a custom HTTP client for Connect mode.
func WithOnePasswordHTTPClient(c *http.Client) OnePasswordProviderOption {
	return func(p *OnePasswordProvider) {
		p.client = c
	}
}

// WithOnePasswordCLIPath overrides the `op` binary path (for testing).
func WithOnePasswordCLIPath(path string) OnePasswordProviderOption {
	return func(p *OnePasswordProvider) {
		p.opPath = path
	}
}

// NewOnePasswordProvider creates a new 1Password secret provider.
func NewOnePasswordProvider(opts ...OnePasswordProviderOption) *OnePasswordProvider {
	p := &OnePasswordProvider{
		client: &http.Client{Timeout: 30 * time.Second},
		opPath: "op",
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Name returns "1password".
func (p *OnePasswordProvider) Name() string {
	return onePasswordProviderName
}

// Resolve fetches a secret from 1Password. If addr is set, uses the Connect
// REST API. Otherwise, shells out to `op read`.
//
// Required params:
//   - "vault": the vault name
//   - "item": the item name
//
// Optional params:
//   - "field": the field label to extract (defaults to "password")
func (p *OnePasswordProvider) Resolve(ctx context.Context, ref SecretRef) (*Secret, error) {
	vault := ref.Params["vault"]
	if vault == "" {
		return nil, fmt.Errorf("secrets: 1password: vault param is required")
	}

	item := ref.Params["item"]
	if item == "" {
		return nil, fmt.Errorf("secrets: 1password: item param is required")
	}

	field := ref.Params["field"]
	if field == "" {
		field = defaultOnePasswordField
	}

	if p.addr != "" {
		return p.resolveConnect(ctx, vault, item, field, ref.Name)
	}
	return p.resolveCLI(ctx, vault, item, field, ref.Name)
}

// resolveCLI uses `op read` to fetch a secret via the 1Password desktop app.
func (p *OnePasswordProvider) resolveCLI(ctx context.Context, vault, item, field, name string) (*Secret, error) {
	// Validate that vault, item, and field contain no "/" characters before
	// building the op:// URI. A "/" in any component would change the path
	// structure and could redirect the read to an unintended secret.
	if strings.ContainsRune(vault, '/') {
		return nil, fmt.Errorf("secrets: 1password: vault name must not contain '/': %q", vault)
	}
	if strings.ContainsRune(item, '/') {
		return nil, fmt.Errorf("secrets: 1password: item name must not contain '/': %q", item)
	}
	if strings.ContainsRune(field, '/') {
		return nil, fmt.Errorf("secrets: 1password: field name must not contain '/': %q", field)
	}

	// op:// URI format: op://vault/item/field
	uri := fmt.Sprintf("op://%s/%s/%s", vault, item, field)

	cmd := exec.CommandContext(ctx, p.opPath, "read", uri)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("secrets: 1password: op read %s: %w: %s", uri, err, strings.TrimSpace(stderr.String()))
	}

	value := strings.TrimRight(stdout.String(), "\n")

	return &Secret{
		Name:      name,
		Value:     []byte(value),
		ExpiresAt: time.Time{},
		Metadata: map[string]string{
			"provider": onePasswordProviderName,
			"vault":    vault,
			"item":     item,
			"field":    field,
		},
	}, nil
}

// onePasswordItemResponse represents the relevant fields from a 1Password
// Connect item response.
type onePasswordItemResponse struct {
	ID     string                 `json:"id"`
	Title  string                 `json:"title"`
	Fields []onePasswordItemField `json:"fields"`
}

// onePasswordItemField represents a single field within a 1Password item.
type onePasswordItemField struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Value   string `json:"value"`
	Type    string `json:"type"`
	Purpose string `json:"purpose"`
}

// resolveConnect uses the 1Password Connect REST API (enterprise mode).
func (p *OnePasswordProvider) resolveConnect(ctx context.Context, vault, item, field, name string) (*Secret, error) {
	itemURL := fmt.Sprintf("%s/v1/vaults/%s/items/%s", p.addr, vault, item)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, itemURL, nil)
	if err != nil {
		return nil, fmt.Errorf("secrets: 1password: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("secrets: 1password: request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("secrets: 1password: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("secrets: 1password: HTTP %d: %s", resp.StatusCode, extractErrorMessage(body))
	}

	var itemResp onePasswordItemResponse
	if err := json.Unmarshal(body, &itemResp); err != nil {
		return nil, fmt.Errorf("secrets: 1password: decode response: %w", err)
	}

	for _, f := range itemResp.Fields {
		if f.Label == field {
			return &Secret{
				Name:      name,
				Value:     []byte(f.Value),
				ExpiresAt: time.Time{},
				Metadata: map[string]string{
					"provider": onePasswordProviderName,
					"vault":    vault,
					"item":     item,
					"field":    field,
				},
			}, nil
		}
	}

	return nil, fmt.Errorf("secrets: 1password: field %q not found in item %q", field, item)
}

// Close is a no-op for the 1Password provider.
func (p *OnePasswordProvider) Close() error {
	return nil
}
