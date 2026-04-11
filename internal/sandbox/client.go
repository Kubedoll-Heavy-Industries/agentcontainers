package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

const defaultSocketPath = ".docker/sandboxes/sandboxd.sock"

// Client communicates with the sandboxd daemon via its Unix socket API.
type Client struct {
	httpClient *http.Client
	baseURL    string
	logger     *zap.Logger
}

// ClientOption configures a Client.
type ClientOption func(*clientOptions)

type clientOptions struct {
	socketPath string
	httpClient *http.Client
	logger     *zap.Logger
}

// WithSocketPath overrides the default sandboxd socket path.
func WithSocketPath(path string) ClientOption {
	return func(o *clientOptions) {
		o.socketPath = path
	}
}

// WithHTTPClient sets a custom HTTP client (useful for testing).
func WithHTTPClient(c *http.Client) ClientOption {
	return func(o *clientOptions) {
		o.httpClient = c
	}
}

// WithLogger sets the logger for the sandbox client.
func WithLogger(l *zap.Logger) ClientOption {
	return func(o *clientOptions) {
		if l != nil {
			o.logger = l
		}
	}
}

// NewClient creates a sandbox API client that communicates with the sandboxd
// daemon over its Unix socket. The socket path defaults to
// ~/.docker/sandboxes/sandboxd.sock and can be overridden via the
// DOCKER_SANDBOXES_API environment variable or WithSocketPath.
func NewClient(opts ...ClientOption) (*Client, error) {
	o := &clientOptions{
		logger: zap.NewNop(),
	}
	for _, opt := range opts {
		opt(o)
	}

	if o.socketPath == "" {
		o.socketPath = os.Getenv("DOCKER_SANDBOXES_API")
	}
	if o.socketPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("sandbox client: get home dir: %w", err)
		}
		o.socketPath = filepath.Join(home, defaultSocketPath)
	}

	httpClient := o.httpClient
	if httpClient == nil {
		socketPath := o.socketPath
		httpClient = &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", socketPath)
				},
			},
		}
	}

	return &Client{
		httpClient: httpClient,
		baseURL:    "http://sandboxd",
		logger:     o.logger,
	}, nil
}

// Health checks the daemon status.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var h HealthResponse
	if err := c.doGet(ctx, "/health", &h); err != nil {
		return nil, err
	}
	return &h, nil
}

// CreateVM creates and starts a new sandbox VM.
func (c *Client) CreateVM(ctx context.Context, req *VMCreateRequest) (*VMCreateResponse, error) {
	var resp VMCreateResponse
	if err := c.doPost(ctx, "/vm", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListVMs returns all registered VMs.
func (c *Client) ListVMs(ctx context.Context) ([]VMListEntry, error) {
	var vms []VMListEntry
	if err := c.doGet(ctx, "/vm", &vms); err != nil {
		return nil, err
	}
	return vms, nil
}

// InspectVM returns details of a specific VM.
func (c *Client) InspectVM(ctx context.Context, name string) (*VMInspectResponse, error) {
	var v VMInspectResponse
	if err := c.doGet(ctx, "/vm/"+name, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// StopVM stops a VM without removing it.
func (c *Client) StopVM(ctx context.Context, name string) error {
	return c.doPost(ctx, "/vm/"+name+"/stop", nil, nil)
}

// DeleteVM removes a VM and all its state.
func (c *Client) DeleteVM(ctx context.Context, name string) error {
	return c.doDelete(ctx, "/vm/"+name)
}

// Keepalive resets the idle timeout for a VM.
func (c *Client) Keepalive(ctx context.Context, name string) error {
	return c.doPost(ctx, "/vm/"+name+"/keepalive", nil, nil)
}

// UpdateProxyConfig updates the network proxy configuration for a running VM.
func (c *Client) UpdateProxyConfig(ctx context.Context, req *ProxyConfigRequest) error {
	return c.doPost(ctx, "/network/proxyconfig", req, nil)
}

// --- internal HTTP helpers ---

func (c *Client) doGet(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("sandbox API %s: %w", path, err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sandbox API %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("sandbox API GET %s: %s %s", path, resp.Status, body)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("sandbox API GET %s: decode: %w", path, err)
		}
	}
	return nil
}

func (c *Client) doPost(ctx context.Context, path string, body any, out any) error {
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("sandbox API %s: marshal: %w", path, err)
		}
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, r)
	if err != nil {
		return fmt.Errorf("sandbox API %s: %w", path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sandbox API %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("sandbox API POST %s: %s %s", path, resp.Status, b)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("sandbox API POST %s: decode: %w", path, err)
		}
	}
	return nil
}

func (c *Client) doDelete(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("sandbox API %s: %w", path, err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sandbox API %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("sandbox API DELETE %s: %s %s", path, resp.Status, b)
	}
	return nil
}
