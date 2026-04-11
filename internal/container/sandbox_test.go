package container

import (
	"context"
	"fmt"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/policy"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/sandbox"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/secrets"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/sidecar"
)

// mockSandboxAPI is a test double for SandboxAPI.
type mockSandboxAPI struct {
	healthFn            func(ctx context.Context) (*sandbox.HealthResponse, error)
	createVMFn          func(ctx context.Context, req *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error)
	listVMsFn           func(ctx context.Context) ([]sandbox.VMListEntry, error)
	inspectVMFn         func(ctx context.Context, name string) (*sandbox.VMInspectResponse, error)
	stopVMFn            func(ctx context.Context, name string) error
	deleteVMFn          func(ctx context.Context, name string) error
	keepaliveFn         func(ctx context.Context, name string) error
	updateProxyConfigFn func(ctx context.Context, req *sandbox.ProxyConfigRequest) error
}

func (m *mockSandboxAPI) Health(ctx context.Context) (*sandbox.HealthResponse, error) {
	if m.healthFn != nil {
		return m.healthFn(ctx)
	}
	return &sandbox.HealthResponse{Status: "ok"}, nil
}

func (m *mockSandboxAPI) CreateVM(ctx context.Context, req *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error) {
	if m.createVMFn != nil {
		return m.createVMFn(ctx, req)
	}
	return nil, fmt.Errorf("CreateVM not configured")
}

func (m *mockSandboxAPI) ListVMs(ctx context.Context) ([]sandbox.VMListEntry, error) {
	if m.listVMsFn != nil {
		return m.listVMsFn(ctx)
	}
	return nil, nil
}

func (m *mockSandboxAPI) InspectVM(ctx context.Context, name string) (*sandbox.VMInspectResponse, error) {
	if m.inspectVMFn != nil {
		return m.inspectVMFn(ctx, name)
	}
	return nil, fmt.Errorf("InspectVM not configured")
}

func (m *mockSandboxAPI) StopVM(ctx context.Context, name string) error {
	if m.stopVMFn != nil {
		return m.stopVMFn(ctx, name)
	}
	return nil
}

func (m *mockSandboxAPI) DeleteVM(ctx context.Context, name string) error {
	if m.deleteVMFn != nil {
		return m.deleteVMFn(ctx, name)
	}
	return nil
}

func (m *mockSandboxAPI) Keepalive(ctx context.Context, name string) error {
	if m.keepaliveFn != nil {
		return m.keepaliveFn(ctx, name)
	}
	return nil
}

func (m *mockSandboxAPI) UpdateProxyConfig(ctx context.Context, req *sandbox.ProxyConfigRequest) error {
	if m.updateProxyConfigFn != nil {
		return m.updateProxyConfigFn(ctx, req)
	}
	return nil
}

// failingDockerFactory returns a dockerClientFactory that always returns an error.
func failingDockerFactory(err error) dockerClientFactory {
	return func(_ string) (client.APIClient, error) {
		return nil, err
	}
}

func TestSandboxRuntime_InterfaceCompliance(t *testing.T) {
	var _ Runtime = (*SandboxRuntime)(nil)
}

func TestSandboxRuntime_Start(t *testing.T) {
	logger := zaptest.NewLogger(t)

	mock := &mockSandboxAPI{
		createVMFn: func(_ context.Context, req *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error) {
			if req.VMName != "ac-test-agent" {
				t.Errorf("expected VM name ac-test-agent, got %s", req.VMName)
			}
			if req.AgentName != "shell" {
				t.Errorf("expected agent_name shell, got %s", req.AgentName)
			}
			if req.WorkspaceDir != "/home/user/project" {
				t.Errorf("expected workspace /home/user/project, got %s", req.WorkspaceDir)
			}
			return &sandbox.VMCreateResponse{
				VMID: "vm-abc123",
				VMConfig: sandbox.VMConfig{
					SocketPath: "/tmp/sandboxes/vm-abc123/docker.sock",
				},
				Started: true,
			}, nil
		},
	}

	// Track the host passed to the Docker factory.
	var capturedHost string
	factory := func(host string) (client.APIClient, error) {
		capturedHost = host
		return &mockDockerAPIClient{}, nil
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(logger),
		WithSandboxClient(mock),
		WithDockerClientFactory(factory),
	)
	if err != nil {
		t.Fatalf("NewSandboxRuntime: %v", err)
	}

	cfg := &config.AgentContainer{
		Name: "test-agent",
	}
	opts := StartOptions{
		WorkspacePath: "/home/user/project",
	}

	session, err := rt.Start(context.Background(), cfg, opts)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	if session.ContainerID != "vm-abc123" {
		t.Errorf("expected ContainerID vm-abc123, got %s", session.ContainerID)
	}
	if session.Name != "ac-test-agent" {
		t.Errorf("expected Name ac-test-agent, got %s", session.Name)
	}
	if session.RuntimeType != RuntimeSandbox {
		t.Errorf("expected RuntimeType sandbox, got %s", session.RuntimeType)
	}
	if session.Status != "running" {
		t.Errorf("expected Status running, got %s", session.Status)
	}
	if session.CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}

	expectedHost := "unix:///tmp/sandboxes/vm-abc123/docker.sock"
	if capturedHost != expectedHost {
		t.Errorf("expected docker host %s, got %s", expectedHost, capturedHost)
	}

	// Verify the Docker client was cached.
	rt.mu.Lock()
	_, cached := rt.vmDockerClients["ac-test-agent"]
	rt.mu.Unlock()
	if !cached {
		t.Error("expected Docker client to be cached for VM name")
	}
}

func TestSandboxRuntime_Start_NoWorkspace(t *testing.T) {
	logger := zaptest.NewLogger(t)

	mock := &mockSandboxAPI{
		createVMFn: func(_ context.Context, req *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error) {
			if req.WorkspaceDir != "" {
				t.Errorf("expected empty workspace, got %s", req.WorkspaceDir)
			}
			return &sandbox.VMCreateResponse{
				VMID: "vm-no-ws",
				VMConfig: sandbox.VMConfig{
					SocketPath: "/tmp/sandboxes/vm-no-ws/docker.sock",
				},
				Started: true,
			}, nil
		},
	}

	factory := func(_ string) (client.APIClient, error) {
		return &mockDockerAPIClient{}, nil
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(logger),
		WithSandboxClient(mock),
		WithDockerClientFactory(factory),
	)
	if err != nil {
		t.Fatalf("NewSandboxRuntime: %v", err)
	}

	cfg := &config.AgentContainer{
		Name: "no-workspace",
	}

	session, err := rt.Start(context.Background(), cfg, StartOptions{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if session.ContainerID != "vm-no-ws" {
		t.Errorf("expected ContainerID vm-no-ws, got %s", session.ContainerID)
	}
}

func TestSandboxRuntime_Start_CreateVMError(t *testing.T) {
	logger := zaptest.NewLogger(t)

	mock := &mockSandboxAPI{
		createVMFn: func(_ context.Context, _ *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error) {
			return nil, fmt.Errorf("sandboxd unreachable")
		},
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(logger),
		WithSandboxClient(mock),
	)
	if err != nil {
		t.Fatalf("NewSandboxRuntime: %v", err)
	}

	cfg := &config.AgentContainer{
		Name: "fail-agent",
	}

	_, err = rt.Start(context.Background(), cfg, StartOptions{})
	if err == nil {
		t.Fatal("expected error from Start, got nil")
	}

	expected := "sandbox runtime: creating VM ac-fail-agent: sandboxd unreachable"
	if err.Error() != expected {
		t.Errorf("expected error %q, got %q", expected, err.Error())
	}
}

func TestSandboxRuntime_Start_EmptySocketPath(t *testing.T) {
	logger := zaptest.NewLogger(t)

	mock := &mockSandboxAPI{
		createVMFn: func(_ context.Context, _ *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error) {
			return &sandbox.VMCreateResponse{
				VMID:     "vm-empty-sock",
				VMConfig: sandbox.VMConfig{SocketPath: ""},
				Started:  true,
			}, nil
		},
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(logger),
		WithSandboxClient(mock),
	)
	if err != nil {
		t.Fatalf("NewSandboxRuntime: %v", err)
	}

	cfg := &config.AgentContainer{Name: "empty-sock"}

	_, err = rt.Start(context.Background(), cfg, StartOptions{})
	if err == nil {
		t.Fatal("expected error for empty socket path, got nil")
	}
	if err.Error() != "sandbox runtime: VM ac-empty-sock returned empty socket path" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSandboxRuntime_Start_DockerClientError(t *testing.T) {
	logger := zaptest.NewLogger(t)

	var deleteVMCalled bool
	mock := &mockSandboxAPI{
		createVMFn: func(_ context.Context, _ *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error) {
			return &sandbox.VMCreateResponse{
				VMID: "vm-docker-fail",
				VMConfig: sandbox.VMConfig{
					SocketPath: "/tmp/sandboxes/vm-docker-fail/docker.sock",
				},
				Started: true,
			}, nil
		},
		deleteVMFn: func(_ context.Context, name string) error {
			deleteVMCalled = true
			if name != "ac-docker-fail" {
				t.Errorf("expected delete for ac-docker-fail, got %s", name)
			}
			return nil
		},
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(logger),
		WithSandboxClient(mock),
		WithDockerClientFactory(failingDockerFactory(fmt.Errorf("connection refused"))),
	)
	if err != nil {
		t.Fatalf("NewSandboxRuntime: %v", err)
	}

	cfg := &config.AgentContainer{Name: "docker-fail"}

	_, err = rt.Start(context.Background(), cfg, StartOptions{})
	if err == nil {
		t.Fatal("expected error when docker client creation fails, got nil")
	}
	if !deleteVMCalled {
		t.Error("expected DeleteVM to be called for cleanup after docker client error")
	}
}

func TestSandboxRuntime_Stop(t *testing.T) {
	var stopCalled, deleteCalled bool
	mock := &mockSandboxAPI{
		stopVMFn: func(_ context.Context, name string) error {
			stopCalled = true
			if name != "vm-123" {
				t.Errorf("expected name vm-123, got %s", name)
			}
			return nil
		},
		deleteVMFn: func(_ context.Context, name string) error {
			deleteCalled = true
			return nil
		},
	}

	rt, err := NewSandboxRuntime(
		WithSandboxClient(mock),
		WithDockerClientFactory(func(_ string) (client.APIClient, error) {
			return nil, nil
		}),
	)
	if err != nil {
		t.Fatalf("NewSandboxRuntime: %v", err)
	}

	// Pre-populate the docker client cache so Stop can clean it up.
	rt.mu.Lock()
	rt.vmDockerClients["vm-123"] = nil
	rt.mu.Unlock()

	session := &Session{ContainerID: "vm-123", Name: "vm-123", RuntimeType: RuntimeSandbox, Status: "running"}
	if err := rt.Stop(context.Background(), session); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !stopCalled {
		t.Error("expected StopVM to be called")
	}
	if !deleteCalled {
		t.Error("expected DeleteVM to be called")
	}
	if session.Status != "stopped" {
		t.Errorf("expected status stopped, got %s", session.Status)
	}

	// Verify the docker client was removed from cache.
	rt.mu.Lock()
	_, cached := rt.vmDockerClients["vm-123"]
	rt.mu.Unlock()
	if cached {
		t.Error("expected docker client to be removed from cache after Stop")
	}
}

func TestSandboxRuntime_Stop_NilSession(t *testing.T) {
	rt, err := NewSandboxRuntime(
		WithSandboxClient(&mockSandboxAPI{}),
	)
	if err != nil {
		t.Fatalf("NewSandboxRuntime: %v", err)
	}

	err = rt.Stop(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil session")
	}
	if err.Error() != "sandbox runtime: nil session" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSandboxRuntime_Exec_NilSession(t *testing.T) {
	rt, err := NewSandboxRuntime(
		WithSandboxClient(&mockSandboxAPI{}),
	)
	if err != nil {
		t.Fatalf("NewSandboxRuntime: %v", err)
	}

	_, err = rt.Exec(context.Background(), nil, []string{"echo"})
	if err == nil {
		t.Fatal("expected error for nil session")
	}
	if err.Error() != "sandbox runtime: nil session" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSandboxRuntime_Exec_EmptyCommand(t *testing.T) {
	rt, err := NewSandboxRuntime(
		WithSandboxClient(&mockSandboxAPI{}),
	)
	if err != nil {
		t.Fatalf("NewSandboxRuntime: %v", err)
	}

	session := &Session{Name: "test-vm"}
	_, err = rt.Exec(context.Background(), session, nil)
	if err == nil {
		t.Fatal("expected error for empty command")
	}
	if err.Error() != "sandbox runtime: empty command" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSandboxRuntime_Exec_NoDockerClient(t *testing.T) {
	rt, err := NewSandboxRuntime(
		WithSandboxClient(&mockSandboxAPI{}),
	)
	if err != nil {
		t.Fatalf("NewSandboxRuntime: %v", err)
	}

	session := &Session{Name: "unknown-vm"}
	_, err = rt.Exec(context.Background(), session, []string{"echo", "hi"})
	if err == nil {
		t.Fatal("expected error for missing docker client")
	}
	if err.Error() != "sandbox runtime: no docker client for VM unknown-vm" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSandboxRuntime_Logs_NilSession(t *testing.T) {
	rt, err := NewSandboxRuntime(
		WithSandboxClient(&mockSandboxAPI{}),
	)
	if err != nil {
		t.Fatalf("NewSandboxRuntime: %v", err)
	}

	_, err = rt.Logs(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil session")
	}
	if err.Error() != "sandbox runtime: nil session" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSandboxRuntime_List(t *testing.T) {
	mock := &mockSandboxAPI{
		listVMsFn: func(_ context.Context) ([]sandbox.VMListEntry, error) {
			return []sandbox.VMListEntry{
				{VMID: "vm-id-1", VMName: "ac-agent-1", Status: "running", Active: true, CreatedAt: "2026-03-01T10:00:00Z"},
				{VMID: "vm-id-2", VMName: "ac-agent-2", Status: "stopped", Active: false, CreatedAt: "2026-03-01T09:00:00Z"},
				{VMID: "vm-id-3", VMName: "other-vm", Status: "running", Active: true}, // not ours
			}, nil
		},
	}

	rt, err := NewSandboxRuntime(
		WithSandboxClient(mock),
	)
	if err != nil {
		t.Fatalf("NewSandboxRuntime: %v", err)
	}

	t.Run("all=false filters stopped", func(t *testing.T) {
		sessions, err := rt.List(context.Background(), false)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(sessions) != 1 {
			t.Fatalf("expected 1 session, got %d", len(sessions))
		}
		if sessions[0].Name != "ac-agent-1" {
			t.Errorf("expected Name ac-agent-1, got %s", sessions[0].Name)
		}
		if sessions[0].ContainerID != "vm-id-1" {
			t.Errorf("expected ContainerID vm-id-1, got %s", sessions[0].ContainerID)
		}
		if sessions[0].CreatedAt.IsZero() {
			t.Error("expected non-zero CreatedAt for ac-agent-1")
		}
	})

	t.Run("all=true includes stopped", func(t *testing.T) {
		sessions, err := rt.List(context.Background(), true)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(sessions) != 2 {
			t.Fatalf("expected 2 sessions, got %d", len(sessions))
		}
		// Verify both use VMID for ContainerID.
		for _, s := range sessions {
			if s.ContainerID != "vm-id-1" && s.ContainerID != "vm-id-2" {
				t.Errorf("expected ContainerID to be a VMID, got %s", s.ContainerID)
			}
		}
	})

	t.Run("CreatedAt parsing with invalid format", func(t *testing.T) {
		mock.listVMsFn = func(_ context.Context) ([]sandbox.VMListEntry, error) {
			return []sandbox.VMListEntry{
				{VMID: "vm-bad-ts", VMName: "ac-bad-ts", Status: "running", Active: true, CreatedAt: "not-a-date"},
			}, nil
		}
		sessions, err := rt.List(context.Background(), true)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(sessions) != 1 {
			t.Fatalf("expected 1 session, got %d", len(sessions))
		}
		if !sessions[0].CreatedAt.IsZero() {
			t.Error("expected zero CreatedAt for unparseable timestamp")
		}
	})
}

func TestSandboxRuntime_List_Error(t *testing.T) {
	mock := &mockSandboxAPI{
		listVMsFn: func(_ context.Context) ([]sandbox.VMListEntry, error) {
			return nil, fmt.Errorf("socket not found")
		},
	}

	rt, err := NewSandboxRuntime(
		WithSandboxClient(mock),
	)
	if err != nil {
		t.Fatalf("NewSandboxRuntime: %v", err)
	}

	_, err = rt.List(context.Background(), false)
	if err == nil {
		t.Fatal("expected error from List")
	}
	if err.Error() != "sandbox runtime: listing VMs: socket not found" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewSandboxRuntime_WithLogger(t *testing.T) {
	rt, err := NewSandboxRuntime(
		WithSandboxLogger(nil),
		WithSandboxClient(&mockSandboxAPI{}),
	)
	if err != nil {
		t.Fatalf("NewSandboxRuntime() unexpected error: %v", err)
	}
	if rt.logger == nil {
		t.Error("expected non-nil logger (should default to nop)")
	}
}

func TestNewSandboxRuntime_WithEnforcementLevel(t *testing.T) {
	mock := &mockSandboxAPI{}
	rt, err := NewSandboxRuntime(
		WithSandboxClient(mock),
		WithSandboxEnforcementLevel(enforcement.LevelGRPC),
	)
	require.NoError(t, err)
	assert.Equal(t, enforcement.LevelGRPC, rt.enfLevel)
}

func TestNewSandboxRuntime_DefaultEnforcementLevel(t *testing.T) {
	mock := &mockSandboxAPI{}
	rt, err := NewSandboxRuntime(
		WithSandboxClient(mock),
	)
	require.NoError(t, err)
	assert.Equal(t, enforcement.LevelGRPC, rt.enfLevel, "default enforcement level should be LevelGRPC (zero value)")
}

func TestSandboxRuntime_Start_PushesProxyConfig(t *testing.T) {
	var proxyReq *sandbox.ProxyConfigRequest
	mock := &mockSandboxAPI{
		createVMFn: func(_ context.Context, _ *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error) {
			return &sandbox.VMCreateResponse{
				VMID:     "vm-proxy-test",
				VMConfig: sandbox.VMConfig{SocketPath: "/tmp/test.sock"},
			}, nil
		},
		updateProxyConfigFn: func(_ context.Context, req *sandbox.ProxyConfigRequest) error {
			proxyReq = req
			return nil
		},
	}

	factory := func(_ string) (client.APIClient, error) {
		return &mockDockerAPIClient{}, nil
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(zaptest.NewLogger(t)),
		WithSandboxClient(mock),
		WithDockerClientFactory(factory),
	)
	require.NoError(t, err)

	cfg := &config.AgentContainer{
		Name: "proxy-test",
		Agent: &config.AgentConfig{
			Capabilities: &config.Capabilities{
				Network: &config.NetworkCaps{
					Egress: []config.EgressRule{
						{Host: "api.example.com", Port: 443},
						{Host: "cdn.example.com", Port: 80},
					},
					Deny: []string{"10.0.0.0/8"},
				},
			},
		},
	}

	session, err := rt.Start(context.Background(), cfg, StartOptions{})
	require.NoError(t, err)
	assert.NotNil(t, session)

	// Verify proxy config was pushed.
	require.NotNil(t, proxyReq, "UpdateProxyConfig should have been called")
	assert.Equal(t, "ac-proxy-test", proxyReq.VMName)
	assert.Equal(t, "DENY", proxyReq.Policy)
	assert.Contains(t, proxyReq.AllowHosts, "api.example.com:443")
	assert.Contains(t, proxyReq.AllowHosts, "cdn.example.com:80")
	assert.Contains(t, proxyReq.BlockCIDRs, "10.0.0.0/8")
}

func TestSandboxRuntime_Start_NoCapabilities_SkipsProxyConfig(t *testing.T) {
	proxyCalled := false
	mock := &mockSandboxAPI{
		createVMFn: func(_ context.Context, _ *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error) {
			return &sandbox.VMCreateResponse{
				VMID:     "vm-no-proxy",
				VMConfig: sandbox.VMConfig{SocketPath: "/tmp/test.sock"},
			}, nil
		},
		updateProxyConfigFn: func(_ context.Context, _ *sandbox.ProxyConfigRequest) error {
			proxyCalled = true
			return nil
		},
	}

	factory := func(_ string) (client.APIClient, error) {
		return &mockDockerAPIClient{}, nil
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(zaptest.NewLogger(t)),
		WithSandboxClient(mock),
		WithDockerClientFactory(factory),
	)
	require.NoError(t, err)

	cfg := &config.AgentContainer{Name: "no-proxy"}
	session, err := rt.Start(context.Background(), cfg, StartOptions{})
	require.NoError(t, err)
	assert.NotNil(t, session)
	assert.False(t, proxyCalled, "UpdateProxyConfig should not be called without capabilities")
}

func TestSandboxRuntime_Start_ProxyConfigError_NonFatal(t *testing.T) {
	mock := &mockSandboxAPI{
		createVMFn: func(_ context.Context, _ *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error) {
			return &sandbox.VMCreateResponse{
				VMID:     "vm-proxy-err",
				VMConfig: sandbox.VMConfig{SocketPath: "/tmp/test.sock"},
			}, nil
		},
		updateProxyConfigFn: func(_ context.Context, _ *sandbox.ProxyConfigRequest) error {
			return fmt.Errorf("proxy config endpoint unavailable")
		},
	}

	factory := func(_ string) (client.APIClient, error) {
		return &mockDockerAPIClient{}, nil
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(zaptest.NewLogger(t)),
		WithSandboxClient(mock),
		WithDockerClientFactory(factory),
	)
	require.NoError(t, err)

	cfg := &config.AgentContainer{
		Name: "proxy-err",
		Agent: &config.AgentConfig{
			Capabilities: &config.Capabilities{
				Network: &config.NetworkCaps{
					Egress: []config.EgressRule{
						{Host: "example.com", Port: 443},
					},
				},
			},
		},
	}

	// Start should succeed even though UpdateProxyConfig fails.
	session, err := rt.Start(context.Background(), cfg, StartOptions{})
	require.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, "vm-proxy-err", session.ContainerID)
}

// ---------------------------------------------------------------------------
// Sidecar lifecycle tests
// ---------------------------------------------------------------------------

func TestSandboxRuntime_Start_WithEnforcer(t *testing.T) {
	var startCalled bool
	var capturedOpts sidecar.StartOptions

	mock := &mockSandboxAPI{
		createVMFn: func(_ context.Context, _ *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error) {
			return &sandbox.VMCreateResponse{
				VMID:     "vm-enf-test",
				VMConfig: sandbox.VMConfig{SocketPath: "/tmp/test.sock"},
			}, nil
		},
		inspectVMFn: func(_ context.Context, name string) (*sandbox.VMInspectResponse, error) {
			assert.Equal(t, "ac-enf-agent", name)
			return &sandbox.VMInspectResponse{
				VMID:        "vm-enf-test",
				VMName:      "ac-enf-agent",
				IPAddresses: []string{"192.168.65.3"},
			}, nil
		},
	}

	factory := func(_ string) (client.APIClient, error) {
		return &mockDockerAPIClient{}, nil
	}

	mockStarter := func(_ context.Context, _ client.APIClient, opts sidecar.StartOptions) (*sidecar.SidecarHandle, error) {
		startCalled = true
		capturedOpts = opts
		return &sidecar.SidecarHandle{
			ContainerID: "enforcer-ctr-123",
			Addr:        opts.HealthCheckAddr,
			Managed:     true,
		}, nil
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(zaptest.NewLogger(t)),
		WithSandboxClient(mock),
		WithDockerClientFactory(factory),
		WithSandboxEnforcementLevel(enforcement.LevelGRPC),
		WithSidecarStarter(mockStarter),
	)
	require.NoError(t, err)

	cfg := &config.AgentContainer{Name: "enf-agent"}
	session, err := rt.Start(context.Background(), cfg, StartOptions{})
	require.NoError(t, err)
	require.NotNil(t, session)

	// Verify sidecar was started.
	assert.True(t, startCalled, "sidecar starter should have been called")
	assert.False(t, capturedOpts.Required, "sidecar should be non-required in sandbox")
	assert.Equal(t, "192.168.65.3:50051", capturedOpts.HealthCheckAddr)

	// Verify session has enforcer addr.
	assert.Equal(t, "192.168.65.3:50051", session.EnforcerAddr)

	// Verify the sidecar handle was cached.
	rt.mu.Lock()
	handle, ok := rt.vmSidecarHandles["ac-enf-agent"]
	rt.mu.Unlock()
	assert.True(t, ok, "sidecar handle should be cached")
	assert.Equal(t, "enforcer-ctr-123", handle.ContainerID)
}

func TestSandboxRuntime_Start_WithEnforcer_NoIP(t *testing.T) {
	var startCalled bool

	mock := &mockSandboxAPI{
		createVMFn: func(_ context.Context, _ *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error) {
			return &sandbox.VMCreateResponse{
				VMID:     "vm-no-ip",
				VMConfig: sandbox.VMConfig{SocketPath: "/tmp/test.sock"},
			}, nil
		},
		inspectVMFn: func(_ context.Context, _ string) (*sandbox.VMInspectResponse, error) {
			return &sandbox.VMInspectResponse{
				VMID:        "vm-no-ip",
				VMName:      "ac-no-ip-agent",
				IPAddresses: []string{}, // no IPs
			}, nil
		},
	}

	factory := func(_ string) (client.APIClient, error) {
		return &mockDockerAPIClient{}, nil
	}

	mockStarter := func(_ context.Context, _ client.APIClient, _ sidecar.StartOptions) (*sidecar.SidecarHandle, error) {
		startCalled = true
		return nil, nil
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(zaptest.NewLogger(t)),
		WithSandboxClient(mock),
		WithDockerClientFactory(factory),
		WithSandboxEnforcementLevel(enforcement.LevelGRPC),
		WithSidecarStarter(mockStarter),
	)
	require.NoError(t, err)

	cfg := &config.AgentContainer{Name: "no-ip-agent"}
	session, err := rt.Start(context.Background(), cfg, StartOptions{})
	require.NoError(t, err)
	require.NotNil(t, session)

	// Sidecar should NOT have been started.
	assert.False(t, startCalled, "sidecar starter should NOT be called when VM has no IPs")
	assert.Empty(t, session.EnforcerAddr, "EnforcerAddr should be empty when VM has no IPs")
}

func TestSandboxRuntime_Start_WithEnforcer_InspectFails(t *testing.T) {
	var startCalled bool

	mock := &mockSandboxAPI{
		createVMFn: func(_ context.Context, _ *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error) {
			return &sandbox.VMCreateResponse{
				VMID:     "vm-inspect-fail",
				VMConfig: sandbox.VMConfig{SocketPath: "/tmp/test.sock"},
			}, nil
		},
		inspectVMFn: func(_ context.Context, _ string) (*sandbox.VMInspectResponse, error) {
			return nil, fmt.Errorf("inspect VM failed: not found")
		},
	}

	factory := func(_ string) (client.APIClient, error) {
		return &mockDockerAPIClient{}, nil
	}

	mockStarter := func(_ context.Context, _ client.APIClient, _ sidecar.StartOptions) (*sidecar.SidecarHandle, error) {
		startCalled = true
		return nil, nil
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(zaptest.NewLogger(t)),
		WithSandboxClient(mock),
		WithDockerClientFactory(factory),
		WithSandboxEnforcementLevel(enforcement.LevelGRPC),
		WithSidecarStarter(mockStarter),
	)
	require.NoError(t, err)

	cfg := &config.AgentContainer{Name: "inspect-fail"}
	session, err := rt.Start(context.Background(), cfg, StartOptions{})
	require.NoError(t, err)
	require.NotNil(t, session)

	// Sidecar should NOT have been started — inspect failed.
	assert.False(t, startCalled, "sidecar starter should NOT be called when InspectVM fails")
	assert.Empty(t, session.EnforcerAddr)
}

func TestSandboxRuntime_Start_WithEnforcer_StartFails(t *testing.T) {
	mock := &mockSandboxAPI{
		createVMFn: func(_ context.Context, _ *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error) {
			return &sandbox.VMCreateResponse{
				VMID:     "vm-start-fail",
				VMConfig: sandbox.VMConfig{SocketPath: "/tmp/test.sock"},
			}, nil
		},
		inspectVMFn: func(_ context.Context, _ string) (*sandbox.VMInspectResponse, error) {
			return &sandbox.VMInspectResponse{
				IPAddresses: []string{"10.0.0.5"},
			}, nil
		},
	}

	factory := func(_ string) (client.APIClient, error) {
		return &mockDockerAPIClient{}, nil
	}

	mockStarter := func(_ context.Context, _ client.APIClient, _ sidecar.StartOptions) (*sidecar.SidecarHandle, error) {
		return nil, fmt.Errorf("sidecar image pull failed")
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(zaptest.NewLogger(t)),
		WithSandboxClient(mock),
		WithDockerClientFactory(factory),
		WithSandboxEnforcementLevel(enforcement.LevelGRPC),
		WithSidecarStarter(mockStarter),
	)
	require.NoError(t, err)

	cfg := &config.AgentContainer{Name: "start-fail"}
	session, err := rt.Start(context.Background(), cfg, StartOptions{})
	require.NoError(t, err, "Start should succeed even when sidecar fails (non-fatal)")
	require.NotNil(t, session)

	// EnforcerAddr should be empty since sidecar failed.
	assert.Empty(t, session.EnforcerAddr)

	// No sidecar handle should be cached.
	rt.mu.Lock()
	_, ok := rt.vmSidecarHandles["ac-start-fail"]
	rt.mu.Unlock()
	assert.False(t, ok, "no sidecar handle should be cached on failure")
}

func TestSandboxRuntime_Start_WithEnforcer_SoftFailure(t *testing.T) {
	// When sidecar returns (nil, nil) — a soft failure with Required=false.
	mock := &mockSandboxAPI{
		createVMFn: func(_ context.Context, _ *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error) {
			return &sandbox.VMCreateResponse{
				VMID:     "vm-soft-fail",
				VMConfig: sandbox.VMConfig{SocketPath: "/tmp/test.sock"},
			}, nil
		},
		inspectVMFn: func(_ context.Context, _ string) (*sandbox.VMInspectResponse, error) {
			return &sandbox.VMInspectResponse{
				IPAddresses: []string{"10.0.0.6"},
			}, nil
		},
	}

	factory := func(_ string) (client.APIClient, error) {
		return &mockDockerAPIClient{}, nil
	}

	mockStarter := func(_ context.Context, _ client.APIClient, _ sidecar.StartOptions) (*sidecar.SidecarHandle, error) {
		return nil, nil // soft failure
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(zaptest.NewLogger(t)),
		WithSandboxClient(mock),
		WithDockerClientFactory(factory),
		WithSandboxEnforcementLevel(enforcement.LevelGRPC),
		WithSidecarStarter(mockStarter),
	)
	require.NoError(t, err)

	cfg := &config.AgentContainer{Name: "soft-fail"}
	session, err := rt.Start(context.Background(), cfg, StartOptions{})
	require.NoError(t, err)
	require.NotNil(t, session)

	// EnforcerAddr should be empty since sidecar had soft failure.
	assert.Empty(t, session.EnforcerAddr)
}

func TestSandboxRuntime_Start_EnforcementNone_SkipsSidecar(t *testing.T) {
	var startCalled bool

	mock := &mockSandboxAPI{
		createVMFn: func(_ context.Context, _ *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error) {
			return &sandbox.VMCreateResponse{
				VMID:     "vm-no-enf",
				VMConfig: sandbox.VMConfig{SocketPath: "/tmp/test.sock"},
			}, nil
		},
	}

	factory := func(_ string) (client.APIClient, error) {
		return &mockDockerAPIClient{}, nil
	}

	mockStarter := func(_ context.Context, _ client.APIClient, _ sidecar.StartOptions) (*sidecar.SidecarHandle, error) {
		startCalled = true
		return nil, nil
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(zaptest.NewLogger(t)),
		WithSandboxClient(mock),
		WithDockerClientFactory(factory),
		WithSandboxEnforcementLevel(enforcement.LevelNone),
		WithSidecarStarter(mockStarter),
	)
	require.NoError(t, err)

	cfg := &config.AgentContainer{Name: "no-enf"}
	session, err := rt.Start(context.Background(), cfg, StartOptions{})
	require.NoError(t, err)
	require.NotNil(t, session)

	// Sidecar should NOT have been started.
	assert.False(t, startCalled, "sidecar should not start when enforcement is LevelNone")
	assert.Empty(t, session.EnforcerAddr)
}

func TestSandboxRuntime_Stop_StopsSidecar(t *testing.T) {
	var sidecarStopCalled bool
	var stoppedHandle *sidecar.SidecarHandle

	mock := &mockSandboxAPI{
		stopVMFn: func(_ context.Context, _ string) error {
			return nil
		},
		deleteVMFn: func(_ context.Context, _ string) error {
			return nil
		},
	}

	mockDocker := &mockDockerAPIClient{}

	mockStopper := func(_ context.Context, _ client.APIClient, handle *sidecar.SidecarHandle) error {
		sidecarStopCalled = true
		stoppedHandle = handle
		return nil
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(zaptest.NewLogger(t)),
		WithSandboxClient(mock),
		WithDockerClientFactory(func(_ string) (client.APIClient, error) {
			return mockDocker, nil
		}),
		WithSidecarStopper(mockStopper),
	)
	require.NoError(t, err)

	// Pre-populate caches as if Start() had run.
	rt.mu.Lock()
	rt.vmDockerClients["ac-stop-test"] = mockDocker
	rt.vmSidecarHandles["ac-stop-test"] = &sidecar.SidecarHandle{
		ContainerID: "enforcer-ctr-456",
		Addr:        "192.168.65.3:50051",
		Managed:     true,
	}
	rt.mu.Unlock()

	session := &Session{
		ContainerID: "vm-stop-test",
		Name:        "ac-stop-test",
		RuntimeType: RuntimeSandbox,
		Status:      "running",
	}

	err = rt.Stop(context.Background(), session)
	require.NoError(t, err)

	// Verify sidecar was stopped.
	assert.True(t, sidecarStopCalled, "sidecar stopper should have been called")
	assert.Equal(t, "enforcer-ctr-456", stoppedHandle.ContainerID)
	assert.Equal(t, "stopped", session.Status)

	// Verify the sidecar handle was removed from cache.
	rt.mu.Lock()
	_, ok := rt.vmSidecarHandles["ac-stop-test"]
	rt.mu.Unlock()
	assert.False(t, ok, "sidecar handle should be removed after Stop")
}

func TestSandboxRuntime_Stop_SidecarStopError_NonFatal(t *testing.T) {
	mock := &mockSandboxAPI{
		stopVMFn: func(_ context.Context, _ string) error {
			return nil
		},
		deleteVMFn: func(_ context.Context, _ string) error {
			return nil
		},
	}

	mockDocker := &mockDockerAPIClient{}

	mockStopper := func(_ context.Context, _ client.APIClient, _ *sidecar.SidecarHandle) error {
		return fmt.Errorf("sidecar stop failed: container already removed")
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(zaptest.NewLogger(t)),
		WithSandboxClient(mock),
		WithDockerClientFactory(func(_ string) (client.APIClient, error) {
			return mockDocker, nil
		}),
		WithSidecarStopper(mockStopper),
	)
	require.NoError(t, err)

	// Pre-populate caches.
	rt.mu.Lock()
	rt.vmDockerClients["ac-stop-err"] = mockDocker
	rt.vmSidecarHandles["ac-stop-err"] = &sidecar.SidecarHandle{
		ContainerID: "enforcer-dead",
		Managed:     true,
	}
	rt.mu.Unlock()

	session := &Session{
		ContainerID: "vm-stop-err",
		Name:        "ac-stop-err",
		RuntimeType: RuntimeSandbox,
		Status:      "running",
	}

	// Stop should succeed even if sidecar stop fails.
	err = rt.Stop(context.Background(), session)
	require.NoError(t, err)
	assert.Equal(t, "stopped", session.Status)
}

func TestSandboxRuntime_Stop_NoSidecar(t *testing.T) {
	// When there's no sidecar handle (enforcement disabled), Stop should still work.
	var stopCalled, deleteCalled bool
	mock := &mockSandboxAPI{
		stopVMFn: func(_ context.Context, _ string) error {
			stopCalled = true
			return nil
		},
		deleteVMFn: func(_ context.Context, _ string) error {
			deleteCalled = true
			return nil
		},
	}

	var sidecarStopCalled bool
	mockStopper := func(_ context.Context, _ client.APIClient, _ *sidecar.SidecarHandle) error {
		sidecarStopCalled = true
		return nil
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(zaptest.NewLogger(t)),
		WithSandboxClient(mock),
		WithDockerClientFactory(func(_ string) (client.APIClient, error) {
			return nil, nil
		}),
		WithSidecarStopper(mockStopper),
	)
	require.NoError(t, err)

	// Only docker client cached, no sidecar handle.
	rt.mu.Lock()
	rt.vmDockerClients["ac-no-sidecar"] = nil
	rt.mu.Unlock()

	session := &Session{
		ContainerID: "vm-no-sidecar",
		Name:        "ac-no-sidecar",
		RuntimeType: RuntimeSandbox,
		Status:      "running",
	}

	err = rt.Stop(context.Background(), session)
	require.NoError(t, err)
	assert.True(t, stopCalled)
	assert.True(t, deleteCalled)
	assert.False(t, sidecarStopCalled, "sidecar stopper should NOT be called when no handle exists")
	assert.Equal(t, "stopped", session.Status)
}

// ---------------------------------------------------------------------------
// mockSandboxStrategy — test double for enforcement.Strategy with function hooks.
// (The simpler mockStrategy in docker_test.go lacks hooks for verifying calls.)
// ---------------------------------------------------------------------------

type mockSandboxStrategy struct {
	applyFn  func(ctx context.Context, containerID string, p *policy.ContainerPolicy) error
	updateFn func(ctx context.Context, containerID string, p *policy.ContainerPolicy) error
	removeFn func(ctx context.Context, containerID string) error
	eventsCh chan enforcement.Event
	level    enforcement.Level
}

func (m *mockSandboxStrategy) Apply(ctx context.Context, containerID string, _ uint32, p *policy.ContainerPolicy) error {
	if m.applyFn != nil {
		return m.applyFn(ctx, containerID, p)
	}
	return nil
}

func (m *mockSandboxStrategy) Update(ctx context.Context, containerID string, p *policy.ContainerPolicy) error {
	if m.updateFn != nil {
		return m.updateFn(ctx, containerID, p)
	}
	return nil
}

func (m *mockSandboxStrategy) Remove(ctx context.Context, containerID string) error {
	if m.removeFn != nil {
		return m.removeFn(ctx, containerID)
	}
	return nil
}

func (m *mockSandboxStrategy) InjectSecrets(_ context.Context, _ string, _ map[string]*secrets.Secret) error {
	return nil
}

func (m *mockSandboxStrategy) Events(containerID string) <-chan enforcement.Event {
	if m.eventsCh != nil {
		return m.eventsCh
	}
	return nil
}

func (m *mockSandboxStrategy) Level() enforcement.Level {
	return m.level
}

// Compile-time interface check for mockSandboxStrategy.
var _ enforcement.Strategy = (*mockSandboxStrategy)(nil)

// ---------------------------------------------------------------------------
// Enforcement strategy wiring tests
// ---------------------------------------------------------------------------

func TestSandboxRuntime_Start_AppliesEnforcement(t *testing.T) {
	var applyCalled bool
	var appliedContainerID string
	var appliedPolicy *policy.ContainerPolicy

	strat := &mockSandboxStrategy{
		level: enforcement.LevelGRPC,
		applyFn: func(_ context.Context, containerID string, p *policy.ContainerPolicy) error {
			applyCalled = true
			appliedContainerID = containerID
			appliedPolicy = p
			return nil
		},
	}

	mockDocker := &mockDockerAPIClient{
		containerListFn: func(_ context.Context, _ client.ContainerListOptions) (client.ContainerListResult, error) {
			return client.ContainerListResult{
				Items: []container.Summary{
					{ID: "agent-ctr-001", State: container.StateRunning},
				},
			}, nil
		},
	}

	mock := &mockSandboxAPI{
		createVMFn: func(_ context.Context, _ *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error) {
			return &sandbox.VMCreateResponse{
				VMID:     "vm-enf-apply",
				VMConfig: sandbox.VMConfig{SocketPath: "/tmp/test.sock"},
			}, nil
		},
		inspectVMFn: func(_ context.Context, _ string) (*sandbox.VMInspectResponse, error) {
			return &sandbox.VMInspectResponse{
				IPAddresses: []string{"10.0.0.1"},
			}, nil
		},
	}

	factory := func(_ string) (client.APIClient, error) {
		return mockDocker, nil
	}

	mockStarter := func(_ context.Context, _ client.APIClient, _ sidecar.StartOptions) (*sidecar.SidecarHandle, error) {
		return &sidecar.SidecarHandle{
			ContainerID: "enforcer-ctr-enf",
			Addr:        "10.0.0.1:50051",
			Managed:     true,
		}, nil
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(zaptest.NewLogger(t)),
		WithSandboxClient(mock),
		WithDockerClientFactory(factory),
		WithSandboxEnforcementLevel(enforcement.LevelGRPC),
		WithSidecarStarter(mockStarter),
		WithStrategyFactory(func(_ string) (enforcement.Strategy, error) {
			return strat, nil
		}),
	)
	require.NoError(t, err)

	testPolicy := &policy.ContainerPolicy{
		AllowedHosts: []string{"example.com"},
	}

	cfg := &config.AgentContainer{Name: "enf-apply-test"}
	session, err := rt.Start(context.Background(), cfg, StartOptions{Policy: testPolicy})
	require.NoError(t, err)
	require.NotNil(t, session)

	// Verify strategy.Apply was called with correct args.
	assert.True(t, applyCalled, "strategy.Apply should have been called")
	assert.Equal(t, "agent-ctr-001", appliedContainerID)
	assert.Equal(t, testPolicy, appliedPolicy)

	// Verify the strategy was cached by VMID.
	rt.mu.Lock()
	cachedStrategy := rt.vmStrategies["vm-enf-apply"]
	cachedAgentCtr := rt.vmAgentContainers["vm-enf-apply"]
	rt.mu.Unlock()
	assert.Equal(t, strat, cachedStrategy)
	assert.Equal(t, "agent-ctr-001", cachedAgentCtr)
}

func TestSandboxRuntime_Start_StrategyFactoryError_NonFatal(t *testing.T) {
	mock := &mockSandboxAPI{
		createVMFn: func(_ context.Context, _ *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error) {
			return &sandbox.VMCreateResponse{
				VMID:     "vm-strat-fail",
				VMConfig: sandbox.VMConfig{SocketPath: "/tmp/test.sock"},
			}, nil
		},
		inspectVMFn: func(_ context.Context, _ string) (*sandbox.VMInspectResponse, error) {
			return &sandbox.VMInspectResponse{
				IPAddresses: []string{"10.0.0.2"},
			}, nil
		},
	}

	factory := func(_ string) (client.APIClient, error) {
		return &mockDockerAPIClient{}, nil
	}

	mockStarter := func(_ context.Context, _ client.APIClient, _ sidecar.StartOptions) (*sidecar.SidecarHandle, error) {
		return &sidecar.SidecarHandle{
			ContainerID: "enforcer-strat-fail",
			Addr:        "10.0.0.2:50051",
			Managed:     true,
		}, nil
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(zaptest.NewLogger(t)),
		WithSandboxClient(mock),
		WithDockerClientFactory(factory),
		WithSandboxEnforcementLevel(enforcement.LevelGRPC),
		WithSidecarStarter(mockStarter),
		WithStrategyFactory(func(_ string) (enforcement.Strategy, error) {
			return nil, fmt.Errorf("gRPC dial failed")
		}),
	)
	require.NoError(t, err)

	cfg := &config.AgentContainer{Name: "strat-fail"}
	session, err := rt.Start(context.Background(), cfg, StartOptions{})
	require.NoError(t, err, "Start should succeed even when strategy factory fails")
	require.NotNil(t, session)

	// No strategy should be cached.
	rt.mu.Lock()
	_, ok := rt.vmStrategies["vm-strat-fail"]
	rt.mu.Unlock()
	assert.False(t, ok, "no strategy should be cached when factory fails")
}

func TestSandboxRuntime_Start_ApplyError_NonFatal(t *testing.T) {
	strat := &mockSandboxStrategy{
		level: enforcement.LevelGRPC,
		applyFn: func(_ context.Context, _ string, _ *policy.ContainerPolicy) error {
			return fmt.Errorf("enforcement apply failed: permission denied")
		},
	}

	mockDocker := &mockDockerAPIClient{
		containerListFn: func(_ context.Context, _ client.ContainerListOptions) (client.ContainerListResult, error) {
			return client.ContainerListResult{
				Items: []container.Summary{
					{ID: "agent-ctr-apply-err", State: container.StateRunning},
				},
			}, nil
		},
	}

	mock := &mockSandboxAPI{
		createVMFn: func(_ context.Context, _ *sandbox.VMCreateRequest) (*sandbox.VMCreateResponse, error) {
			return &sandbox.VMCreateResponse{
				VMID:     "vm-apply-err",
				VMConfig: sandbox.VMConfig{SocketPath: "/tmp/test.sock"},
			}, nil
		},
		inspectVMFn: func(_ context.Context, _ string) (*sandbox.VMInspectResponse, error) {
			return &sandbox.VMInspectResponse{
				IPAddresses: []string{"10.0.0.3"},
			}, nil
		},
	}

	factory := func(_ string) (client.APIClient, error) {
		return mockDocker, nil
	}

	mockStarter := func(_ context.Context, _ client.APIClient, _ sidecar.StartOptions) (*sidecar.SidecarHandle, error) {
		return &sidecar.SidecarHandle{
			ContainerID: "enforcer-apply-err",
			Addr:        "10.0.0.3:50051",
			Managed:     true,
		}, nil
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(zaptest.NewLogger(t)),
		WithSandboxClient(mock),
		WithDockerClientFactory(factory),
		WithSandboxEnforcementLevel(enforcement.LevelGRPC),
		WithSidecarStarter(mockStarter),
		WithStrategyFactory(func(_ string) (enforcement.Strategy, error) {
			return strat, nil
		}),
	)
	require.NoError(t, err)

	cfg := &config.AgentContainer{Name: "apply-err"}
	session, err := rt.Start(context.Background(), cfg, StartOptions{})
	require.NoError(t, err, "Start should succeed even when strategy.Apply fails (non-fatal)")
	require.NotNil(t, session)

	// Strategy should still be cached (it can be retried or used for events).
	rt.mu.Lock()
	_, ok := rt.vmStrategies["vm-apply-err"]
	rt.mu.Unlock()
	assert.True(t, ok, "strategy should be cached even when Apply fails")
}

func TestSandboxRuntime_Stop_RemovesEnforcement(t *testing.T) {
	var removeCalled bool
	var removedContainerID string

	strat := &mockSandboxStrategy{
		level: enforcement.LevelGRPC,
		removeFn: func(_ context.Context, containerID string) error {
			removeCalled = true
			removedContainerID = containerID
			return nil
		},
	}

	mock := &mockSandboxAPI{
		stopVMFn:   func(_ context.Context, _ string) error { return nil },
		deleteVMFn: func(_ context.Context, _ string) error { return nil },
	}

	mockDocker := &mockDockerAPIClient{}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(zaptest.NewLogger(t)),
		WithSandboxClient(mock),
		WithDockerClientFactory(func(_ string) (client.APIClient, error) {
			return mockDocker, nil
		}),
	)
	require.NoError(t, err)

	// Pre-populate caches as if Start() had run.
	rt.mu.Lock()
	rt.vmDockerClients["ac-enf-stop"] = mockDocker
	rt.vmStrategies["vm-enf-stop"] = strat
	rt.vmAgentContainers["vm-enf-stop"] = "agent-ctr-inside-vm"
	rt.mu.Unlock()

	session := &Session{
		ContainerID: "vm-enf-stop",
		Name:        "ac-enf-stop",
		RuntimeType: RuntimeSandbox,
		Status:      "running",
	}

	err = rt.Stop(context.Background(), session)
	require.NoError(t, err)

	// Verify strategy.Remove was called with the agent container ID.
	assert.True(t, removeCalled, "strategy.Remove should have been called")
	assert.Equal(t, "agent-ctr-inside-vm", removedContainerID)

	// Verify caches were cleaned up.
	rt.mu.Lock()
	_, stratOK := rt.vmStrategies["vm-enf-stop"]
	_, agentOK := rt.vmAgentContainers["vm-enf-stop"]
	rt.mu.Unlock()
	assert.False(t, stratOK, "strategy should be removed from cache")
	assert.False(t, agentOK, "agent container ID should be removed from cache")
	assert.Equal(t, "stopped", session.Status)
}

func TestSandboxRuntime_Stop_RemoveEnforcementError_NonFatal(t *testing.T) {
	strat := &mockSandboxStrategy{
		level: enforcement.LevelGRPC,
		removeFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("grpc: connection closed")
		},
	}

	mock := &mockSandboxAPI{
		stopVMFn:   func(_ context.Context, _ string) error { return nil },
		deleteVMFn: func(_ context.Context, _ string) error { return nil },
	}

	mockDocker := &mockDockerAPIClient{}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(zaptest.NewLogger(t)),
		WithSandboxClient(mock),
		WithDockerClientFactory(func(_ string) (client.APIClient, error) {
			return mockDocker, nil
		}),
	)
	require.NoError(t, err)

	rt.mu.Lock()
	rt.vmDockerClients["ac-remove-err"] = mockDocker
	rt.vmStrategies["vm-remove-err"] = strat
	rt.vmAgentContainers["vm-remove-err"] = "agent-ctr-rerr"
	rt.mu.Unlock()

	session := &Session{
		ContainerID: "vm-remove-err",
		Name:        "ac-remove-err",
		RuntimeType: RuntimeSandbox,
		Status:      "running",
	}

	// Stop should succeed even if strategy.Remove fails.
	err = rt.Stop(context.Background(), session)
	require.NoError(t, err)
	assert.Equal(t, "stopped", session.Status)
}

func TestSandboxRuntime_EnforcementEvents(t *testing.T) {
	eventCh := make(chan enforcement.Event, 10)
	strat := &mockSandboxStrategy{
		level:    enforcement.LevelGRPC,
		eventsCh: eventCh,
	}

	rt, err := NewSandboxRuntime(
		WithSandboxClient(&mockSandboxAPI{}),
	)
	require.NoError(t, err)

	// Pre-populate caches.
	rt.mu.Lock()
	rt.vmStrategies["vm-events"] = strat
	rt.vmAgentContainers["vm-events"] = "agent-ctr-evt"
	rt.mu.Unlock()

	// Should return the event channel.
	ch := rt.EnforcementEvents("vm-events")
	require.NotNil(t, ch, "EnforcementEvents should return a channel when strategy exists")

	// Send an event and verify it comes through.
	testEvent := enforcement.Event{
		Type:    enforcement.EventNetConnect,
		Verdict: enforcement.VerdictBlock,
		PID:     42,
		Comm:    "curl",
	}
	eventCh <- testEvent

	received := <-ch
	assert.Equal(t, testEvent.PID, received.PID)
	assert.Equal(t, testEvent.Comm, received.Comm)
}

func TestSandboxRuntime_EnforcementEvents_NoStrategy(t *testing.T) {
	rt, err := NewSandboxRuntime(
		WithSandboxClient(&mockSandboxAPI{}),
	)
	require.NoError(t, err)

	// No strategy cached: should return nil.
	ch := rt.EnforcementEvents("nonexistent-vm")
	assert.Nil(t, ch, "EnforcementEvents should return nil when no strategy exists")
}

func TestSandboxRuntime_EnforcementEvents_NoAgentContainer(t *testing.T) {
	strat := &mockSandboxStrategy{
		level:    enforcement.LevelGRPC,
		eventsCh: make(chan enforcement.Event, 1),
	}

	rt, err := NewSandboxRuntime(
		WithSandboxClient(&mockSandboxAPI{}),
	)
	require.NoError(t, err)

	// Strategy exists but no agent container mapping.
	rt.mu.Lock()
	rt.vmStrategies["vm-no-agent"] = strat
	rt.mu.Unlock()

	ch := rt.EnforcementEvents("vm-no-agent")
	assert.Nil(t, ch, "EnforcementEvents should return nil when agent container ID is unknown")
}
