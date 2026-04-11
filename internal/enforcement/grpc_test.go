package enforcement

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcerapi"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/policy"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/secrets"
)

// mockEnforcerServer is a test implementation of the Enforcer gRPC service.
type mockEnforcerServer struct {
	enforcerapi.UnimplementedEnforcerServer
	registerCalled        bool
	unregisterCalled      bool
	networkCalled         bool
	filesystemCalled      bool
	processCalled         bool
	credentialCalled      bool
	injectSecretsCalled   bool
	failNetworkPolicy     bool
	failFilesystemPolicy  bool
	failProcessPolicy     bool
	failCredentialPolicy  bool
	failInjectSecrets     bool
	lastCredentialRequest *enforcerapi.CredentialPolicyRequest
	lastInjectRequest     *enforcerapi.InjectSecretsRequest
	events                []*enforcerapi.EnforcementEvent
}

func (m *mockEnforcerServer) RegisterContainer(ctx context.Context, req *enforcerapi.RegisterContainerRequest) (*enforcerapi.RegisterContainerResponse, error) {
	m.registerCalled = true
	return &enforcerapi.RegisterContainerResponse{
		CgroupId: 12345,
	}, nil
}

func (m *mockEnforcerServer) UnregisterContainer(ctx context.Context, req *enforcerapi.UnregisterContainerRequest) (*enforcerapi.UnregisterContainerResponse, error) {
	m.unregisterCalled = true
	return &enforcerapi.UnregisterContainerResponse{}, nil
}

func (m *mockEnforcerServer) ApplyNetworkPolicy(ctx context.Context, req *enforcerapi.NetworkPolicyRequest) (*enforcerapi.PolicyResponse, error) {
	m.networkCalled = true
	if m.failNetworkPolicy {
		return &enforcerapi.PolicyResponse{
			Success: false,
			Error:   "network policy error",
		}, nil
	}
	return &enforcerapi.PolicyResponse{Success: true}, nil
}

func (m *mockEnforcerServer) ApplyFilesystemPolicy(ctx context.Context, req *enforcerapi.FilesystemPolicyRequest) (*enforcerapi.PolicyResponse, error) {
	m.filesystemCalled = true
	if m.failFilesystemPolicy {
		return &enforcerapi.PolicyResponse{
			Success: false,
			Error:   "filesystem policy error",
		}, nil
	}
	return &enforcerapi.PolicyResponse{Success: true}, nil
}

func (m *mockEnforcerServer) ApplyProcessPolicy(ctx context.Context, req *enforcerapi.ProcessPolicyRequest) (*enforcerapi.PolicyResponse, error) {
	m.processCalled = true
	if m.failProcessPolicy {
		return &enforcerapi.PolicyResponse{
			Success: false,
			Error:   "process policy error",
		}, nil
	}
	return &enforcerapi.PolicyResponse{Success: true}, nil
}

func (m *mockEnforcerServer) ApplyCredentialPolicy(ctx context.Context, req *enforcerapi.CredentialPolicyRequest) (*enforcerapi.PolicyResponse, error) {
	m.credentialCalled = true
	m.lastCredentialRequest = req
	if m.failCredentialPolicy {
		return &enforcerapi.PolicyResponse{
			Success: false,
			Error:   "credential policy error",
		}, nil
	}
	return &enforcerapi.PolicyResponse{Success: true}, nil
}

func (m *mockEnforcerServer) StreamEvents(req *enforcerapi.StreamEventsRequest, stream grpc.ServerStreamingServer[enforcerapi.EnforcementEvent]) error {
	for _, event := range m.events {
		if err := stream.Send(event); err != nil {
			return err
		}
	}
	return nil
}

func (m *mockEnforcerServer) InjectSecrets(ctx context.Context, req *enforcerapi.InjectSecretsRequest) (*enforcerapi.InjectSecretsResponse, error) {
	m.injectSecretsCalled = true
	m.lastInjectRequest = req
	if m.failInjectSecrets {
		return &enforcerapi.InjectSecretsResponse{
			Success: false,
			Error:   "inject secrets error",
		}, nil
	}
	return &enforcerapi.InjectSecretsResponse{
		Success:       true,
		InjectedCount: uint32(len(req.GetSecrets())),
	}, nil
}

func (m *mockEnforcerServer) GetStats(ctx context.Context, req *enforcerapi.GetStatsRequest) (*enforcerapi.StatsResponse, error) {
	return &enforcerapi.StatsResponse{
		NetworkAllowed:    100,
		NetworkBlocked:    5,
		FilesystemAllowed: 200,
		FilesystemBlocked: 10,
		ProcessAllowed:    50,
		ProcessBlocked:    2,
	}, nil
}

// setupMockServer creates an in-process gRPC server using bufconn.
func setupMockServer(mock *mockEnforcerServer) (*grpc.Server, *bufconn.Listener) {
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	enforcerapi.RegisterEnforcerServer(server, mock)
	go func() {
		_ = server.Serve(listener)
	}()
	return server, listener
}

// newTestGRPCStrategy creates a GRPCStrategy connected to the mock server.
func newTestGRPCStrategy(t *testing.T, listener *bufconn.Listener) *GRPCStrategy {
	t.Helper()

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient() error = %v", err)
	}

	return &GRPCStrategy{
		client:   enforcerapi.NewEnforcerClient(conn),
		conn:     conn,
		level:    LevelGRPC,
		events:   make(map[string]chan Event),
		cancelFn: make(map[string]context.CancelFunc),
	}
}

func TestNewGRPCStrategy(t *testing.T) {
	mock := &mockEnforcerServer{}
	server, listener := setupMockServer(mock)
	defer server.Stop()

	strategy := newTestGRPCStrategy(t, listener)
	defer strategy.Close() //nolint:errcheck

	if strategy.Level() != LevelGRPC {
		t.Errorf("Level() = %v, want %v", strategy.Level(), LevelGRPC)
	}
}

func TestGRPCStrategy_Apply(t *testing.T) {
	// Skip on non-Linux: ResolveCgroupPath is unsupported.
	if runtime.GOOS != "linux" {
		t.Skip("Skipping: cgroup resolution not supported on this platform")
	}

	mock := &mockEnforcerServer{}
	server, listener := setupMockServer(mock)
	defer server.Stop()

	strategy := newTestGRPCStrategy(t, listener)
	defer strategy.Close() //nolint:errcheck

	p := &policy.ContainerPolicy{
		NetworkMode:  "bridge",
		AllowedHosts: []string{"example.com"},
		AllowedEgressRules: []policy.EgressPolicy{
			{Host: "api.example.com", Port: 443, Protocol: "tcp"},
		},
		DNS: []string{"8.8.8.8"},
		AllowedMounts: []policy.MountPolicy{
			{Source: "/tmp", Target: "/tmp", ReadOnly: true},
		},
		AllowedCommands: []string{"/bin/bash"},
	}

	ctx := context.Background()
	// Use a fake container ID that won't actually exist
	err := strategy.Apply(ctx, "test-container-123", 12345, p)

	// Expect error because ResolveCgroupPath will fail for non-existent container
	if err == nil {
		t.Fatal("Apply() expected error for non-existent container, got nil")
	}

	// For a more isolated test, we'd need to mock ResolveCgroupPath
}

func TestGRPCStrategy_Remove(t *testing.T) {
	mock := &mockEnforcerServer{}
	server, listener := setupMockServer(mock)
	defer server.Stop()

	strategy := newTestGRPCStrategy(t, listener)
	defer strategy.Close() //nolint:errcheck

	ctx := context.Background()
	err := strategy.Remove(ctx, "test-container-123")
	if err != nil {
		t.Fatalf("Remove() error = %v", err)
	}

	if !mock.unregisterCalled {
		t.Error("UnregisterContainer was not called")
	}
}

func TestGRPCStrategy_Events(t *testing.T) {
	mock := &mockEnforcerServer{
		events: []*enforcerapi.EnforcementEvent{
			{
				TimestampNs: 1234567890,
				ContainerId: "test-123",
				Domain:      "network",
				Verdict:     "allow",
				Pid:         1234,
				Comm:        "curl",
				Details: map[string]string{
					"dst_ip":   "1.2.3.4",
					"dst_port": "443",
				},
			},
		},
	}
	server, listener := setupMockServer(mock)
	defer server.Stop()

	strategy := newTestGRPCStrategy(t, listener)
	defer strategy.Close() //nolint:errcheck

	// Start event stream manually (since Apply would fail without a real container)
	if err := strategy.startEventStream("test-123"); err != nil {
		t.Fatalf("startEventStream() error = %v", err)
	}

	ch := strategy.Events("test-123")
	if ch == nil {
		t.Fatal("Events() returned nil channel")
	}

	select {
	case event := <-ch:
		if event.PID != 1234 {
			t.Errorf("Event PID = %d, want 1234", event.PID)
		}
		if event.Comm != "curl" {
			t.Errorf("Event Comm = %q, want %q", event.Comm, "curl")
		}
		if event.Verdict != VerdictAllow {
			t.Errorf("Event Verdict = %v, want %v", event.Verdict, VerdictAllow)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for event")
	}
}

func TestGRPCStrategy_ErrorHandling(t *testing.T) {
	mock := &mockEnforcerServer{
		failNetworkPolicy: true,
	}
	server, listener := setupMockServer(mock)
	defer server.Stop()

	strategy := newTestGRPCStrategy(t, listener)
	defer strategy.Close() //nolint:errcheck

	p := &policy.ContainerPolicy{
		NetworkMode:  "bridge",
		AllowedHosts: []string{"example.com"},
	}

	// We can't test Apply directly without mocking ResolveCgroupPath,
	// but we can test the policy translation returns proper errors.
	// Let's test Update instead (which skips RegisterContainer).
	ctx := context.Background()
	err := strategy.Update(ctx, "test-123", p)

	if err == nil {
		t.Fatal("Update() expected error when network policy fails, got nil")
	}

	if !mock.networkCalled {
		t.Error("ApplyNetworkPolicy was not called")
	}

	// Filesystem and process should not be called if network fails first
	if mock.filesystemCalled || mock.processCalled {
		t.Error("Filesystem or Process policies should not be called when network fails")
	}
}

func TestTranslateNetworkPolicy(t *testing.T) {
	p := &policy.ContainerPolicy{
		AllowedHosts: []string{"example.com", "1.2.3.4"},
		AllowedEgressRules: []policy.EgressPolicy{
			{Host: "api.example.com", Port: 443, Protocol: "tcp"},
			{Host: "db.example.com", Port: 5432, Protocol: "tcp"},
		},
		DNS: []string{"8.8.8.8", "8.8.4.4"},
	}

	req := translateNetworkPolicy("test-123", p)

	if req.GetContainerId() != "test-123" {
		t.Errorf("ContainerId = %q, want %q", req.GetContainerId(), "test-123")
	}

	if len(req.GetAllowedHosts()) != 2 {
		t.Errorf("len(AllowedHosts) = %d, want 2", len(req.GetAllowedHosts()))
	}

	if len(req.GetEgressRules()) != 2 {
		t.Errorf("len(EgressRules) = %d, want 2", len(req.GetEgressRules()))
	}

	if len(req.GetDnsServers()) != 2 {
		t.Errorf("len(DnsServers) = %d, want 2", len(req.GetDnsServers()))
	}

	// Check first egress rule
	if req.GetEgressRules()[0].GetHost() != "api.example.com" {
		t.Errorf("EgressRules[0].Host = %q, want %q", req.GetEgressRules()[0].GetHost(), "api.example.com")
	}
	if req.GetEgressRules()[0].GetPort() != 443 {
		t.Errorf("EgressRules[0].Port = %d, want 443", req.GetEgressRules()[0].GetPort())
	}
}

func TestTranslateFilesystemPolicy(t *testing.T) {
	p := &policy.ContainerPolicy{
		AllowedMounts: []policy.MountPolicy{
			{Source: "/tmp", Target: "/tmp", ReadOnly: true},
			{Source: "/data", Target: "/data", ReadOnly: false},
		},
	}

	req := translateFilesystemPolicy("test-123", p)

	if req.GetContainerId() != "test-123" {
		t.Errorf("ContainerId = %q, want %q", req.GetContainerId(), "test-123")
	}

	if len(req.GetReadPaths()) != 1 {
		t.Errorf("len(ReadPaths) = %d, want 1", len(req.GetReadPaths()))
	}

	if len(req.GetWritePaths()) != 1 {
		t.Errorf("len(WritePaths) = %d, want 1", len(req.GetWritePaths()))
	}

	if req.GetReadPaths()[0] != "/tmp" {
		t.Errorf("ReadPaths[0] = %q, want %q", req.GetReadPaths()[0], "/tmp")
	}

	if req.GetWritePaths()[0] != "/data" {
		t.Errorf("WritePaths[0] = %q, want %q", req.GetWritePaths()[0], "/data")
	}
}

func TestTranslateProcessPolicy(t *testing.T) {
	p := &policy.ContainerPolicy{
		AllowedCommands: []string{"/bin/bash", "/usr/bin/python3"},
	}

	req := translateProcessPolicy("test-123", p)

	if req.GetContainerId() != "test-123" {
		t.Errorf("ContainerId = %q, want %q", req.GetContainerId(), "test-123")
	}

	if len(req.GetAllowedBinaries()) != 2 {
		t.Errorf("len(AllowedBinaries) = %d, want 2", len(req.GetAllowedBinaries()))
	}

	if req.GetAllowedBinaries()[0] != "/bin/bash" {
		t.Errorf("AllowedBinaries[0] = %q, want %q", req.GetAllowedBinaries()[0], "/bin/bash")
	}
}

func TestTranslateEvent(t *testing.T) {
	tests := []struct {
		name        string
		protoEvent  *enforcerapi.EnforcementEvent
		wantType    EventType
		wantVerdict Verdict
	}{
		{
			name: "network allow",
			protoEvent: &enforcerapi.EnforcementEvent{
				TimestampNs: 1234567890,
				ContainerId: "test-123",
				Domain:      "network",
				Verdict:     "allow",
				Pid:         1234,
				Comm:        "curl",
			},
			wantType:    EventNetConnect,
			wantVerdict: VerdictAllow,
		},
		{
			name: "filesystem block",
			protoEvent: &enforcerapi.EnforcementEvent{
				TimestampNs: 1234567890,
				ContainerId: "test-123",
				Domain:      "filesystem",
				Verdict:     "block",
				Pid:         1234,
				Comm:        "cat",
				Details: map[string]string{
					"path": "/etc/shadow",
				},
			},
			wantType:    EventFSOpen,
			wantVerdict: VerdictBlock,
		},
		{
			name: "process block",
			protoEvent: &enforcerapi.EnforcementEvent{
				TimestampNs: 1234567890,
				ContainerId: "test-123",
				Domain:      "process",
				Verdict:     "block",
				Pid:         1234,
				Comm:        "bash",
				Details: map[string]string{
					"binary": "/usr/bin/malware",
				},
			},
			wantType:    EventExec,
			wantVerdict: VerdictBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := translateEvent(tt.protoEvent)

			if event.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", event.Type, tt.wantType)
			}

			if event.Verdict != tt.wantVerdict {
				t.Errorf("Verdict = %v, want %v", event.Verdict, tt.wantVerdict)
			}

			if event.PID != 1234 {
				t.Errorf("PID = %d, want 1234", event.PID)
			}

			if tt.protoEvent.Domain == "filesystem" && event.FS == nil {
				t.Error("FS event data is nil")
			}

			if tt.protoEvent.Domain == "process" && event.Exec == nil {
				t.Error("Exec event data is nil")
			}
		})
	}
}

func TestTranslateCredentialPolicy(t *testing.T) {
	p := &policy.ContainerPolicy{
		SecretACLs: []policy.SecretACL{
			{
				Path:         "/run/secrets/GITHUB_TOKEN",
				AllowedTools: []string{"git-tool", "code-review"},
				TTLSeconds:   3600,
			},
			{
				Path:         "/run/secrets/NPM_TOKEN",
				AllowedTools: []string{"npm-publish"},
				TTLSeconds:   0,
			},
		},
	}

	req := translateCredentialPolicy("test-cred-123", p)

	if req.GetContainerId() != "test-cred-123" {
		t.Errorf("ContainerId = %q, want %q", req.GetContainerId(), "test-cred-123")
	}

	acls := req.GetSecretAcls()
	if len(acls) != 2 {
		t.Fatalf("len(SecretAcls) = %d, want 2", len(acls))
	}

	// First ACL.
	if acls[0].GetPath() != "/run/secrets/GITHUB_TOKEN" {
		t.Errorf("SecretAcls[0].Path = %q, want %q", acls[0].GetPath(), "/run/secrets/GITHUB_TOKEN")
	}
	if len(acls[0].GetAllowedTools()) != 2 {
		t.Fatalf("len(SecretAcls[0].AllowedTools) = %d, want 2", len(acls[0].GetAllowedTools()))
	}
	if acls[0].GetAllowedTools()[0] != "git-tool" {
		t.Errorf("SecretAcls[0].AllowedTools[0] = %q, want %q", acls[0].GetAllowedTools()[0], "git-tool")
	}
	if acls[0].GetAllowedTools()[1] != "code-review" {
		t.Errorf("SecretAcls[0].AllowedTools[1] = %q, want %q", acls[0].GetAllowedTools()[1], "code-review")
	}
	if acls[0].GetTtlSeconds() != 3600 {
		t.Errorf("SecretAcls[0].TtlSeconds = %d, want 3600", acls[0].GetTtlSeconds())
	}

	// Second ACL.
	if acls[1].GetPath() != "/run/secrets/NPM_TOKEN" {
		t.Errorf("SecretAcls[1].Path = %q, want %q", acls[1].GetPath(), "/run/secrets/NPM_TOKEN")
	}
	if len(acls[1].GetAllowedTools()) != 1 {
		t.Fatalf("len(SecretAcls[1].AllowedTools) = %d, want 1", len(acls[1].GetAllowedTools()))
	}
	if acls[1].GetTtlSeconds() != 0 {
		t.Errorf("SecretAcls[1].TtlSeconds = %d, want 0", acls[1].GetTtlSeconds())
	}
}

func TestTranslateCredentialPolicy_Empty(t *testing.T) {
	p := &policy.ContainerPolicy{}

	req := translateCredentialPolicy("test-empty", p)

	if req.GetContainerId() != "test-empty" {
		t.Errorf("ContainerId = %q, want %q", req.GetContainerId(), "test-empty")
	}

	if len(req.GetSecretAcls()) != 0 {
		t.Errorf("len(SecretAcls) = %d, want 0", len(req.GetSecretAcls()))
	}
}

func TestGRPCStrategy_Update_CredentialPolicy(t *testing.T) {
	mock := &mockEnforcerServer{}
	server, listener := setupMockServer(mock)
	defer server.Stop()

	strategy := newTestGRPCStrategy(t, listener)
	defer strategy.Close() //nolint:errcheck

	p := &policy.ContainerPolicy{
		NetworkMode:  "bridge",
		AllowedHosts: []string{"example.com"},
		SecretACLs: []policy.SecretACL{
			{
				Path:         "/run/secrets/API_KEY",
				AllowedTools: []string{"http-client"},
				TTLSeconds:   1800,
			},
		},
	}

	ctx := context.Background()
	err := strategy.Update(ctx, "test-cred-update", p)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	if !mock.credentialCalled {
		t.Error("ApplyCredentialPolicy was not called")
	}

	if mock.lastCredentialRequest == nil {
		t.Fatal("lastCredentialRequest is nil")
	}

	acls := mock.lastCredentialRequest.GetSecretAcls()
	if len(acls) != 1 {
		t.Fatalf("len(SecretAcls) = %d, want 1", len(acls))
	}
	if acls[0].GetPath() != "/run/secrets/API_KEY" {
		t.Errorf("SecretAcls[0].Path = %q, want %q", acls[0].GetPath(), "/run/secrets/API_KEY")
	}
}

func TestGRPCStrategy_Update_NoCredentialPolicy(t *testing.T) {
	mock := &mockEnforcerServer{}
	server, listener := setupMockServer(mock)
	defer server.Stop()

	strategy := newTestGRPCStrategy(t, listener)
	defer strategy.Close() //nolint:errcheck

	p := &policy.ContainerPolicy{
		NetworkMode:  "bridge",
		AllowedHosts: []string{"example.com"},
	}

	ctx := context.Background()
	err := strategy.Update(ctx, "test-no-cred", p)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	if mock.credentialCalled {
		t.Error("ApplyCredentialPolicy should not be called when SecretACLs is empty")
	}
}

func TestGRPCStrategy_Update_CredentialPolicyError(t *testing.T) {
	mock := &mockEnforcerServer{
		failCredentialPolicy: true,
	}
	server, listener := setupMockServer(mock)
	defer server.Stop()

	strategy := newTestGRPCStrategy(t, listener)
	defer strategy.Close() //nolint:errcheck

	p := &policy.ContainerPolicy{
		NetworkMode:  "bridge",
		AllowedHosts: []string{"example.com"},
		SecretACLs: []policy.SecretACL{
			{
				Path:         "/run/secrets/TOKEN",
				AllowedTools: []string{"tool-a"},
			},
		},
	}

	ctx := context.Background()
	err := strategy.Update(ctx, "test-cred-fail", p)

	if err == nil {
		t.Fatal("Update() expected error when credential policy fails, got nil")
	}

	if !mock.credentialCalled {
		t.Error("ApplyCredentialPolicy was not called")
	}

	// All prior policies should have succeeded.
	if !mock.networkCalled {
		t.Error("ApplyNetworkPolicy was not called")
	}
	if !mock.filesystemCalled {
		t.Error("ApplyFilesystemPolicy was not called")
	}
	if !mock.processCalled {
		t.Error("ApplyProcessPolicy was not called")
	}
}

func TestGRPCStrategy_Close(t *testing.T) {
	mock := &mockEnforcerServer{}
	server, listener := setupMockServer(mock)
	defer server.Stop()

	strategy := newTestGRPCStrategy(t, listener)

	// Start an event stream
	_ = strategy.startEventStream("test-123")

	// Verify event channel exists
	if strategy.Events("test-123") == nil {
		t.Fatal("Events channel should exist before Close")
	}

	// Close the strategy
	if err := strategy.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Verify cleanup
	strategy.mu.Lock()
	defer strategy.mu.Unlock()

	if len(strategy.events) != 0 {
		t.Error("Events map should be empty after Close")
	}

	if len(strategy.cancelFn) != 0 {
		t.Error("CancelFn map should be empty after Close")
	}
}

func TestGRPCStrategy_InjectSecrets(t *testing.T) {
	mock := &mockEnforcerServer{}
	server, listener := setupMockServer(mock)
	defer server.Stop()

	strategy := newTestGRPCStrategy(t, listener)
	defer strategy.Close() //nolint:errcheck

	resolved := map[string]*secrets.Secret{
		"GITHUB_TOKEN": {
			Name:  "GITHUB_TOKEN",
			Value: []byte("ghp_test_token_value"),
		},
		"NPM_TOKEN": {
			Name:  "NPM_TOKEN",
			Value: []byte("npm_test_token_value"),
		},
	}

	ctx := context.Background()
	err := strategy.InjectSecrets(ctx, "test-inject-123", resolved)
	if err != nil {
		t.Fatalf("InjectSecrets() error = %v", err)
	}

	if !mock.injectSecretsCalled {
		t.Error("InjectSecrets was not called on the server")
	}
	if mock.lastInjectRequest == nil {
		t.Fatal("lastInjectRequest is nil")
	}
	if mock.lastInjectRequest.GetContainerId() != "test-inject-123" {
		t.Errorf("ContainerId = %q, want %q", mock.lastInjectRequest.GetContainerId(), "test-inject-123")
	}
	if len(mock.lastInjectRequest.GetSecrets()) != 2 {
		t.Errorf("len(Secrets) = %d, want 2", len(mock.lastInjectRequest.GetSecrets()))
	}
}

func TestGRPCStrategy_InjectSecrets_Error(t *testing.T) {
	mock := &mockEnforcerServer{failInjectSecrets: true}
	server, listener := setupMockServer(mock)
	defer server.Stop()

	strategy := newTestGRPCStrategy(t, listener)
	defer strategy.Close() //nolint:errcheck

	resolved := map[string]*secrets.Secret{
		"TOKEN": {Name: "TOKEN", Value: []byte("secret")},
	}

	ctx := context.Background()
	err := strategy.InjectSecrets(ctx, "test-inject-fail", resolved)
	if err == nil {
		t.Fatal("InjectSecrets() expected error when server fails, got nil")
	}
}

func TestGRPCStrategy_InjectSecrets_Empty(t *testing.T) {
	mock := &mockEnforcerServer{}
	server, listener := setupMockServer(mock)
	defer server.Stop()

	strategy := newTestGRPCStrategy(t, listener)
	defer strategy.Close() //nolint:errcheck

	ctx := context.Background()
	err := strategy.InjectSecrets(ctx, "test-inject-empty", map[string]*secrets.Secret{})
	if err != nil {
		t.Fatalf("InjectSecrets() with empty secrets error = %v", err)
	}
	if !mock.injectSecretsCalled {
		t.Error("InjectSecrets should be called even with empty secrets")
	}
}
