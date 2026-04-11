package container

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"go.uber.org/zap/zaptest"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/sandbox"
)

// ---------------------------------------------------------------------------
// mockDockerAPIClient — minimal mock of client.APIClient for Exec/Logs tests.
// We embed a nil client.APIClient to satisfy the full interface; only methods
// actually used by SandboxRuntime are implemented here.
// ---------------------------------------------------------------------------

type mockDockerAPIClient struct {
	client.APIClient // embed for interface satisfaction

	containerListFn   func(ctx context.Context, opts client.ContainerListOptions) (client.ContainerListResult, error)
	containerLogsFn   func(ctx context.Context, ctr string, opts client.ContainerLogsOptions) (client.ContainerLogsResult, error)
	containerCreateFn func(ctx context.Context, opts client.ContainerCreateOptions) (client.ContainerCreateResult, error)
	containerStartFn  func(ctx context.Context, ctr string, opts client.ContainerStartOptions) (client.ContainerStartResult, error)
	copyToContainerFn func(ctx context.Context, ctr string, opts client.CopyToContainerOptions) (client.CopyToContainerResult, error)
	imageInspectFn    func(ctx context.Context, ref string) (client.ImageInspectResult, error)
	imagePullFn       func(ctx context.Context, ref string, opts client.ImagePullOptions) (client.ImagePullResponse, error)
	execCreateFn      func(ctx context.Context, ctr string, opts client.ExecCreateOptions) (client.ExecCreateResult, error)
	execAttachFn      func(ctx context.Context, execID string, opts client.ExecAttachOptions) (client.ExecAttachResult, error)
	execInspectFn     func(ctx context.Context, execID string, opts client.ExecInspectOptions) (client.ExecInspectResult, error)
}

func (m *mockDockerAPIClient) Close() error { return nil }

func (m *mockDockerAPIClient) ImageInspect(ctx context.Context, ref string, _ ...client.ImageInspectOption) (client.ImageInspectResult, error) {
	if m.imageInspectFn != nil {
		return m.imageInspectFn(ctx, ref)
	}
	// Default: image already present (no pull needed).
	return client.ImageInspectResult{}, nil
}

func (m *mockDockerAPIClient) ImagePull(ctx context.Context, ref string, opts client.ImagePullOptions) (client.ImagePullResponse, error) {
	if m.imagePullFn != nil {
		return m.imagePullFn(ctx, ref, opts)
	}
	return nil, nil
}

func (m *mockDockerAPIClient) ContainerCreate(ctx context.Context, opts client.ContainerCreateOptions) (client.ContainerCreateResult, error) {
	if m.containerCreateFn != nil {
		return m.containerCreateFn(ctx, opts)
	}
	return client.ContainerCreateResult{ID: "mock-container-id"}, nil
}

func (m *mockDockerAPIClient) ContainerStart(ctx context.Context, ctr string, opts client.ContainerStartOptions) (client.ContainerStartResult, error) {
	if m.containerStartFn != nil {
		return m.containerStartFn(ctx, ctr, opts)
	}
	return client.ContainerStartResult{}, nil
}

func (m *mockDockerAPIClient) CopyToContainer(ctx context.Context, ctr string, opts client.CopyToContainerOptions) (client.CopyToContainerResult, error) {
	if m.copyToContainerFn != nil {
		return m.copyToContainerFn(ctx, ctr, opts)
	}
	return client.CopyToContainerResult{}, nil
}

func (m *mockDockerAPIClient) ContainerList(ctx context.Context, opts client.ContainerListOptions) (client.ContainerListResult, error) {
	if m.containerListFn != nil {
		return m.containerListFn(ctx, opts)
	}
	return client.ContainerListResult{}, nil
}

func (m *mockDockerAPIClient) ContainerLogs(ctx context.Context, ctr string, opts client.ContainerLogsOptions) (client.ContainerLogsResult, error) {
	if m.containerLogsFn != nil {
		return m.containerLogsFn(ctx, ctr, opts)
	}
	return nil, fmt.Errorf("ContainerLogs not configured")
}

func (m *mockDockerAPIClient) ExecCreate(ctx context.Context, ctr string, opts client.ExecCreateOptions) (client.ExecCreateResult, error) {
	if m.execCreateFn != nil {
		return m.execCreateFn(ctx, ctr, opts)
	}
	return client.ExecCreateResult{}, fmt.Errorf("ExecCreate not configured")
}

func (m *mockDockerAPIClient) ExecAttach(ctx context.Context, execID string, opts client.ExecAttachOptions) (client.ExecAttachResult, error) {
	if m.execAttachFn != nil {
		return m.execAttachFn(ctx, execID, opts)
	}
	return client.ExecAttachResult{}, fmt.Errorf("ExecAttach not configured")
}

func (m *mockDockerAPIClient) ExecInspect(ctx context.Context, execID string, opts client.ExecInspectOptions) (client.ExecInspectResult, error) {
	if m.execInspectFn != nil {
		return m.execInspectFn(ctx, execID, opts)
	}
	return client.ExecInspectResult{}, fmt.Errorf("ExecInspect not configured")
}

// buildStdcopyPayload constructs a Docker multiplexed stream payload.
// The Docker stdcopy protocol uses an 8-byte header per frame:
// [stream_type(1), 0, 0, 0, size(4 big-endian)].
func buildStdcopyPayload(streamType byte, content string) io.Reader {
	var buf bytes.Buffer
	header := make([]byte, 8)
	header[0] = streamType
	binary.BigEndian.PutUint32(header[4:], uint32(len(content)))
	buf.Write(header)
	buf.WriteString(content)
	return &buf
}

// newHijackedResponse wraps a reader in a HijackedResponse for testing exec attach.
func newHijackedResponse(r io.Reader) client.ExecAttachResult {
	pr, pw := net.Pipe()
	go func() {
		_, _ = io.Copy(pw, r)
		_ = pw.Close() //nolint:errcheck
	}()
	return client.ExecAttachResult{HijackedResponse: client.NewHijackedResponse(pr, "")}
}

// newTestSandboxRuntimeWithDocker creates a SandboxRuntime with a pre-cached
// per-VM Docker client for the given VM name.
func newTestSandboxRuntimeWithDocker(t *testing.T, vmName string, dockerCli client.APIClient) *SandboxRuntime {
	t.Helper()
	rt, err := NewSandboxRuntime(
		WithSandboxLogger(zaptest.NewLogger(t)),
		WithSandboxClient(&mockSandboxAPI{}),
	)
	if err != nil {
		t.Fatalf("NewSandboxRuntime: %v", err)
	}
	if vmName != "" && dockerCli != nil {
		rt.mu.Lock()
		rt.vmDockerClients[vmName] = dockerCli
		rt.mu.Unlock()
	}
	return rt
}

// ---------------------------------------------------------------------------
// Stop — additional edge case tests
// ---------------------------------------------------------------------------

func TestSandboxRuntime_Stop_DeleteError(t *testing.T) {
	mock := &mockSandboxAPI{
		stopVMFn: func(_ context.Context, _ string) error {
			return nil
		},
		deleteVMFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("delete permission denied")
		},
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(zaptest.NewLogger(t)),
		WithSandboxClient(mock),
	)
	if err != nil {
		t.Fatalf("NewSandboxRuntime: %v", err)
	}

	session := &Session{ContainerID: "ac-fail-delete", Name: "ac-fail-delete", RuntimeType: RuntimeSandbox}
	err = rt.Stop(context.Background(), session)
	if err == nil {
		t.Fatal("expected error when DeleteVM fails")
	}
	if !strings.Contains(err.Error(), "deleting VM") {
		t.Errorf("expected deleting VM error, got: %v", err)
	}
}

func TestSandboxRuntime_Stop_StopErrorFallsThrough(t *testing.T) {
	// When StopVM fails, Stop should still attempt DeleteVM and succeed.
	var deleteCalled bool
	mock := &mockSandboxAPI{
		stopVMFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("stop timed out")
		},
		deleteVMFn: func(_ context.Context, _ string) error {
			deleteCalled = true
			return nil
		},
	}

	rt, err := NewSandboxRuntime(
		WithSandboxLogger(zaptest.NewLogger(t)),
		WithSandboxClient(mock),
	)
	if err != nil {
		t.Fatalf("NewSandboxRuntime: %v", err)
	}

	session := &Session{ContainerID: "ac-stop-fail", Name: "ac-stop-fail", RuntimeType: RuntimeSandbox, Status: "running"}
	if err := rt.Stop(context.Background(), session); err != nil {
		t.Fatalf("expected Stop to succeed despite StopVM failure, got: %v", err)
	}
	if !deleteCalled {
		t.Error("expected DeleteVM to be called despite StopVM failure")
	}
	if session.Status != "stopped" {
		t.Errorf("expected session status stopped, got %s", session.Status)
	}
}

// ---------------------------------------------------------------------------
// Exec — full flow tests with mocked Docker API
// ---------------------------------------------------------------------------

func TestSandboxRuntime_Exec(t *testing.T) {
	mockDocker := &mockDockerAPIClient{
		containerListFn: func(_ context.Context, _ client.ContainerListOptions) (client.ContainerListResult, error) {
			return client.ContainerListResult{
				Items: []container.Summary{
					{ID: "ctr-abc123", State: container.StateRunning},
				},
			}, nil
		},
		execCreateFn: func(_ context.Context, ctr string, opts client.ExecCreateOptions) (client.ExecCreateResult, error) {
			if ctr != "ctr-abc123" {
				t.Errorf("ExecCreate: expected container ctr-abc123, got %s", ctr)
			}
			if len(opts.Cmd) != 2 || opts.Cmd[0] != "echo" || opts.Cmd[1] != "hello" {
				t.Errorf("ExecCreate: unexpected cmd: %v", opts.Cmd)
			}
			return client.ExecCreateResult{ID: "exec-001"}, nil
		},
		execAttachFn: func(_ context.Context, execID string, _ client.ExecAttachOptions) (client.ExecAttachResult, error) {
			if execID != "exec-001" {
				t.Errorf("ExecAttach: expected exec-001, got %s", execID)
			}
			payload := buildStdcopyPayload(1, "hello\n") // 1 = stdout
			return newHijackedResponse(payload), nil
		},
		execInspectFn: func(_ context.Context, execID string, _ client.ExecInspectOptions) (client.ExecInspectResult, error) {
			if execID != "exec-001" {
				t.Errorf("ExecInspect: expected exec-001, got %s", execID)
			}
			return client.ExecInspectResult{ExitCode: 0}, nil
		},
	}

	rt := newTestSandboxRuntimeWithDocker(t, "ac-exec-test", mockDocker)
	session := &Session{ContainerID: "ac-exec-test", Name: "ac-exec-test", RuntimeType: RuntimeSandbox}

	result, err := rt.Exec(context.Background(), session, []string{"echo", "hello"})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
	if !strings.Contains(string(result.Stdout), "hello") {
		t.Errorf("expected stdout to contain hello, got %q", string(result.Stdout))
	}
}

func TestSandboxRuntime_Exec_NonZeroExit(t *testing.T) {
	mockDocker := &mockDockerAPIClient{
		containerListFn: func(_ context.Context, _ client.ContainerListOptions) (client.ContainerListResult, error) {
			return client.ContainerListResult{
				Items: []container.Summary{
					{ID: "ctr-exit1", State: container.StateRunning},
				},
			}, nil
		},
		execCreateFn: func(_ context.Context, _ string, _ client.ExecCreateOptions) (client.ExecCreateResult, error) {
			return client.ExecCreateResult{ID: "exec-exit1"}, nil
		},
		execAttachFn: func(_ context.Context, _ string, _ client.ExecAttachOptions) (client.ExecAttachResult, error) {
			payload := buildStdcopyPayload(2, "command not found\n") // 2 = stderr
			return newHijackedResponse(payload), nil
		},
		execInspectFn: func(_ context.Context, _ string, _ client.ExecInspectOptions) (client.ExecInspectResult, error) {
			return client.ExecInspectResult{ExitCode: 127}, nil
		},
	}

	rt := newTestSandboxRuntimeWithDocker(t, "ac-exit1", mockDocker)
	session := &Session{ContainerID: "ac-exit1", Name: "ac-exit1", RuntimeType: RuntimeSandbox}

	result, err := rt.Exec(context.Background(), session, []string{"badcmd"})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if result.ExitCode != 127 {
		t.Errorf("expected exit code 127, got %d", result.ExitCode)
	}
	if !strings.Contains(string(result.Stderr), "command not found") {
		t.Errorf("expected stderr to contain 'command not found', got %q", string(result.Stderr))
	}
}

func TestSandboxRuntime_Exec_NoRunningContainer(t *testing.T) {
	mockDocker := &mockDockerAPIClient{
		containerListFn: func(_ context.Context, _ client.ContainerListOptions) (client.ContainerListResult, error) {
			return client.ContainerListResult{
				Items: []container.Summary{
					{ID: "ctr-stopped", State: container.StateExited},
				},
			}, nil
		},
	}

	rt := newTestSandboxRuntimeWithDocker(t, "ac-no-running", mockDocker)
	session := &Session{ContainerID: "ac-no-running", Name: "ac-no-running", RuntimeType: RuntimeSandbox}

	_, err := rt.Exec(context.Background(), session, []string{"echo"})
	if err == nil {
		t.Fatal("expected error when no running container found")
	}
	if !strings.Contains(err.Error(), "no running container") {
		t.Errorf("expected no running container error, got: %v", err)
	}
}

func TestSandboxRuntime_Exec_ContainerListError(t *testing.T) {
	mockDocker := &mockDockerAPIClient{
		containerListFn: func(_ context.Context, _ client.ContainerListOptions) (client.ContainerListResult, error) {
			return client.ContainerListResult{}, fmt.Errorf("daemon unavailable")
		},
	}

	rt := newTestSandboxRuntimeWithDocker(t, "ac-list-err", mockDocker)
	session := &Session{ContainerID: "ac-list-err", Name: "ac-list-err", RuntimeType: RuntimeSandbox}

	_, err := rt.Exec(context.Background(), session, []string{"echo"})
	if err == nil {
		t.Fatal("expected error when ContainerList fails")
	}
	if !strings.Contains(err.Error(), "listing containers") {
		t.Errorf("expected listing containers error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Logs — full flow tests with mocked Docker API
// ---------------------------------------------------------------------------

func TestSandboxRuntime_Logs(t *testing.T) {
	mockDocker := &mockDockerAPIClient{
		containerListFn: func(_ context.Context, _ client.ContainerListOptions) (client.ContainerListResult, error) {
			return client.ContainerListResult{
				Items: []container.Summary{
					{ID: "ctr-logs", State: container.StateRunning},
				},
			}, nil
		},
		containerLogsFn: func(_ context.Context, ctr string, _ client.ContainerLogsOptions) (client.ContainerLogsResult, error) {
			if ctr != "ctr-logs" {
				t.Errorf("ContainerLogs: expected ctr-logs, got %s", ctr)
			}
			return io.NopCloser(strings.NewReader("log line 1\nlog line 2\n")), nil
		},
	}

	rt := newTestSandboxRuntimeWithDocker(t, "ac-logs-test", mockDocker)
	session := &Session{ContainerID: "ac-logs-test", Name: "ac-logs-test", RuntimeType: RuntimeSandbox}

	reader, err := rt.Logs(context.Background(), session)
	if err != nil {
		t.Fatalf("Logs: %v", err)
	}
	defer func() { _ = reader.Close() }() //nolint:errcheck

	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("reading logs: %v", err)
	}
	if !strings.Contains(string(data), "log line 1") {
		t.Errorf("expected log output to contain 'log line 1', got %q", string(data))
	}
}

func TestSandboxRuntime_Logs_ContainerLogsError(t *testing.T) {
	mockDocker := &mockDockerAPIClient{
		containerListFn: func(_ context.Context, _ client.ContainerListOptions) (client.ContainerListResult, error) {
			return client.ContainerListResult{
				Items: []container.Summary{
					{ID: "ctr-log-fail", State: container.StateRunning},
				},
			}, nil
		},
		containerLogsFn: func(_ context.Context, _ string, _ client.ContainerLogsOptions) (client.ContainerLogsResult, error) {
			return nil, fmt.Errorf("container logs unavailable")
		},
	}

	rt := newTestSandboxRuntimeWithDocker(t, "ac-log-fail", mockDocker)
	session := &Session{ContainerID: "ac-log-fail", Name: "ac-log-fail", RuntimeType: RuntimeSandbox}

	_, err := rt.Logs(context.Background(), session)
	if err == nil {
		t.Fatal("expected error from Logs")
	}
	if !strings.Contains(err.Error(), "streaming logs") {
		t.Errorf("expected streaming logs error, got: %v", err)
	}
}

func TestSandboxRuntime_Logs_NoDockerClient(t *testing.T) {
	rt := newTestSandboxRuntimeWithDocker(t, "", nil) // no client cached
	session := &Session{ContainerID: "ac-no-client", Name: "ac-no-client", RuntimeType: RuntimeSandbox}

	_, err := rt.Logs(context.Background(), session)
	if err == nil {
		t.Fatal("expected error when no Docker client cached")
	}
	if !strings.Contains(err.Error(), "no docker client") {
		t.Errorf("expected no docker client error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// List — additional tests
// ---------------------------------------------------------------------------

func TestSandboxRuntime_List_FilterStopped(t *testing.T) {
	mock := &mockSandboxAPI{
		listVMsFn: func(_ context.Context) ([]sandbox.VMListEntry, error) {
			return []sandbox.VMListEntry{
				{VMID: "vm-run-1", VMName: "ac-running", Status: "running", Active: true},
				{VMID: "vm-stop-1", VMName: "ac-stopped", Status: "stopped", Active: false},
				{VMID: "vm-start-1", VMName: "ac-active-starting", Status: "starting", Active: true},
			}, nil
		},
	}

	rt, err := NewSandboxRuntime(
		WithSandboxClient(mock),
	)
	if err != nil {
		t.Fatalf("NewSandboxRuntime: %v", err)
	}

	// all=false: only running or active VMs.
	sessions, err := rt.List(context.Background(), false)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions (running + active), got %d", len(sessions))
	}
	for _, s := range sessions {
		if s.Name == "ac-stopped" {
			t.Error("expected ac-stopped to be filtered out when all=false")
		}
		// Verify ContainerID uses VMID, not VMName.
		if s.ContainerID == s.Name {
			t.Errorf("ContainerID should be VMID not VMName for %s, got %s", s.Name, s.ContainerID)
		}
	}
}
