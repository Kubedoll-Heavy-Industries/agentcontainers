//go:build integration

package integration

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/container"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/sandbox"
)

// startSandboxVM creates a Sandbox VM, registers cleanup, and returns the
// runtime and session. Skips if sandboxd is not available.
func startSandboxVM(t *testing.T, ctx context.Context, cfg *config.AgentContainer) (*container.SandboxRuntime, *container.Session) {
	t.Helper()

	if !container.DefaultSandboxProber() {
		t.Skip("sandboxd not available, skipping sandbox integration test")
	}

	rt, err := container.NewSandboxRuntime(
		container.WithSandboxLogger(nil), // nop logger
	)
	if err != nil {
		t.Fatalf("creating sandbox runtime: %v", err)
	}

	// Use the real project workspace so the sandbox VM has a valid
	// directory to mount. The sandboxd agent boots a devcontainer inside
	// the VM using this path.
	workDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getting working directory: %v", err)
	}

	session, err := rt.Start(ctx, cfg, container.StartOptions{
		Detach:        true,
		WorkspacePath: workDir,
	})
	if err != nil {
		t.Fatalf("starting sandbox VM: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if stopErr := rt.Stop(cleanupCtx, session); stopErr != nil {
			t.Logf("cleanup: failed to stop sandbox VM: %v", stopErr)
		}
	})

	return rt, session
}

func TestSandbox_Health(t *testing.T) {
	if !container.DefaultSandboxProber() {
		t.Skip("sandboxd not available")
	}

	c, err := sandbox.NewClient()
	if err != nil {
		t.Fatalf("creating sandbox client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	h, err := c.Health(ctx)
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}

	if h.Status == "" {
		t.Error("health status is empty")
	}
	t.Logf("sandboxd health: status=%s version=%s vms=%d", h.Status, h.Version, h.VMs)
}

func TestSandbox_StartExecStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cfg := &config.AgentContainer{
		Name: "integ-sandbox-lifecycle",
	}

	rt, session := startSandboxVM(t, ctx, cfg)

	// Verify session fields.
	if session.ContainerID == "" {
		t.Fatal("session ContainerID (VMID) is empty")
	}
	if session.Name == "" {
		t.Fatal("session Name is empty")
	}
	if session.RuntimeType != container.RuntimeSandbox {
		t.Errorf("session RuntimeType = %q, want %q", session.RuntimeType, container.RuntimeSandbox)
	}
	if session.Status != "running" {
		t.Errorf("session Status = %q, want 'running'", session.Status)
	}
	t.Logf("VM started: name=%s id=%s", session.Name, session.ContainerID)

	// Wait for the agent container inside the VM to start.
	// Sandbox VMs take a moment to boot and start their Docker daemon + agent.
	var execErr error
	for i := 0; i < 30; i++ {
		_, execErr = rt.Exec(ctx, session, []string{"echo", "probe"})
		if execErr == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if execErr != nil {
		t.Fatalf("agent container never became ready: %v", execErr)
	}

	// Run a command inside the sandboxed agent container.
	result, err := rt.Exec(ctx, session, []string{"echo", "hello-sandbox"})
	if err != nil {
		t.Fatalf("exec failed: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0; stderr: %s", result.ExitCode, string(result.Stderr))
	}
	if !strings.Contains(string(result.Stdout), "hello-sandbox") {
		t.Errorf("stdout = %q, want to contain 'hello-sandbox'", string(result.Stdout))
	}

	// Test list — our VM should appear.
	sessions, err := rt.List(ctx, false)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	found := false
	for _, s := range sessions {
		if s.Name == session.Name {
			found = true
			break
		}
	}
	if !found {
		t.Error("started VM not found in list")
	}

	// Stop the VM.
	if err := rt.Stop(ctx, session); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
	t.Logf("VM stopped: name=%s", session.Name)
}

func TestSandbox_ProxyConfig(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cfg := &config.AgentContainer{
		Name: "integ-sandbox-proxy",
		Agent: &config.AgentConfig{
			Capabilities: &config.Capabilities{
				Network: &config.NetworkCaps{
					Egress: []config.EgressRule{
						{Host: "api.github.com", Port: 443},
					},
				},
			},
		},
	}

	rt, session := startSandboxVM(t, ctx, cfg)

	// The VM was created with proxy config pushed. Verify it's running.
	if session.Status != "running" {
		t.Errorf("session Status = %q, want 'running'", session.Status)
	}

	// Wait for agent container readiness.
	var execErr error
	for i := 0; i < 30; i++ {
		_, execErr = rt.Exec(ctx, session, []string{"echo", "probe"})
		if execErr == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if execErr != nil {
		t.Fatalf("agent container never became ready: %v", execErr)
	}

	// Verify the proxy environment is configured inside the container.
	// SandboxRuntime.Start forwards ProxyEnvVars from the VM creation
	// response into the agent container's environment.
	result, err := rt.Exec(ctx, session, []string{"env"})
	if err != nil {
		t.Fatalf("exec env failed: %v", err)
	}
	envOut := string(result.Stdout)
	t.Logf("env output:\n%s", envOut)

	for _, key := range []string{"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY"} {
		if !strings.Contains(envOut, key+"=") {
			t.Errorf("expected %s in container env", key)
		}
	}

	// Verify the MITM proxy CA certificate was injected into the container.
	// SandboxRuntime.Start copies the base64-encoded PEM cert from the VM
	// creation response into /usr/local/share/ca-certificates/proxy-ca.crt.
	certResult, err := rt.Exec(ctx, session, []string{"cat", "/usr/local/share/ca-certificates/proxy-ca.crt"})
	if err != nil {
		t.Fatalf("exec cat proxy-ca.crt failed: %v", err)
	}
	if certResult.ExitCode != 0 {
		t.Errorf("proxy-ca.crt not found in container; exit code = %d, stderr: %s",
			certResult.ExitCode, string(certResult.Stderr))
	}
	certOut := string(certResult.Stdout)
	if !strings.Contains(certOut, "BEGIN CERTIFICATE") {
		t.Errorf("proxy-ca.crt does not contain PEM certificate data; got: %s", certOut[:min(len(certOut), 200)])
	}
	t.Logf("proxy CA cert present (%d bytes)", len(certOut))

	if err := rt.Stop(ctx, session); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
}
