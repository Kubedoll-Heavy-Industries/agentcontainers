//go:build integration

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/container"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/policy"
)

// writeTestConfig writes a config file and returns its path.
func writeTestConfig(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

const integrationConfig = `{
    "name": "cli-integration-test",
    "image": "alpine:3.19",
    "agent": {
        "capabilities": {
            "shell": {
                "commands": [
                    {"binary": "echo"},
                    {"binary": "ls"},
                    {"binary": "cat"}
                ]
            }
        }
    }
}`

// startIntegrationContainer starts a container for integration testing and
// registers a cleanup function to stop it.
func startIntegrationContainer(t *testing.T, ctx context.Context, cfgPath string) (container.Runtime, *container.Session) {
	t.Helper()

	cfg, err := config.ParseFile(cfgPath)
	if err != nil {
		t.Fatalf("parsing config: %v", err)
	}

	// Make name unique to avoid collisions.
	cfg.Name = cfg.Name + "-" + time.Now().Format("150405.000")

	rt, err := container.NewDockerRuntime(container.WithStopTimeout(5 * time.Second))
	if err != nil {
		t.Fatalf("creating docker runtime: %v", err)
	}

	var caps *config.Capabilities
	if cfg.Agent != nil {
		caps = cfg.Agent.Capabilities
	}
	p := policy.Resolve(caps)
	// Alpine has no tmpfs; disable read-only root for integration tests.
	p.ReadonlyRootfs = false

	session, err := rt.Start(ctx, cfg, container.StartOptions{
		Detach: true,
		Policy: p,
	})
	if err != nil {
		t.Fatalf("starting container: %v", err)
	}

	t.Cleanup(func() {
		if stopErr := rt.Stop(context.Background(), session); stopErr != nil {
			t.Logf("warning: failed to stop container %s: %v", session.ContainerID, stopErr)
		}
	})

	return rt, session
}

func TestCLI_FullWorkflow_Integration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dir := t.TempDir()
	cfgPath := writeTestConfig(t, dir, integrationConfig)

	rt, session := startIntegrationContainer(t, ctx, cfgPath)

	if session.ContainerID == "" {
		t.Fatal("expected non-empty container ID")
	}
	if session.RuntimeType != container.RuntimeDocker {
		t.Errorf("runtime type = %q, want %q", session.RuntimeType, container.RuntimeDocker)
	}
	if session.Status != "running" {
		t.Errorf("status = %q, want %q", session.Status, "running")
	}

	// Exec a command.
	result, err := rt.Exec(ctx, session, []string{"echo", "hello from integration test"})
	if err != nil {
		t.Fatalf("exec failed: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", result.ExitCode)
	}
	if !strings.Contains(string(result.Stdout), "hello from integration test") {
		t.Errorf("stdout = %q, want to contain 'hello from integration test'", string(result.Stdout))
	}

	// Stream logs.
	logReader, err := rt.Logs(ctx, session)
	if err != nil {
		t.Fatalf("logs failed: %v", err)
	}
	logReader.Close()

	// Stop container (cleanup deferred, but we test explicitly).
	if err := rt.Stop(ctx, session); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
	if session.Status != "stopped" {
		t.Errorf("status after stop = %q, want %q", session.Status, "stopped")
	}
}

func TestCLI_RunDetached_Integration(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeTestConfig(t, dir, integrationConfig)

	cmd := newRootCmd("test", "integration", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"run", "--detach", "--config", cfgPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("run command failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Session started") {
		t.Errorf("expected 'Session started' in output, got: %s", output)
	}
	if !strings.Contains(output, "detached") {
		t.Errorf("expected 'detached' in output, got: %s", output)
	}

	// Extract container ID for cleanup.
	var containerID string
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "Container:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				containerID = strings.TrimSpace(parts[1])
			}
		}
	}
	if containerID == "" {
		t.Fatal("could not extract container ID from output")
	}

	t.Cleanup(func() {
		stopCmd := newRootCmd("test", "integration", "now")
		var stopBuf bytes.Buffer
		stopCmd.SetOut(&stopBuf)
		stopCmd.SetErr(&stopBuf)
		stopCmd.SetArgs([]string{"stop", containerID})
		if stopErr := stopCmd.Execute(); stopErr != nil {
			t.Logf("warning: stop failed during cleanup: %v", stopErr)
		}
	})
}

func TestCLI_ExecCommand_Integration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dir := t.TempDir()
	cfgPath := writeTestConfig(t, dir, integrationConfig)
	_, session := startIntegrationContainer(t, ctx, cfgPath)

	execCmd := newRootCmd("test", "integration", "now")
	var buf bytes.Buffer
	execCmd.SetOut(&buf)
	execCmd.SetErr(&buf)
	execCmd.SetArgs([]string{"exec", session.ContainerID, "--", "echo", "exec-test-output"})

	if err := execCmd.Execute(); err != nil {
		t.Fatalf("exec command failed: %v", err)
	}

	if !strings.Contains(buf.String(), "exec-test-output") {
		t.Errorf("expected 'exec-test-output' in output, got: %s", buf.String())
	}
}

func TestCLI_StopCommand_Integration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dir := t.TempDir()
	cfgPath := writeTestConfig(t, dir, integrationConfig)

	cfg, err := config.ParseFile(cfgPath)
	if err != nil {
		t.Fatalf("parsing config: %v", err)
	}
	cfg.Name = cfg.Name + "-stop-" + time.Now().Format("150405.000")

	rt, err := container.NewDockerRuntime(container.WithStopTimeout(5 * time.Second))
	if err != nil {
		t.Fatalf("creating docker runtime: %v", err)
	}

	p := policy.Resolve(nil)
	p.ReadonlyRootfs = false

	session, err := rt.Start(ctx, cfg, container.StartOptions{Detach: true, Policy: p})
	if err != nil {
		t.Fatalf("starting container: %v", err)
	}

	stopCmd := newRootCmd("test", "integration", "now")
	var buf bytes.Buffer
	stopCmd.SetOut(&buf)
	stopCmd.SetErr(&buf)
	stopCmd.SetArgs([]string{"stop", session.ContainerID})

	if stopErr := stopCmd.Execute(); stopErr != nil {
		t.Fatalf("stop command failed: %v", stopErr)
	}

	if !strings.Contains(buf.String(), "stopped and removed") {
		t.Errorf("expected 'stopped and removed' in output, got: %s", buf.String())
	}
}

func TestCLI_MultipleExec_Integration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dir := t.TempDir()
	cfgPath := writeTestConfig(t, dir, integrationConfig)
	rt, session := startIntegrationContainer(t, ctx, cfgPath)

	commands := []struct {
		name string
		cmd  []string
		want string
	}{
		{"echo", []string{"echo", "first"}, "first"},
		{"ls root", []string{"ls", "/"}, "etc"},
		{"echo again", []string{"echo", "second"}, "second"},
	}

	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			result, err := rt.Exec(ctx, session, tc.cmd)
			if err != nil {
				t.Fatalf("exec %q failed: %v", tc.name, err)
			}
			if result.ExitCode != 0 {
				t.Errorf("exit code = %d, want 0", result.ExitCode)
			}
			if !strings.Contains(string(result.Stdout), tc.want) {
				t.Errorf("stdout = %q, want to contain %q", string(result.Stdout), tc.want)
			}
		})
	}
}
