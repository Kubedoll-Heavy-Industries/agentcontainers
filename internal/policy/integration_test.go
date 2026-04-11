//go:build integration

package policy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/container"
)

// newTestRuntime creates a DockerRuntime for integration testing.
func newTestRuntime(t *testing.T) container.Runtime {
	t.Helper()
	rt, err := container.NewDockerRuntime(container.WithStopTimeout(5 * time.Second))
	if err != nil {
		t.Fatalf("creating docker runtime: %v", err)
	}
	return rt
}

// startWithPolicy starts a container with the given policy and registers cleanup.
func startWithPolicy(t *testing.T, ctx context.Context, rt container.Runtime, p *ContainerPolicy) *container.Session {
	t.Helper()

	cfg := &config.AgentContainer{
		Name:  "policy-test-" + time.Now().Format("150405.000"),
		Image: "alpine:3.19",
	}

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

	return session
}

func TestPolicy_NetworkNone_BlocksConnectivity_Integration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rt := newTestRuntime(t)

	p := Resolve(nil) // default-deny: network=none
	p.ReadonlyRootfs = false

	session := startWithPolicy(t, ctx, rt, p)

	// Attempt a network connection; should fail with network=none.
	result, err := rt.Exec(ctx, session, []string{"sh", "-c", "wget -q -T 2 http://1.1.1.1 2>&1 || echo NETWORK_BLOCKED"})
	if err != nil {
		t.Fatalf("exec failed: %v", err)
	}
	if !strings.Contains(string(result.Stdout)+string(result.Stderr), "NETWORK_BLOCKED") {
		t.Errorf("expected network to be blocked, got stdout=%q stderr=%q", string(result.Stdout), string(result.Stderr))
	}
}

func TestPolicy_ReadOnlyRootfs_BlocksWrites_Integration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rt := newTestRuntime(t)

	p := Resolve(nil)
	p.ReadonlyRootfs = true
	p.NetworkMode = "bridge" // allow network so container starts cleanly

	session := startWithPolicy(t, ctx, rt, p)

	result, err := rt.Exec(ctx, session, []string{"sh", "-c", "touch /testfile 2>&1 || echo READONLY_BLOCKED"})
	if err != nil {
		t.Fatalf("exec failed: %v", err)
	}
	if !strings.Contains(string(result.Stdout)+string(result.Stderr), "READONLY_BLOCKED") &&
		!strings.Contains(string(result.Stdout)+string(result.Stderr), "Read-only") {
		t.Errorf("expected read-only root to block writes, got stdout=%q stderr=%q", string(result.Stdout), string(result.Stderr))
	}
}

func TestPolicy_WritableRootfs_AllowsWrites_Integration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rt := newTestRuntime(t)

	p := Resolve(nil)
	p.ReadonlyRootfs = false

	session := startWithPolicy(t, ctx, rt, p)

	result, err := rt.Exec(ctx, session, []string{"sh", "-c", "touch /testfile && echo WRITE_OK"})
	if err != nil {
		t.Fatalf("exec failed: %v", err)
	}
	if !strings.Contains(string(result.Stdout), "WRITE_OK") {
		t.Errorf("expected write to succeed, got stdout=%q", string(result.Stdout))
	}
}

func TestPolicy_CapDropAll_Integration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rt := newTestRuntime(t)

	p := Resolve(nil) // drops ALL capabilities by default
	p.ReadonlyRootfs = false

	session := startWithPolicy(t, ctx, rt, p)

	// chown requires CAP_CHOWN which should be dropped.
	result, err := rt.Exec(ctx, session, []string{"sh", "-c", "chown nobody /tmp 2>&1 || echo CAP_BLOCKED"})
	if err != nil {
		t.Fatalf("exec failed: %v", err)
	}
	if !strings.Contains(string(result.Stdout)+string(result.Stderr), "CAP_BLOCKED") &&
		!strings.Contains(string(result.Stdout)+string(result.Stderr), "Operation not permitted") {
		t.Errorf("expected chown to fail with caps dropped, got stdout=%q stderr=%q", string(result.Stdout), string(result.Stderr))
	}
}

func TestPolicy_CombinedNetworkAndReadonly_Integration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rt := newTestRuntime(t)

	p := Resolve(nil)
	p.NetworkMode = "none"
	p.ReadonlyRootfs = true

	session := startWithPolicy(t, ctx, rt, p)

	// Both network and writes should fail.
	result, err := rt.Exec(ctx, session, []string{"sh", "-c", "touch /testfile 2>&1 || echo READONLY; wget -q -T 1 http://1.1.1.1 2>&1 || echo NONET"})
	if err != nil {
		t.Fatalf("exec failed: %v", err)
	}
	combined := string(result.Stdout) + string(result.Stderr)
	if !strings.Contains(combined, "READONLY") && !strings.Contains(combined, "Read-only") {
		t.Errorf("expected read-only enforcement, got: %s", combined)
	}
	if !strings.Contains(combined, "NONET") {
		t.Errorf("expected network enforcement, got: %s", combined)
	}
}
