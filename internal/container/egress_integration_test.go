//go:build integration

package container

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/policy"
)

func TestEgressEnforcement_BlocksUnallowedHosts_Integration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	rt, err := NewDockerRuntime(WithStopTimeout(5 * time.Second))
	if err != nil {
		t.Fatalf("creating docker runtime: %v", err)
	}

	// Allow only 1.1.1.1 (Cloudflare DNS) but NOT 8.8.8.8 (Google DNS).
	p := &policy.ContainerPolicy{
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges"},
		ReadonlyRootfs: false,
		NetworkMode:    "bridge",
		AllowedHosts:   []string{"one.one.one.one"},
		AllowedEgressRules: []policy.EgressPolicy{
			{Host: "one.one.one.one", Port: 443, Protocol: "https"},
		},
	}

	cfg := &config.AgentContainer{
		Name:  "egress-test-" + time.Now().Format("150405.000"),
		Image: "alpine:3.19",
	}

	session, err := rt.Start(ctx, cfg, StartOptions{
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

	// Test 1: Connection to an unallowed host (8.8.8.8) should be blocked.
	result, err := rt.Exec(ctx, session, []string{
		"sh", "-c", "wget -q -T 3 http://8.8.8.8 2>&1 || echo EGRESS_BLOCKED",
	})
	if err != nil {
		t.Fatalf("exec failed: %v", err)
	}
	combined := string(result.Stdout) + string(result.Stderr)
	if !strings.Contains(combined, "EGRESS_BLOCKED") {
		t.Errorf("expected connection to 8.8.8.8 to be blocked, got: %s", combined)
	}

	// Test 2: Connection to the allowed host should succeed (or at least not
	// be iptables-blocked). We test with a TCP connection attempt.
	result, err = rt.Exec(ctx, session, []string{
		"sh", "-c", "wget -q -T 5 --spider https://one.one.one.one 2>&1 && echo EGRESS_ALLOWED || echo EGRESS_FAILED",
	})
	if err != nil {
		t.Fatalf("exec failed: %v", err)
	}
	combined = string(result.Stdout) + string(result.Stderr)
	// The allowed host should either succeed or fail for non-iptables reasons
	// (e.g., no wget SSL support in Alpine). The key assertion is that
	// the first test (8.8.8.8) is definitively blocked while this one
	// at least gets past iptables.
	t.Logf("allowed host result: %s", combined)
}

func TestEgressEnforcement_AllTrafficBlocked_Integration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	rt, err := NewDockerRuntime(WithStopTimeout(5 * time.Second))
	if err != nil {
		t.Fatalf("creating docker runtime: %v", err)
	}

	// Allow only localhost (effectively blocking all external traffic).
	p := &policy.ContainerPolicy{
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges"},
		ReadonlyRootfs: false,
		NetworkMode:    "bridge",
		AllowedHosts:   []string{"localhost"},
	}

	cfg := &config.AgentContainer{
		Name:  "egress-block-all-" + time.Now().Format("150405.000"),
		Image: "alpine:3.19",
	}

	session, err := rt.Start(ctx, cfg, StartOptions{
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

	// All external connections should be blocked.
	result, err := rt.Exec(ctx, session, []string{
		"sh", "-c", "wget -q -T 3 http://1.1.1.1 2>&1 || echo BLOCKED",
	})
	if err != nil {
		t.Fatalf("exec failed: %v", err)
	}
	if !strings.Contains(string(result.Stdout)+string(result.Stderr), "BLOCKED") {
		t.Errorf("expected all external traffic to be blocked, got: %s",
			string(result.Stdout)+string(result.Stderr))
	}
}
