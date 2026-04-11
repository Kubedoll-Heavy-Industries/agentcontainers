//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

func TestLifecycle_StartExecStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cfg := &config.AgentContainer{
		Name:  "integration-lifecycle",
		Image: testImage,
	}

	rt, session := startContainer(t, ctx, cfg)

	if session.ContainerID == "" {
		t.Fatal("container ID is empty")
	}

	result, err := rt.Exec(ctx, session, []string{"echo", "hello-integration"})
	if err != nil {
		t.Fatalf("exec failed: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", result.ExitCode)
	}
	if !strings.Contains(string(result.Stdout), "hello-integration") {
		t.Errorf("stdout = %q, want to contain 'hello-integration'", string(result.Stdout))
	}

	if err := rt.Stop(ctx, session); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
}

func TestLifecycle_List(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cfg := &config.AgentContainer{
		Name:  "integration-list",
		Image: testImage,
	}

	rt, _ := startContainer(t, ctx, cfg)

	sessions, err := rt.List(ctx, false)
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}

	found := false
	for _, s := range sessions {
		if strings.Contains(s.Name, "integration-list") {
			found = true
			break
		}
	}
	if !found {
		t.Error("started container not found in list")
	}
}

func TestLifecycle_MultipleExec(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cfg := &config.AgentContainer{
		Name:  "integration-multi-exec",
		Image: testImage,
	}

	rt, session := startContainer(t, ctx, cfg)

	commands := []struct {
		cmd  []string
		want string
	}{
		{[]string{"echo", "first"}, "first"},
		{[]string{"ls", "/"}, "etc"},
		{[]string{"cat", "/etc/hostname"}, ""},
	}

	for _, tc := range commands {
		result, err := rt.Exec(ctx, session, tc.cmd)
		if err != nil {
			t.Fatalf("exec %v failed: %v", tc.cmd, err)
		}
		if result.ExitCode != 0 {
			t.Errorf("exec %v: exit code = %d, want 0", tc.cmd, result.ExitCode)
		}
		if tc.want != "" && !strings.Contains(string(result.Stdout), tc.want) {
			t.Errorf("exec %v: stdout = %q, want to contain %q", tc.cmd, string(result.Stdout), tc.want)
		}
	}
}
