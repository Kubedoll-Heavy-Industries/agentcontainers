//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/container"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/policy"
)

const testImage = "alpine:3.19"

// writeConfig writes an agentcontainer.json to the given directory.
func writeConfig(t *testing.T, dir string, content string) string {
	t.Helper()
	path := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

// startContainer creates and starts a test container, registering cleanup.
func startContainer(t *testing.T, ctx context.Context, cfg *config.AgentContainer) (*container.DockerRuntime, *container.Session) {
	t.Helper()

	rt, err := container.NewDockerRuntime(container.WithStopTimeout(5 * time.Second))
	if err != nil {
		t.Fatalf("creating docker runtime: %v", err)
	}

	p := policy.Resolve(nil)
	p.ReadonlyRootfs = false // alpine needs writable rootfs for tests

	session, err := rt.Start(ctx, cfg, container.StartOptions{
		Detach: true,
		Policy: p,
	})
	if err != nil {
		t.Fatalf("starting container: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = rt.Stop(cleanupCtx, session)
	})

	return rt, session
}
