//go:build integration

package container

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

// ---------------------------------------------------------------------------
// Integration tests — require a running Docker daemon.
// Run with: go test -tags integration ./internal/container/...
// ---------------------------------------------------------------------------

func TestDockerRuntime_StartStop_Integration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rt, err := NewDockerRuntime(
		WithDockerLogger(zap.NewExample()),
		WithStopTimeout(5*time.Second),
	)
	require.NoError(t, err)

	cfg := &config.AgentContainer{
		Name:  "integration-test-" + time.Now().Format("150405"),
		Image: "alpine:3.19",
	}

	session, err := rt.Start(ctx, cfg, StartOptions{})
	require.NoError(t, err)
	require.NotNil(t, session)

	assert.NotEmpty(t, session.ContainerID)
	assert.Equal(t, RuntimeDocker, session.RuntimeType)
	assert.Equal(t, "running", session.Status)

	// Clean up.
	err = rt.Stop(ctx, session)
	require.NoError(t, err)
	assert.Equal(t, "stopped", session.Status)
}

func TestDockerRuntime_Exec_Integration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rt, err := NewDockerRuntime(
		WithDockerLogger(zap.NewExample()),
		WithStopTimeout(5*time.Second),
	)
	require.NoError(t, err)

	cfg := &config.AgentContainer{
		Name:  "exec-test-" + time.Now().Format("150405"),
		Image: "alpine:3.19",
	}

	session, err := rt.Start(ctx, cfg, StartOptions{})
	require.NoError(t, err)
	defer func() { _ = rt.Stop(ctx, session) }()

	result, err := rt.Exec(ctx, session, []string{"echo", "hello"})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
	assert.Contains(t, string(result.Stdout), "hello")
}

func TestDockerRuntime_Logs_Integration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rt, err := NewDockerRuntime(
		WithDockerLogger(zap.NewExample()),
		WithStopTimeout(5*time.Second),
	)
	require.NoError(t, err)

	cfg := &config.AgentContainer{
		Name:  "logs-test-" + time.Now().Format("150405"),
		Image: "alpine:3.19",
	}

	session, err := rt.Start(ctx, cfg, StartOptions{})
	require.NoError(t, err)
	defer func() { _ = rt.Stop(ctx, session) }()

	reader, err := rt.Logs(ctx, session)
	require.NoError(t, err)
	require.NotNil(t, reader)
	reader.Close()
}

func TestDockerRuntime_StartEmptyImage_Integration(t *testing.T) {
	ctx := context.Background()

	rt, err := NewDockerRuntime(WithDockerLogger(zap.NewExample()))
	require.NoError(t, err)

	_, err = rt.Start(ctx, &config.AgentContainer{Name: "no-image"}, StartOptions{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "image is required")
}
