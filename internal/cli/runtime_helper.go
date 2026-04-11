package cli

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/container"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
)

// newRuntime creates the appropriate container runtime based on the runtime
// flag value. Docker and Compose are fully implemented; Sandbox remains
// unimplemented. When an enforcement level is provided, it is passed to the
// Docker runtime for policy enforcement wiring.
func newRuntime(runtimeFlag string, log *zap.Logger, enfLevel enforcement.Level) (container.Runtime, error) {
	runtimeType := container.RuntimeType(runtimeFlag)

	// Auto-detect: probe for Sandbox, fall back to Docker.
	if runtimeType == "auto" {
		runtimeType = container.DetectRuntime(container.DefaultSandboxProber)
		log.Info("runtime auto-detected", zap.String("runtime", string(runtimeType)))
	}

	switch runtimeType {
	case container.RuntimeDocker:
		rt, err := container.NewDockerRuntime(
			container.WithDockerLogger(log),
			container.WithEnforcementLevel(enfLevel),
		)
		if err != nil {
			return nil, fmt.Errorf("creating docker runtime: %w", err)
		}
		return rt, nil
	case container.RuntimeCompose:
		rt, err := container.NewComposeRuntime(
			container.WithComposeLogger(log),
			container.WithComposeEnforcementLevel(enfLevel),
		)
		if err != nil {
			return nil, fmt.Errorf("creating compose runtime: %w", err)
		}
		return rt, nil
	case container.RuntimeSandbox:
		rt, err := container.NewSandboxRuntime(
			container.WithSandboxLogger(log),
			container.WithSandboxEnforcementLevel(enfLevel),
		)
		if err != nil {
			return nil, fmt.Errorf("creating sandbox runtime: %w", err)
		}
		return rt, nil
	default:
		return nil, fmt.Errorf("unknown runtime %q (valid: auto, docker, compose, sandbox)", runtimeFlag)
	}
}
