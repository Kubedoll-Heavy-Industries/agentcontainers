package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/container"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
)

func newStopCmd() *cobra.Command {
	var (
		runtime string
		force   bool
	)

	cmd := &cobra.Command{
		Use:   "stop <container-id>",
		Short: "Stop a running agent container",
		Long: `Gracefully stop the container identified by <container-id> and remove it.
If --force is specified, the container is killed with a shorter timeout.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStop(cmd, args[0], runtime, force)
		},
	}

	cmd.Flags().StringVar(&runtime, "runtime", "docker", "Container runtime backend (auto|docker|compose|sandbox)")
	cmd.Flags().BoolVar(&force, "force", false, "Force stop with shorter timeout")

	return cmd
}

func runStop(cmd *cobra.Command, containerID string, runtimeFlag string, force bool) error {
	rt, err := newRuntime(runtimeFlag, logger, enforcement.LevelNone)
	if err != nil {
		return fmt.Errorf("stop: %w", err)
	}

	// For Docker with --force, recreate with shorter stop timeout.
	if force && container.RuntimeType(runtimeFlag) == container.RuntimeDocker {
		rt, err = container.NewDockerRuntime(
			container.WithDockerLogger(logger),
			container.WithStopTimeout(1),
		)
		if err != nil {
			return fmt.Errorf("stop: creating runtime: %w", err)
		}
	}

	session := &container.Session{
		ContainerID: containerID,
		RuntimeType: container.RuntimeType(runtimeFlag),
	}

	if err := rt.Stop(cmd.Context(), session); err != nil {
		return fmt.Errorf("stop: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Container %s stopped\n", shortID(containerID))
	return nil
}
