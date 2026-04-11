package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/container"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
)

func newLogsCmd() *cobra.Command {
	var (
		runtime string
		follow  bool
	)

	cmd := &cobra.Command{
		Use:   "logs <container-id>",
		Short: "Fetch logs from an agent container",
		Long: `Stream logs from the container identified by <container-id>.
If --follow is specified, logs are streamed continuously until interrupted.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogs(cmd, args[0], runtime, follow)
		},
	}

	cmd.Flags().StringVar(&runtime, "runtime", "docker", "Container runtime backend (auto|docker|compose|sandbox)")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Stream logs continuously until interrupted")

	return cmd
}

func runLogs(cmd *cobra.Command, containerID string, runtimeFlag string, follow bool) error {
	rt, err := newRuntime(runtimeFlag, logger, enforcement.LevelNone)
	if err != nil {
		return fmt.Errorf("logs: %w", err)
	}

	session := &container.Session{
		ContainerID: containerID,
		RuntimeType: container.RuntimeType(runtimeFlag),
	}

	ctx := cmd.Context()
	if follow {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			cancel()
		}()
	}

	reader, err := rt.Logs(ctx, session)
	if err != nil {
		return fmt.Errorf("logs: %w", err)
	}
	defer reader.Close() //nolint:errcheck

	if _, err := io.Copy(cmd.OutOrStdout(), reader); err != nil {
		if follow && ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("logs: reading output: %w", err)
	}

	return nil
}
