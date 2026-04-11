package cli

import (
	"fmt"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/sidecar"
)

func newEnforcerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enforcer",
		Short: "Manage the ac-enforcer BPF enforcement sidecar",
		Long: `Manage the ac-enforcer container that provides BPF-based enforcement
via a gRPC sidecar. The enforcer runs as a privileged container with
access to cgroups and BPF filesystems, providing network, filesystem,
and process enforcement for agent containers.`,
	}

	cmd.AddCommand(
		newEnforcerStartCmd(),
		newEnforcerStopCmd(),
		newEnforcerStatusCmd(),
		newEnforcerDiagnoseCmd(),
	)

	return cmd
}

func newEnforcerStartCmd() *cobra.Command {
	var (
		image string
		port  int
	)

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the ac-enforcer sidecar container",
		Long: `Pull and start the ac-enforcer container with the required capabilities
and mounts for BPF enforcement. After starting, the command probes the
gRPC health endpoint to verify the enforcer is ready.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnforcerStart(cmd, image, port)
		},
	}

	cmd.Flags().StringVar(&image, "image", sidecar.DefaultEnforcerImage, "ac-enforcer OCI image reference")
	cmd.Flags().IntVar(&port, "port", sidecar.DefaultPort, "gRPC listen port")

	return cmd
}

func newEnforcerStopCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the ac-enforcer sidecar container",
		Long:  `Stop and remove the ac-enforcer container.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnforcerStop(cmd, force)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Force remove the container")

	return cmd
}

func newEnforcerStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show ac-enforcer sidecar status",
		Long:  `Check whether the ac-enforcer container is running and probe its gRPC health endpoint.`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnforcerStatus(cmd)
		},
	}

	return cmd
}

// newDockerClient creates a Docker API client from the environment.
// This is separated for testability — the function can be replaced in tests.
var newDockerClient = func() (client.APIClient, error) {
	return client.New(client.FromEnv)
}

func runEnforcerStart(cmd *cobra.Command, image string, port int) error {
	ctx := cmd.Context()
	out := cmd.OutOrStdout()

	cli, err := newDockerClient()
	if err != nil {
		return fmt.Errorf("enforcer start: creating docker client: %w", err)
	}

	_, _ = fmt.Fprintln(out, "Starting ac-enforcer sidecar...")

	handle, err := sidecar.StartSidecar(ctx, cli, sidecar.StartOptions{
		Image:    image,
		Port:     port,
		Required: true,
	})
	if err != nil {
		return fmt.Errorf("enforcer start: %w", err)
	}
	if handle == nil {
		return fmt.Errorf("enforcer start: failed to start sidecar")
	}

	_, _ = fmt.Fprintf(out, "Enforcer started\n  Address: 127.0.0.1:%d\n  Container: %s\n", port, shortID(handle.ContainerID))
	return nil
}

func runEnforcerStop(cmd *cobra.Command, force bool) error {
	ctx := cmd.Context()
	out := cmd.OutOrStdout()

	cli, err := newDockerClient()
	if err != nil {
		return fmt.Errorf("enforcer stop: creating docker client: %w", err)
	}

	// Check if the container exists first.
	result, err := cli.ContainerInspect(ctx, sidecar.ContainerName, client.ContainerInspectOptions{})
	if err != nil {
		return fmt.Errorf("enforcer stop: container %q not found: %w", sidecar.ContainerName, err)
	}

	containerID := result.Container.ID

	// Use StopSidecar with a synthetic handle for managed teardown.
	handle := &sidecar.SidecarHandle{
		ContainerID: containerID,
		Managed:     true,
	}

	if force {
		// Force remove directly without graceful stop.
		if _, err := cli.ContainerRemove(ctx, containerID, client.ContainerRemoveOptions{
			Force:         true,
			RemoveVolumes: true,
		}); err != nil {
			return fmt.Errorf("enforcer stop: removing container: %w", err)
		}
	} else {
		if err := sidecar.StopSidecar(ctx, cli, handle); err != nil {
			return fmt.Errorf("enforcer stop: %w", err)
		}
	}

	_, _ = fmt.Fprintln(out, "ac-enforcer stopped")
	return nil
}

func runEnforcerStatus(cmd *cobra.Command) error {
	ctx := cmd.Context()
	out := cmd.OutOrStdout()

	cli, err := newDockerClient()
	if err != nil {
		return fmt.Errorf("enforcer status: creating docker client: %w", err)
	}

	result, err := cli.ContainerInspect(ctx, sidecar.ContainerName, client.ContainerInspectOptions{})
	if err != nil {
		_, _ = fmt.Fprintln(out, "ac-enforcer is not running")
		return nil
	}

	info := result.Container
	state := info.State

	_, _ = fmt.Fprintf(out, "Container:  %s\n", shortID(info.ID))
	_, _ = fmt.Fprintf(out, "Status:     %s\n", state.Status)

	// Show port bindings from host config.
	if info.HostConfig != nil {
		for port, bindings := range info.HostConfig.PortBindings {
			for _, b := range bindings {
				_, _ = fmt.Fprintf(out, "Port:       %s -> %s\n", port, b.HostPort)
			}
		}
	}

	// Show uptime if running.
	if state.Running {
		startedAt, err := time.Parse(time.RFC3339Nano, state.StartedAt)
		if err == nil {
			uptime := time.Since(startedAt).Truncate(time.Second)
			_, _ = fmt.Fprintf(out, "Uptime:     %s\n", uptime)
		}
	}

	// Probe gRPC health if the container is running.
	if state.Running {
		port := enforcerPortFromInspect(info)
		target := fmt.Sprintf("127.0.0.1:%d", port)
		healthy := enforcement.ProbeEnforcerHealth(target)
		if healthy {
			_, _ = fmt.Fprintln(out, "Health:     SERVING")
		} else {
			_, _ = fmt.Fprintln(out, "Health:     UNHEALTHY")
		}
	}

	return nil
}

// enforcerPortFromInspect extracts the host port from the container's port bindings.
// Falls back to DefaultPort if no binding is found.
func enforcerPortFromInspect(info container.InspectResponse) int {
	if info.HostConfig != nil {
		for _, bindings := range info.HostConfig.PortBindings {
			for _, b := range bindings {
				if b.HostPort != "" {
					var port int
					if _, err := fmt.Sscanf(b.HostPort, "%d", &port); err == nil {
						return port
					}
				}
			}
		}
	}
	return sidecar.DefaultPort
}
