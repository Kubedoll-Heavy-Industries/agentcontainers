package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/container"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
)

func newGcCmd() *cobra.Command {
	var (
		runtime string
		dryRun  bool
		force   bool
		all     bool
	)

	cmd := &cobra.Command{
		Use:   "gc",
		Short: "Clean up stale agent containers",
		Long: `Remove stopped agent containers managed by agentcontainers.
By default only stopped containers are removed. Use --all to also
remove running containers. Use --dry-run to preview what would be
cleaned without making changes.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGc(cmd, runtime, dryRun, force, all)
		},
	}

	cmd.Flags().StringVar(&runtime, "runtime", "docker", "Container runtime backend (docker|compose)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be cleaned without removing anything")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompt")
	cmd.Flags().BoolVarP(&all, "all", "a", false, "Also remove running containers (default: only stopped)")

	return cmd
}

func runGc(cmd *cobra.Command, runtimeFlag string, dryRun, force, all bool) error {
	rt, err := newRuntime(runtimeFlag, logger, enforcement.LevelNone)
	if err != nil {
		return fmt.Errorf("gc: %w", err)
	}

	// List all containers (including stopped) so we can filter.
	// Runtime.List() implementations MUST filter to only agentcontainer-managed
	// containers (see runtime.go interface contract). DockerRuntime filters by
	// dev.agentcontainer/managed=true label. This defensive check verifies the
	// RuntimeType to guard against implementation bugs or future runtime backends.
	sessions, err := rt.List(cmd.Context(), true)
	if err != nil {
		return exitError{code: 3, err: fmt.Errorf("gc: listing containers: %w", err)}
	}

	// Separate into running and stopped, filtering for valid agentcontainer sessions.
	var targets []*container.Session
	for _, s := range sessions {
		// Defensive filter: verify this is a known agentcontainer runtime type.
		if !isAgentcontainerSession(s) {
			logger.Warn("skipping non-agentcontainer session in gc",
				zap.String("id", s.ContainerID),
				zap.String("name", s.Name),
				zap.String("runtime", string(s.RuntimeType)),
			)
			continue
		}

		if isRunning(s) && !all {
			continue
		}
		targets = append(targets, s)
	}

	out := cmd.OutOrStdout()

	if len(targets) == 0 {
		_, _ = fmt.Fprintln(out, "Nothing to clean up")
		return nil
	}

	// Display what will be cleaned.
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(w, "CONTAINER ID\tNAME\tSTATUS\tCREATED")
	for _, s := range targets {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			shortID(s.ContainerID),
			s.Name,
			s.Status,
			relativeTime(s.CreatedAt),
		)
	}
	_ = w.Flush()

	if dryRun {
		_, _ = fmt.Fprintf(out, "\nDry run: %d container(s) would be removed\n", len(targets))
		return nil
	}

	// Prompt for confirmation unless --force.
	if !force {
		_, _ = fmt.Fprintf(out, "\nRemove %d container(s)? [y/N] ", len(targets))
		confirmed, err := promptConfirm(cmd)
		if err != nil {
			return exitError{code: 3, err: fmt.Errorf("gc: reading confirmation: %w", err)}
		}
		if !confirmed {
			_, _ = fmt.Fprintln(out, "Cancelled")
			return nil
		}
	}

	// Remove targeted containers.
	var removed int
	var errs []string
	for _, s := range targets {
		if err := rt.Stop(cmd.Context(), s); err != nil {
			errs = append(errs, fmt.Sprintf("  %s: %v", shortID(s.ContainerID), err))
			continue
		}
		removed++
	}

	_, _ = fmt.Fprintf(out, "Removed %d container(s)\n", removed)

	if len(errs) > 0 {
		return exitError{
			code: 3,
			err:  fmt.Errorf("gc: failed to remove some containers:\n%s", strings.Join(errs, "\n")),
		}
	}

	return nil
}

// isRunning returns true if the session status indicates the container is
// currently running.
func isRunning(s *container.Session) bool {
	return strings.HasPrefix(strings.ToLower(s.Status), "running") ||
		strings.HasPrefix(strings.ToLower(s.Status), "up")
}

// isAgentcontainerSession returns true if the session was created by one of
// the known agentcontainer runtime backends. This defensive check protects
// against gc accidentally removing non-agentcontainer containers if a runtime
// implementation fails to filter correctly in List().
func isAgentcontainerSession(s *container.Session) bool {
	if s == nil {
		return false
	}
	switch s.RuntimeType {
	case container.RuntimeDocker, container.RuntimeCompose, container.RuntimeSandbox:
		return true
	default:
		return false
	}
}
