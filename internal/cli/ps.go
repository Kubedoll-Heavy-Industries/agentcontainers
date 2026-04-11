package cli

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
)

func newPsCmd() *cobra.Command {
	var (
		runtime string
		all     bool
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "ps",
		Short: "List active agent container sessions",
		Long: `List containers managed by agentcontainers. By default only running
sessions are shown. Use --all to include stopped sessions.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPs(cmd, runtime, all, jsonOut)
		},
	}

	cmd.Flags().StringVar(&runtime, "runtime", "docker", "Container runtime backend (auto|docker|compose|sandbox)")
	cmd.Flags().BoolVarP(&all, "all", "a", false, "Include stopped sessions")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output machine-readable JSON")

	return cmd
}

// psEntry is the JSON-serialisable representation of a session for --json output.
type psEntry struct {
	ContainerID string `json:"container_id"`
	Name        string `json:"name"`
	Image       string `json:"image"`
	Status      string `json:"status"`
	Created     string `json:"created"`
}

func runPs(cmd *cobra.Command, runtimeFlag string, all bool, jsonOut bool) error {
	rt, err := newRuntime(runtimeFlag, logger, enforcement.LevelNone)
	if err != nil {
		return fmt.Errorf("ps: %w", err)
	}

	sessions, err := rt.List(cmd.Context(), all)
	if err != nil {
		return fmt.Errorf("ps: %w", err)
	}

	if jsonOut {
		entries := make([]psEntry, 0, len(sessions))
		for _, s := range sessions {
			entries = append(entries, psEntry{
				ContainerID: shortID(s.ContainerID),
				Name:        s.Name,
				Image:       s.Image,
				Status:      s.Status,
				Created:     s.CreatedAt.Format(time.RFC3339),
			})
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	}

	if len(sessions) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "No active sessions.")
		return nil
	}

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(w, "CONTAINER\tNAME\tIMAGE\tSTATUS\tCREATED")
	for _, s := range sessions {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			shortID(s.ContainerID),
			s.Name,
			s.Image,
			s.Status,
			relativeTime(s.CreatedAt),
		)
	}
	return w.Flush()
}

// shortID returns the first 12 characters of a container ID, matching Docker's
// default short ID format.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// relativeTime formats a timestamp as a human-readable relative duration
// (e.g. "2 hours ago", "3 days ago").
func relativeTime(t time.Time) string {
	d := time.Since(t)

	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		m := int(d.Minutes())
		if m == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", m)
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", h)
	default:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}
}
