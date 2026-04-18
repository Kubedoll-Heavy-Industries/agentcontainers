package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcerapi"
)

const (
	defaultEnforcerAddr = "127.0.0.1:50051"
)

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Display enforcement events from the agentcontainer-enforcer sidecar",
		Long: `Query and stream enforcement audit events from the agentcontainer-enforcer
gRPC sidecar. Events include network, filesystem, process, and credential
policy decisions with allow/block verdicts.`,
	}

	cmd.AddCommand(
		newAuditEventsCmd(),
		newAuditSummaryCmd(),
		newAuditListCmd(),
		newAuditShowCmd(),
		newAuditVerifyCmd(),
		newAuditExportCmd(),
	)

	return cmd
}

func newAuditEventsCmd() *cobra.Command {
	var (
		addr        string
		containerID string
		eventType   string
		jsonOut     bool
		follow      bool
	)

	cmd := &cobra.Command{
		Use:   "events",
		Short: "Stream enforcement events from the agentcontainer-enforcer sidecar",
		Long: `Stream enforcement events in real time from the agentcontainer-enforcer gRPC
sidecar. Events are displayed as they occur, showing policy verdicts
for network, filesystem, process, and credential operations.

Use --follow (-f) for continuous streaming (like tail -f). Without
--follow, events are collected for a short window and displayed.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuditEvents(cmd, addr, containerID, eventType, jsonOut, follow)
		},
	}

	cmd.Flags().StringVar(&addr, "addr", defaultEnforcerAddr, "agentcontainer-enforcer gRPC address")
	cmd.Flags().StringVar(&containerID, "container", "", "Filter by container ID")
	cmd.Flags().StringVar(&eventType, "type", "", "Filter by event type (network|filesystem|process|credential)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output events as JSON")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Continuously stream events")

	return cmd
}

func newAuditSummaryCmd() *cobra.Command {
	var (
		addr        string
		containerID string
	)

	cmd := &cobra.Command{
		Use:   "summary",
		Short: "Show enforcement event summary from the agentcontainer-enforcer sidecar",
		Long: `Display aggregated enforcement statistics from the agentcontainer-enforcer
gRPC sidecar. Shows counts of allowed and blocked events grouped by
enforcement domain (network, filesystem, process).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuditSummary(cmd, addr, containerID)
		},
	}

	cmd.Flags().StringVar(&addr, "addr", defaultEnforcerAddr, "agentcontainer-enforcer gRPC address")
	cmd.Flags().StringVar(&containerID, "container", "", "Filter by container ID")

	return cmd
}

// auditEvent is the JSON-serialisable representation of an enforcement event.
type auditEvent struct {
	Timestamp   string            `json:"timestamp"`
	ContainerID string            `json:"container_id"`
	Domain      string            `json:"domain"`
	Verdict     string            `json:"verdict"`
	PID         uint32            `json:"pid"`
	Comm        string            `json:"comm"`
	Details     map[string]string `json:"details,omitempty"`
}

// newEnforcerGRPCClient creates a gRPC connection and enforcer client.
// Separated for testability.
var newEnforcerGRPCClient = func(addr string) (enforcerapi.EnforcerClient, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to enforcer at %s: %w", addr, err)
	}
	return enforcerapi.NewEnforcerClient(conn), conn, nil
}

func runAuditEvents(cmd *cobra.Command, addr, containerID, eventType string, jsonOut, follow bool) error {
	ctx := cmd.Context()
	out := cmd.OutOrStdout()

	client, conn, err := newEnforcerGRPCClient(addr)
	if err != nil {
		return fmt.Errorf("audit events: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	stream, err := client.StreamEvents(ctx, &enforcerapi.StreamEventsRequest{
		ContainerId: containerID,
	})
	if err != nil {
		return fmt.Errorf("audit events: starting event stream: %w", err)
	}

	if !jsonOut && follow {
		_, _ = fmt.Fprintln(out, "Streaming enforcement events (press Ctrl-C to stop)...")
	}

	// For non-follow mode, collect events for a bounded duration.
	if !follow {
		collectCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return collectAndDisplayEvents(collectCtx, stream, out, eventType, jsonOut)
	}

	// Follow mode: stream indefinitely.
	return streamEvents(ctx, stream, out, eventType, jsonOut)
}

// collectAndDisplayEvents receives events until the context expires, then displays them.
func collectAndDisplayEvents(ctx context.Context, stream grpc.ServerStreamingClient[enforcerapi.EnforcementEvent], out io.Writer, eventType string, jsonOut bool) error {
	var events []*enforcerapi.EnforcementEvent

	for {
		select {
		case <-ctx.Done():
			// Timeout reached, display collected events.
			return displayCollectedEvents(events, out, eventType, jsonOut)
		default:
		}

		ev, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			// If we hit the context deadline, just display what we have.
			if ctx.Err() != nil {
				break
			}
			return fmt.Errorf("audit events: receiving event: %w", err)
		}

		if eventType != "" && ev.GetDomain() != eventType {
			continue
		}
		events = append(events, ev)
	}

	return displayCollectedEvents(events, out, eventType, jsonOut)
}

func displayCollectedEvents(events []*enforcerapi.EnforcementEvent, out io.Writer, eventType string, jsonOut bool) error {
	if jsonOut {
		entries := make([]auditEvent, 0, len(events))
		for _, ev := range events {
			entries = append(entries, protoEventToAuditEvent(ev))
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	}

	if len(events) == 0 {
		_, _ = fmt.Fprintln(out, "No enforcement events received.")
		return nil
	}

	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(w, "TIMESTAMP\tCONTAINER\tDOMAIN\tVERDICT\tPID\tCOMM\tDETAILS")
	for _, ev := range events {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			formatTimestamp(ev.GetTimestampNs()),
			shortID(ev.GetContainerId()),
			ev.GetDomain(),
			ev.GetVerdict(),
			ev.GetPid(),
			ev.GetComm(),
			formatDetails(ev.GetDetails()),
		)
	}
	return w.Flush()
}

// streamEvents streams events continuously until the context is cancelled.
func streamEvents(ctx context.Context, stream grpc.ServerStreamingClient[enforcerapi.EnforcementEvent], out io.Writer, eventType string, jsonOut bool) error {
	enc := json.NewEncoder(out)
	if !jsonOut {
		w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
		_, _ = fmt.Fprintln(w, "TIMESTAMP\tCONTAINER\tDOMAIN\tVERDICT\tPID\tCOMM\tDETAILS")
		_ = w.Flush()
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		ev, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("audit events: receiving event: %w", err)
		}

		if eventType != "" && ev.GetDomain() != eventType {
			continue
		}

		if jsonOut {
			ae := protoEventToAuditEvent(ev)
			if err := enc.Encode(ae); err != nil {
				return fmt.Errorf("audit events: encoding event: %w", err)
			}
		} else {
			_, _ = fmt.Fprintf(out, "%s   %s   %s   %s   %d   %s   %s\n",
				formatTimestamp(ev.GetTimestampNs()),
				shortID(ev.GetContainerId()),
				ev.GetDomain(),
				ev.GetVerdict(),
				ev.GetPid(),
				ev.GetComm(),
				formatDetails(ev.GetDetails()),
			)
		}
	}
}

func runAuditSummary(cmd *cobra.Command, addr, containerID string) error {
	ctx := cmd.Context()
	out := cmd.OutOrStdout()

	client, conn, err := newEnforcerGRPCClient(addr)
	if err != nil {
		return fmt.Errorf("audit summary: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	stats, err := client.GetStats(ctx, &enforcerapi.GetStatsRequest{
		ContainerId: containerID,
	})
	if err != nil {
		return fmt.Errorf("audit summary: getting stats: %w", err)
	}

	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(w, "DOMAIN\tALLOWED\tBLOCKED\tTOTAL")
	_, _ = fmt.Fprintf(w, "network\t%d\t%d\t%d\n",
		stats.GetNetworkAllowed(),
		stats.GetNetworkBlocked(),
		stats.GetNetworkAllowed()+stats.GetNetworkBlocked(),
	)
	_, _ = fmt.Fprintf(w, "filesystem\t%d\t%d\t%d\n",
		stats.GetFilesystemAllowed(),
		stats.GetFilesystemBlocked(),
		stats.GetFilesystemAllowed()+stats.GetFilesystemBlocked(),
	)
	_, _ = fmt.Fprintf(w, "process\t%d\t%d\t%d\n",
		stats.GetProcessAllowed(),
		stats.GetProcessBlocked(),
		stats.GetProcessAllowed()+stats.GetProcessBlocked(),
	)

	total := stats.GetNetworkAllowed() + stats.GetNetworkBlocked() +
		stats.GetFilesystemAllowed() + stats.GetFilesystemBlocked() +
		stats.GetProcessAllowed() + stats.GetProcessBlocked()
	totalAllowed := stats.GetNetworkAllowed() + stats.GetFilesystemAllowed() + stats.GetProcessAllowed()
	totalBlocked := stats.GetNetworkBlocked() + stats.GetFilesystemBlocked() + stats.GetProcessBlocked()

	_, _ = fmt.Fprintf(w, "TOTAL\t%d\t%d\t%d\n", totalAllowed, totalBlocked, total)

	return w.Flush()
}

// protoEventToAuditEvent converts a protobuf EnforcementEvent to an auditEvent.
func protoEventToAuditEvent(ev *enforcerapi.EnforcementEvent) auditEvent {
	return auditEvent{
		Timestamp:   formatTimestamp(ev.GetTimestampNs()),
		ContainerID: ev.GetContainerId(),
		Domain:      ev.GetDomain(),
		Verdict:     ev.GetVerdict(),
		PID:         ev.GetPid(),
		Comm:        ev.GetComm(),
		Details:     ev.GetDetails(),
	}
}

// formatTimestamp converts nanosecond-epoch to a human-readable timestamp.
func formatTimestamp(ns uint64) string {
	if ns == 0 {
		return "-"
	}
	t := time.Unix(0, int64(ns))
	return t.Format("15:04:05.000")
}

// formatDetails formats a details map as a compact key=value string.
func formatDetails(details map[string]string) string {
	if len(details) == 0 {
		return "-"
	}
	result := ""
	for k, v := range details {
		if result != "" {
			result += " "
		}
		result += k + "=" + v
	}
	return result
}
