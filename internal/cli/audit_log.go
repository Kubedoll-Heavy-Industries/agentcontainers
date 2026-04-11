package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/audit"
)

func newAuditListCmd() *cobra.Command {
	var dir string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all session audit logs",
		Long: `List all session audit logs showing session ID, entry count,
and time range for each log file.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuditList(cmd.OutOrStdout(), dir)
		},
	}

	cmd.Flags().StringVar(&dir, "dir", "", "Audit log directory (default: ~/.ac/audit/)")
	return cmd
}

func runAuditList(out io.Writer, dir string) error {
	logs, err := audit.ListLogs(dir)
	if err != nil {
		return fmt.Errorf("audit list: %w", err)
	}

	if len(logs) == 0 {
		_, _ = fmt.Fprintln(out, "No audit logs found.")
		return nil
	}

	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("audit list: %w", err)
		}
		dir = filepath.Join(home, ".ac", "audit")
	}

	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(w, "SESSION\tENTRIES\tFIRST\tLAST")
	for _, name := range logs {
		sessionID := strings.TrimSuffix(name, ".jsonl")
		path := filepath.Join(dir, name)

		entries, err := audit.ReadLog(path)
		if err != nil {
			_, _ = fmt.Fprintf(w, "%s\t(error)\t-\t-\n", sessionID)
			continue
		}

		count := len(entries)
		first := "-"
		last := "-"
		if count > 0 {
			first = entries[0].Timestamp.Format(time.RFC3339)
			last = entries[count-1].Timestamp.Format(time.RFC3339)
		}
		_, _ = fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", sessionID, count, first, last)
	}
	return w.Flush()
}

func newAuditShowCmd() *cobra.Command {
	var dir string

	cmd := &cobra.Command{
		Use:   "show <session-id>",
		Short: "Show entries from a session audit log",
		Long: `Print all entries from the specified session audit log in
a human-readable tabular format.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuditShow(cmd.OutOrStdout(), dir, args[0])
		},
	}

	cmd.Flags().StringVar(&dir, "dir", "", "Audit log directory (default: ~/.ac/audit/)")
	return cmd
}

func runAuditShow(out io.Writer, dir, sessionID string) error {
	path, err := resolveAuditPath(dir, sessionID)
	if err != nil {
		return fmt.Errorf("audit show: %w", err)
	}

	entries, err := audit.ReadLog(path)
	if err != nil {
		return fmt.Errorf("audit show: %w", err)
	}

	if len(entries) == 0 {
		_, _ = fmt.Fprintln(out, "No entries in log.")
		return nil
	}

	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(w, "SEQ\tTIME\tEVENT\tACTOR\tVERDICT\tCOMMAND\tRESOURCE")
	for _, e := range entries {
		_, _ = fmt.Fprintf(w, "%d\t%s\t%s\t%s/%s\t%s\t%s\t%s\n",
			e.Sequence,
			e.Timestamp.Format("15:04:05.000"),
			e.EventType,
			e.Actor.Type, e.Actor.Name,
			verdictOrDash(e.Verdict),
			stringOrDash(e.Command),
			stringOrDash(e.Resource),
		)
	}
	return w.Flush()
}

func newAuditVerifyCmd() *cobra.Command {
	var dir string

	cmd := &cobra.Command{
		Use:   "verify <session-id>",
		Short: "Verify hash chain integrity of a session audit log",
		Long: `Verify that the hash chain in the specified session audit log
is intact. Reports the result and exits with non-zero status on failure.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuditVerify(cmd.OutOrStdout(), dir, args[0])
		},
	}

	cmd.Flags().StringVar(&dir, "dir", "", "Audit log directory (default: ~/.ac/audit/)")
	return cmd
}

func runAuditVerify(out io.Writer, dir, sessionID string) error {
	path, err := resolveAuditPath(dir, sessionID)
	if err != nil {
		return fmt.Errorf("audit verify: %w", err)
	}

	entries, err := audit.ReadLog(path)
	if err != nil {
		return fmt.Errorf("audit verify: %w", err)
	}

	if err := audit.ValidateChain(entries); err != nil {
		_, _ = fmt.Fprintf(out, "FAIL: %s\n", err)
		return fmt.Errorf("audit verify: chain integrity check failed")
	}

	_, _ = fmt.Fprintf(out, "OK: %d entries, chain intact.\n", len(entries))
	return nil
}

func newAuditExportCmd() *cobra.Command {
	var dir string

	cmd := &cobra.Command{
		Use:   "export <session-id>",
		Short: "Export raw JSONL audit log for SIEM integration",
		Long: `Output the raw JSONL content of a session audit log to stdout.
Useful for piping to SIEM systems or external analysis tools.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuditExport(cmd.OutOrStdout(), dir, args[0])
		},
	}

	cmd.Flags().StringVar(&dir, "dir", "", "Audit log directory (default: ~/.ac/audit/)")
	return cmd
}

func runAuditExport(out io.Writer, dir, sessionID string) error {
	path, err := resolveAuditPath(dir, sessionID)
	if err != nil {
		return fmt.Errorf("audit export: %w", err)
	}

	entries, err := audit.ReadLog(path)
	if err != nil {
		return fmt.Errorf("audit export: %w", err)
	}

	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("audit export: %w", err)
		}
		_, _ = fmt.Fprintln(out, string(line))
	}
	return nil
}

// resolveAuditPath resolves an audit log file path from dir and session ID.
func resolveAuditPath(dir, sessionID string) (string, error) {
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".ac", "audit")
	}
	return filepath.Join(dir, sessionID+".jsonl"), nil
}

func verdictOrDash(v audit.Verdict) string {
	if v == "" {
		return "-"
	}
	return string(v)
}

func stringOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
