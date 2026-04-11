package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/signing"
)

func newTUFCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tuf",
		Short: "Manage Sigstore TUF root metadata",
		Long: `Commands for managing Sigstore TUF (The Update Framework) root metadata.
TUF root metadata contains the Fulcio root CA certificate, Rekor public key,
and CT log public key needed for offline signature verification.`,
	}

	cmd.AddCommand(newTUFExportCmd())
	return cmd
}

func newTUFExportCmd() *cobra.Command {
	var outputDir string

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export Sigstore TUF root metadata for offline verification",
		Long: `Export Sigstore TUF root metadata to a directory for air-gapped environments.

This command:
1. Runs "cosign initialize" to ensure the local TUF root is fresh
2. Copies the TUF root directory tree to the specified output directory

The exported directory can then be transferred to an air-gapped system and
used with "ac verify --offline --trusted-root <dir>/root.json".`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTUFExport(cmd, outputDir)
		},
	}

	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "Target directory for TUF root export (required)")
	_ = cmd.MarkFlagRequired("output")

	return cmd
}

func runTUFExport(cmd *cobra.Command, outputDir string) error {
	out := cmd.OutOrStdout()
	ctx := cmd.Context()

	exporter := signing.NewTUFExporter()

	_, _ = fmt.Fprintf(out, "Refreshing TUF root via cosign initialize...\n")

	if err := exporter.Export(ctx, outputDir); err != nil {
		return fmt.Errorf("tuf export: %w", err)
	}

	// Validate the exported root.
	if err := signing.ValidateTUFRoot(outputDir); err != nil {
		return fmt.Errorf("tuf export: exported root validation failed: %w", err)
	}

	_, _ = fmt.Fprintf(out, "TUF root exported to %s\n", outputDir)
	_, _ = fmt.Fprintf(out, "Use with: ac verify --offline --trusted-root %s/root.json\n", outputDir)

	return nil
}
