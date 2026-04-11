package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/sbom"
)

func newSbomCmd() *cobra.Command {
	var (
		tool       string
		outputPath string
	)

	cmd := &cobra.Command{
		Use:   "sbom <image-or-path>",
		Short: "Generate an SBOM for a container image or source directory",
		Long: `Generate a CycloneDX SBOM for a container image (via syft) or a
source directory (via cdxgen). The output is written to stdout or a file.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSbom(cmd, args[0], tool, outputPath)
		},
	}

	cmd.Flags().StringVar(&tool, "tool", "syft", "SBOM generator tool: syft or cdxgen")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Write SBOM to file instead of stdout")

	return cmd
}

func runSbom(cmd *cobra.Command, target, tool, outputPath string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	var gen sbom.Generator
	switch tool {
	case "syft":
		gen = sbom.NewSyftGenerator()
	case "cdxgen":
		gen = sbom.NewCdxgenGenerator()
	default:
		return fmt.Errorf("sbom: unknown tool %q (use syft or cdxgen)", tool)
	}

	if !gen.Available(ctx) {
		return fmt.Errorf("sbom: %s is not installed or not in PATH", gen.Name())
	}

	bom, err := gen.Generate(ctx, target)
	if err != nil {
		return fmt.Errorf("sbom: %w", err)
	}

	if outputPath != "" {
		if err := os.WriteFile(outputPath, bom.Content, 0o644); err != nil {
			return fmt.Errorf("sbom: writing output: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "SBOM written to %s (%d components, digest %s)\n", outputPath, bom.Components, bom.Digest)
		return nil
	}

	_, err = cmd.OutOrStdout().Write(bom.Content)
	return err
}
