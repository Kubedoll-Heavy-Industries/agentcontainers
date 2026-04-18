package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/signing"
)

func newAttestCmd() *cobra.Command {
	var (
		expectedWorkflow   string
		expectedSourceRepo string
		minLevel           int
		certIssuer         string
		outputJSON         bool
	)

	cmd := &cobra.Command{
		Use:   "attest <oci-reference>",
		Short: "Verify SLSA provenance on an OCI artifact",
		Long: `Verify SLSA provenance attestation on an OCI artifact.

This command checks that the artifact was built by a trusted CI/CD system
with verifiable build provenance. It validates:

  - The artifact has a SLSA provenance attestation
  - The attestation was produced by the expected GitHub Actions workflow
  - The SLSA build level meets the minimum requirement
  - The source repository matches expectations

Examples:
  agentcontainer attest ghcr.io/org/image@sha256:abc123...
  agentcontainer attest --min-level 3 ghcr.io/org/image@sha256:abc123...
  agentcontainer attest --workflow docker.yml --source-repo org/repo ghcr.io/org/image:latest
  agentcontainer attest --json ghcr.io/org/image@sha256:abc123...`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if minLevel < 1 || minLevel > 4 {
				return fmt.Errorf("attest: --min-level must be between 1 and 4, got %d", minLevel)
			}
			return runAttest(cmd, args[0], attestOptions{
				ExpectedWorkflow:   expectedWorkflow,
				ExpectedSourceRepo: expectedSourceRepo,
				MinLevel:           signing.SLSALevel(minLevel),
				CertIssuer:         certIssuer,
				OutputJSON:         outputJSON,
			}, nil)
		},
	}

	cmd.Flags().StringVar(&expectedWorkflow, "workflow", "",
		"Expected GitHub Actions workflow URI substring (e.g. 'docker.yml')")
	cmd.Flags().StringVar(&expectedSourceRepo, "source-repo", "",
		"Expected source repository (e.g. 'org/repo')")
	cmd.Flags().IntVar(&minLevel, "min-level", 1,
		"Minimum acceptable SLSA build level (1-4)")
	cmd.Flags().StringVar(&certIssuer, "cert-issuer", "",
		"Expected OIDC certificate issuer (e.g. 'https://token.actions.githubusercontent.com')")
	cmd.Flags().BoolVar(&outputJSON, "json", false,
		"Output provenance summary as JSON")

	return cmd
}

// attestOptions holds the parsed options for the attest command.
type attestOptions struct {
	ExpectedWorkflow   string
	ExpectedSourceRepo string
	MinLevel           signing.SLSALevel
	CertIssuer         string
	OutputJSON         bool
}

// runAttest is the testable implementation of the attest command.
func runAttest(cmd *cobra.Command, ref string, opts attestOptions, verifier signing.ProvenanceVerifier) error {
	out := cmd.OutOrStdout()
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if verifier == nil {
		verifier = signing.NewCosignProvenanceVerifier()
	}

	verifyOpts := signing.ProvenanceVerifyOptions{
		ExpectedWorkflow:   opts.ExpectedWorkflow,
		ExpectedSourceRepo: opts.ExpectedSourceRepo,
		MinSLSALevel:       opts.MinLevel,
		CertIssuer:         opts.CertIssuer,
	}

	if !opts.OutputJSON {
		_, _ = fmt.Fprintf(out, "Verifying SLSA provenance for %s...\n", ref)
	}

	result, err := verifier.VerifyProvenance(ctx, ref, verifyOpts)
	if err != nil {
		return fmt.Errorf("attest: %w", err)
	}

	if opts.OutputJSON {
		return printAttestJSON(out, result)
	}

	return printAttestSummary(out, result)
}

// printAttestSummary prints a human-readable provenance summary.
func printAttestSummary(out io.Writer, result *signing.ProvenanceVerifyResult) error {
	_, _ = fmt.Fprintf(out, "Provenance verified.\n\n")
	_, _ = fmt.Fprintf(out, "  SLSA Level:    %s\n", signing.SLSALevelString(result.SLSALevel))
	_, _ = fmt.Fprintf(out, "  Builder:       %s\n", result.BuilderID)

	if result.SourceRepo != "" {
		_, _ = fmt.Fprintf(out, "  Source:        %s\n", result.SourceRepo)
	}
	if result.SourceCommit != "" {
		_, _ = fmt.Fprintf(out, "  Commit:        %s\n", result.SourceCommit)
	}
	if result.BuildTimestamp != nil {
		_, _ = fmt.Fprintf(out, "  Built at:      %s\n", result.BuildTimestamp.Format("2006-01-02T15:04:05Z"))
	}

	return nil
}

// attestJSONResult is the JSON output schema for the attest command.
type attestJSONResult struct {
	Verified       bool   `json:"verified"`
	SLSALevel      int    `json:"slsa_level"`
	SLSALevelLabel string `json:"slsa_level_label"`
	BuilderID      string `json:"builder_id"`
	SourceRepo     string `json:"source_repo,omitempty"`
	SourceCommit   string `json:"source_commit,omitempty"`
	BuildTimestamp string `json:"build_timestamp,omitempty"`
}

// printAttestJSON prints the provenance summary as JSON.
func printAttestJSON(out io.Writer, result *signing.ProvenanceVerifyResult) error {
	jr := attestJSONResult{
		Verified:       result.Verified,
		SLSALevel:      int(result.SLSALevel),
		SLSALevelLabel: signing.SLSALevelString(result.SLSALevel),
		BuilderID:      result.BuilderID,
		SourceRepo:     result.SourceRepo,
		SourceCommit:   result.SourceCommit,
	}

	if result.BuildTimestamp != nil {
		jr.BuildTimestamp = result.BuildTimestamp.Format("2006-01-02T15:04:05Z")
	}

	data, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		return fmt.Errorf("attest: marshal JSON: %w", err)
	}
	data = append(data, '\n')
	_, _ = out.Write(data)
	return nil
}
