package sbom

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// SyftGenerator shells out to the syft CLI to produce CycloneDX SBOMs
// from container images.
type SyftGenerator struct {
	runner commandRunner
}

// NewSyftGenerator returns a Generator backed by the syft CLI.
func NewSyftGenerator() *SyftGenerator {
	return &SyftGenerator{runner: defaultRunner}
}

func (g *SyftGenerator) Name() string { return "syft" }

func (g *SyftGenerator) Available(ctx context.Context) bool {
	cmd := g.runner(ctx, "syft", "version")
	return cmd.Run() == nil
}

func (g *SyftGenerator) Generate(ctx context.Context, target string) (*BOM, error) {
	var stdout, stderr bytes.Buffer
	cmd := g.runner(ctx, "syft", target, "-o", "cyclonedx-json")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("syft exited %d: %s", exitErr.ExitCode(), stderr.String())
		}
		return nil, fmt.Errorf("running syft: %w", err)
	}

	return newBOM(stdout.Bytes())
}
