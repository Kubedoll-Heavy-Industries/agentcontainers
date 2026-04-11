package sbom

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// CdxgenGenerator shells out to the cdxgen CLI to produce CycloneDX SBOMs
// from source directories.
type CdxgenGenerator struct {
	runner commandRunner
}

// NewCdxgenGenerator returns a Generator backed by the cdxgen CLI.
func NewCdxgenGenerator() *CdxgenGenerator {
	return &CdxgenGenerator{runner: defaultRunner}
}

func (g *CdxgenGenerator) Name() string { return "cdxgen" }

func (g *CdxgenGenerator) Available(ctx context.Context) bool {
	cmd := g.runner(ctx, "cdxgen", "--version")
	return cmd.Run() == nil
}

func (g *CdxgenGenerator) Generate(ctx context.Context, target string) (*BOM, error) {
	var stdout, stderr bytes.Buffer
	cmd := g.runner(ctx, "cdxgen", "-o", "/dev/stdout", target)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("cdxgen exited %d: %s", exitErr.ExitCode(), stderr.String())
		}
		return nil, fmt.Errorf("running cdxgen: %w", err)
	}

	return newBOM(stdout.Bytes())
}
