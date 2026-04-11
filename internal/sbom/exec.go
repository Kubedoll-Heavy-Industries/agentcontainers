package sbom

import (
	"context"
	"os/exec"
)

// commandRunner abstracts exec.CommandContext for testing.
type commandRunner func(ctx context.Context, name string, args ...string) *exec.Cmd

// defaultRunner uses the real exec.CommandContext.
var defaultRunner commandRunner = exec.CommandContext
