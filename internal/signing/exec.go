package signing

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// cmdRunner abstracts command execution for testability.
type cmdRunner interface {
	// Run executes a command with the given name, arguments, and environment
	// variables. Returns combined stdout and stderr output.
	Run(ctx context.Context, name string, args []string, env []string) ([]byte, error)
}

// execRunner is the real implementation that uses os/exec.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args []string, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(env) > 0 {
		cmd.Env = append(cmd.Environ(), env...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		detail := stderr.String()
		if detail == "" {
			detail = stdout.String()
		}
		return nil, fmt.Errorf("%s failed: %w: %s", name, err, detail)
	}
	return stdout.Bytes(), nil
}

// lookPath checks whether a binary is on PATH. Abstracted for testing.
var lookPath = exec.LookPath
