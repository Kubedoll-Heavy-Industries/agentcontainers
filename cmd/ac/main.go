// Package main provides the entry point for the ac CLI.
package main

import (
	"fmt"
	"os"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/cli"
)

// Build information injected by goreleaser via ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := cli.Execute(version, commit, date); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
