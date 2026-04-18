---
title: Contributing
description: How to contribute to agentcontainers.
---

## Development setup

```bash
git clone https://github.com/Kubedoll-Heavy-Industries/agentcontainers.git
cd agentcontainers
mise install    # Install toolchain
mise run build  # Build to tmp/agentcontainer
mise run test   # Run unit tests
```

## Build and test

```bash
go build ./...           # Build all packages
go vet ./...             # Static analysis
go test -race ./...      # Unit tests with race detector
mise run lint            # golangci-lint
```

Always run `go build ./... && go vet ./... && go test -race ./...` before submitting.

## Code conventions

- Go CLI using Cobra for subcommands
- Config format is JSONC parsed via `tailscale/hujson`
- Error wrapping: `fmt.Errorf("context: %w", err)`
- Table-driven tests with `t.Run()` subtests
- Constructor pattern: `NewXxx(opts ...XxxOption)` with functional options

## Adding a CLI command

1. Create `internal/cli/<command>.go` with `newXxxCmd()` and `runXxx()`
2. Add to `cmd.AddCommand()` in `internal/cli/root.go`
3. Create `internal/cli/<command>_test.go`
