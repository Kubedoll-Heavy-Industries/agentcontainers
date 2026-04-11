---
title: Quickstart
description: Install agentcontainers and run your first agent container.
---

## Prerequisites

- Docker Desktop 4.x or Docker Engine 24+
- Go 1.23+ (if building from source)

## Install

```bash
# From source
go install github.com/Kubedoll-Heavy-Industries/agentcontainers/cmd/ac@latest

# Or build from this repo
git clone https://github.com/Kubedoll-Heavy-Industries/agentcontainers.git
cd agentcontainers
go build -o ac ./cmd/ac
```

## Create a config

```bash
ac init
```

This creates an `agentcontainer.json` in your workspace:

```jsonc
{
  "name": "my-agent",
  "image": "node:22",
  "agent": {
    "capabilities": {
      "network": {
        "allow": ["api.github.com:443"]
      },
      "filesystem": {
        "read": ["/workspace/**"],
        "write": ["/workspace/**"]
      },
      "shell": {
        "allow": ["git", "npm", "node"]
      }
    }
  }
}
```

## Run

```bash
ac run
```

This builds or pulls the image, starts the container with hardened security defaults, and attaches the BPF enforcer sidecar.

## Exec into the container

```bash
ac exec my-agent -- bash
```

## Stop

```bash
ac stop my-agent
```

## Next steps

- [Configuration reference](/getting-started/configuration/) for the full `agentcontainer.json` schema
- [Secrets Management](/guides/secrets/) for credential injection
- [Organization Policy](/guides/org-policy/) for enterprise-wide constraints
