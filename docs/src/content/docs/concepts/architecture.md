---
title: Architecture
description: The four-layer runtime model and how requests flow through the system.
---

agentcontainers uses a four-layer model to isolate AI agents while giving them controlled access to the tools and credentials they need.

## The four-layer model

```
Layer 1: User / IDE / CLI
           │
           ▼
Layer 2: agentcontainer Runtime (ac binary)
         ├── Policy Engine
         ├── Provenance Verifier
         ├── Secrets Manager
         ├── Permission Gateway (approval broker)
         └── Enforcer (gRPC → sidecar)
           │
           ▼
Layer 3: Isolated OCI Container
         ├── Dropped capabilities
         ├── seccomp profile
         ├── Read-only root filesystem
         └── tmpfs mounts at /run/secrets/
           │
           ▼
Layer 4: Agent + MCP Servers + Skills
         └── Running inside the container
```

### Layer 1: User interface

The user interacts through the `ac` CLI or an IDE extension. Commands like `ac run`, `ac exec`, and `ac stop` drive the lifecycle.

### Layer 2: agentcontainer Runtime

The runtime is the control plane. It:
- **Loads and validates** `agentcontainer.json` (JSONC, superset of devcontainer.json)
- **Resolves org policy** from OCI registries and merges with workspace config
- **Verifies provenance** (signatures, SBOM, SLSA attestations) via the lockfile
- **Resolves secrets** through pluggable providers (OIDC, Vault, 1Password, Infisical, env)
- **Injects secrets** into `/run/secrets/` via tmpfs, with per-tool scoping
- **Starts the enforcer sidecar** which applies BPF LSM hooks for kernel-level policy enforcement
- **Brokers approvals** for capability escalation (human-in-the-loop)

### Layer 3: Isolated container

The container runs with hardened defaults:
- All Linux capabilities dropped except those explicitly declared
- seccomp profile restricts syscalls
- Read-only root filesystem
- Network egress restricted to declared endpoints
- No access to host credential stores, SSH keys, or browser cookies

### Layer 4: Agent workload

The agent, its MCP servers, and skills run inside the container. They see only the capabilities, network endpoints, filesystem paths, and secrets declared in the config.

## How a request flows through the system

1. `ac run` loads `agentcontainer.json` and resolves the config chain
2. The policy engine merges org policy (deny wins)
3. The provenance verifier checks the lockfile against the registry
4. The Secrets Manager resolves all declared secrets via providers
5. The container starts with hardened security settings
6. The enforcer sidecar attaches BPF hooks to the container's cgroup
7. At runtime, every network connection, file open, and process exec is checked against policy
8. Capability violations are logged, blocked, or escalated per the policy config

## Container backends

### Docker (default)

Single-container isolation via Docker Engine API. Suitable for most use cases.

```bash
ac run                      # auto-detects Docker
ac run --runtime docker     # explicit
```

### Compose

Multi-container orchestration for MCP server sidecars. Uses Docker Compose SDK. Each MCP server runs in its own container with isolated secrets.

```bash
ac run --runtime compose
```

### Sandbox

Docker Sandbox microVMs for full agent isolation with a private Docker daemon. Uses gVisor for an additional isolation layer.

```bash
ac run --runtime sandbox
```

Runtime auto-detection: `--runtime auto` probes for Sandbox availability, falls back to Docker.

## The enforcer sidecar

The enforcer is a Rust binary (`ac-enforcer`) that runs as a sidecar container. It attaches Aya BPF programs to the agent container's cgroup and enforces policy at the kernel level:

- **Network**: `connect4`, `connect6`, `sendmsg4`, `sendmsg6` hooks gate all TCP and UDP egress
- **Filesystem**: LSM `file_open` hook with inode-level allow/deny lists
- **Process**: LSM `bprm_check_security` hook validates executed binaries
- **Credentials**: `SECRET_ACLS` map in the LSM `file_open` hook gates per-cgroup access to `/run/secrets/` files with TTL expiry

The enforcer communicates with the runtime via gRPC. If the enforcer is unreachable or fails to start, the session fails (fail-closed by default).

## Secret injection flow

```
agentcontainer.json          Provider backends
     │                            │
     ▼                            ▼
Secrets Manager ──────► Resolve via OIDC / Vault / 1Password / Infisical / env
     │
     ▼
Write to tmpfs (/run/secrets/<name>, mode 0400)
     │
     ▼
Mount into container (per-tool scoping via namespace isolation)
     │
     ▼
Enforcer registers SECRET_ACLS entries (inode, dev, cgroup → TTL, permissions)
     │
     ▼
BPF LSM file_open hook enforces access at kernel level
```

The container never contacts secret providers directly. The Secrets Manager on the host handles all resolution, injection, and TTL-based rotation.

## Policy resolution

Config resolution follows this order:

1. Workspace root `agentcontainer.json`
2. `.devcontainer/agentcontainer.json`
3. `.devcontainer/devcontainer.json` (default-deny if using devcontainer)
4. Remote org policy overlay (from OCI registry)

The org policy is the strictest layer. It can only restrict workspace permissions, never expand them. See the [Organization Policy guide](/guides/org-policy/) for details.

## What makes this different from a devcontainer

| Feature | devcontainer | agentcontainer |
|---|---|---|
| Config format | `devcontainer.json` | `agentcontainer.json` (strict superset) |
| Capabilities | Implicit allow-all | Declared capabilities, default-deny |
| Secrets | Environment variables | tmpfs injection, per-tool scoping, TTL rotation |
| Network | Unrestricted | Endpoint allowlist, BPF enforcement |
| Provenance | None | SLSA attestations, SBOM, Sigstore signing |
| Org policy | None | OCI-distributed policy overlays |
| Enforcement | Container isolation only | BPF LSM hooks, 6-layer defense-in-depth |
