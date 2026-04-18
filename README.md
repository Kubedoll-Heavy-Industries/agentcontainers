# agentcontainers

**Immutable, reproducible, least-privilege runtime environments for AI agents.**

`agentcontainers` extends the [devcontainer.json](https://containers.dev/) specification to add security policy, supply chain verification, and human-in-the-loop permission approval for persistent AI agents (Claude Code, Codex CLI, Copilot Workspace, and similar tools).

> "AI agents are threatening to break the blood-brain barrier between the application layer and the OS layer."
> — Meredith Whittaker, President of Signal, SXSW 2025

---

## Why

Persistent AI agents require broad, long-lived system permissions. They read and write files, execute shell commands, make network requests, and consume credentials — often with the same ambient authority as the user who launched them. This is the equivalent of running every application as root on a shared machine with no network policy and no syscall filtering.

`agentcontainers` applies the lessons of a decade of container security to the agent problem:

| Threat | Mechanism |
|--------|-----------|
| Unapproved binary execution | Default-deny approval broker + eBPF enforcer |
| Argument injection / subshell escapes | Six-layer defense-in-depth (AST → seccomp → eBPF → AppArmor → Falco) |
| File access outside declared paths | Read-only root FS, explicit bind mounts |
| Network exfiltration | cgroup-scoped BPF connect4/sendmsg hooks |
| Credential theft | Secrets injected via tmpfs at `/run/secrets`; never in env vars |
| Supply chain attacks on tools/skills | OCI-packaged, Sigstore-signed, SBOM-attested, digest-pinned |
| Capability escalation without approval | Human-in-the-loop approval with capability diff |

---

## Status

**Pre-Alpha.** M0–M4 are shipped; M5 (ecosystem) is in planning. The build and tests pass. The API and schema are not yet stable.

| Milestone | Status | What shipped |
|-----------|--------|-------------|
| M0: Foundation | Shipped | `agentcontainer init/run/exec/ps/stop/logs/save/audit`, schema, Docker runtime, approval broker, Rust eBPF enforcer |
| M1: Verify | Shipped | `agentcontainer lock/verify/shim/sbom/component`, lockfile, OCI digest pinning, WASM tool hosting |
| M2: Sandbox | Shipped | Docker Sandbox VM backend, in-VM enforcement, compose-in-sandbox, multi-arch enforcer image |
| M3: Attest | Shipped | `agentcontainer sign`, Sigstore integration, SLSA provenance, drift threshold enforcement, offline verification |
| M4: Enterprise | Mostly complete | Org policy as OCI layer, secrets (Vault/Infisical/1Password/OIDC), per-MCP LSM credential enforcement |
| M5: Ecosystem | Planning | VS Code extension, Firecracker backend, Linux K8s, MCP registry integration |

---

## Quick Start

### Prerequisites

- Go 1.23+
- Docker Desktop (macOS) or Docker Engine (Linux)
- [mise](https://mise.jdx.dev/) for task running
- `cosign` (optional, for signature verification)

### Install

```bash
git clone https://github.com/Kubedoll-Heavy-Industries/agentcontainers
cd agentcontainers
mise install
mise run build       # builds to tmp/agentcontainer
```

Or install directly:

```bash
go install github.com/Kubedoll-Heavy-Industries/agentcontainers/cmd/agentcontainer@latest
```

### Initialize an agent container

```bash
# In your project directory
agentcontainer init

# This generates agentcontainer.json. If a devcontainer.json already exists,
# it is used as the base and extended with agent-specific defaults.
```

### Pin dependencies

```bash
agentcontainer lock    # resolves all OCI references to digests and writes agentcontainer-lock.json
agentcontainer verify  # verifies lockfile coverage and optionally checks signatures
```

### Run an agent

```bash
agentcontainer run     # starts the container + enforcer sidecar
agentcontainer exec -- claude   # executes inside the container with approval gating
```

---

## agentcontainer.json

Any valid `devcontainer.json` is a valid `agentcontainer.json`. The `agent` key adds capabilities, policy, secrets, and provenance configuration:

```jsonc
{
  "image": "ghcr.io/my-org/my-agent:latest",
  "agent": {
    "capabilities": {
      "network": {
        "egress": {
          "allowedDomains": ["api.github.com", "registry.npmjs.org"]
        }
      },
      "filesystem": {
        "readOnlyPaths": ["/workspace"],
        "writablePaths": ["/workspace/.cache"]
      },
      "tools": {
        "allowedBinaries": ["git", "npm", "node"],
        "requireApproval": true
      }
    },
    "policy": {
      "source": "oci://ghcr.io/my-org/policy:latest"
    },
    "secrets": {
      "GITHUB_TOKEN": "vault://vault.corp/secret/github#token",
      "NPM_TOKEN":    "op://Engineering/npm/token"
    }
  }
}
```

Full schema reference: [SPEC.md](./SPEC.md)

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Host (trusted)                                     │
│                                                     │
│  agentcontainer CLI ─────────────────────────────  │
│     │                                               │
│     ▼                                               │
│  Agentcontainer Runtime                             │
│     ├── Policy engine (config → ContainerPolicy)    │
│     ├── Approval broker (human-in-the-loop gating)  │
│     ├── Secrets manager (OIDC / Vault / 1Password)  │
│     └── OCI verifier (Sigstore / lockfile)          │
│     │                                               │
│     ▼           gRPC                                │
│  ┌──────────────────────────────────────────────┐  │
│  │  Isolated OCI Container (UNTRUSTED)          │  │
│  │    └── Agent process (Claude Code, etc.)     │  │◄──── Developer / IDE
│  └──────────────────────────────────────────────┘  │
│     │                                               │
│     ▼           gRPC                                │
│  ac-enforcer sidecar (Rust + Aya eBPF)             │
│     ├── cgroup/connect4/sendmsg BPF hooks           │
│     ├── LSM file_open hook (credential gating)      │
│     └── WASM Component tool host                   │
└─────────────────────────────────────────────────────┘
```

Enforcement is **fail-closed**: if the enforcer sidecar is unavailable, the container does not start.

For full architecture details, threat model, and design decisions: [SPEC.md](./SPEC.md)

---

## Development

```bash
mise run build          # build binary to tmp/agentcontainer
mise run test           # go test -race ./...
mise run test:cover     # tests with coverage report
mise run lint           # golangci-lint
mise run dev            # live reload with air

# Before declaring work complete:
go build ./... && go vet ./... && go test -race ./...
```

Repository layout:

| Path | What's there |
|------|-------------|
| `cmd/agentcontainer/` | Binary entry point |
| `internal/cli/` | Cobra command definitions, one file per command |
| `internal/config/` | Schema types, JSONC parser, validator |
| `internal/container/` | Runtime backends (Docker, Compose, Sandbox) |
| `internal/enforcement/` | gRPC strategy, policy translation |
| `internal/signing/` | Sigstore/cosign integration, SLSA provenance |
| `internal/oci/` | OCI Distribution Spec client, push/pull |
| `internal/orgpolicy/` | Org policy extraction, merge, comparison |
| `internal/secrets/` | Secret provider implementations |
| `enforcer/` | Rust: ac-ebpf (Aya BPF), ac-enforcer (Tokio gRPC) |
| `SPEC.md` | Full specification (~1600 lines) |
| `ROADMAP.md` | Milestone plan with status |
| `prd/` | Per-feature PRDs |

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Security

See [SECURITY.md](./SECURITY.md) for the vulnerability reporting policy and threat model.

## License

Apache 2.0. See [LICENSE](./LICENSE).
