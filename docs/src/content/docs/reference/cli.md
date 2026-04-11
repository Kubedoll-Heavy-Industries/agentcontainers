---
title: CLI Reference
description: All ac commands and their usage.
---

## Core commands

| Command | Description |
|---|---|
| `ac init` | Initialize an `agentcontainer.json` in the current workspace |
| `ac run` | Build/pull image and start the agent container |
| `ac exec <name> -- <cmd>` | Execute a command in a running container |
| `ac stop <name>` | Stop a running container |
| `ac build` | Build the container image |
| `ac ps` | List running agent containers |
| `ac logs <name>` | View container logs |
| `ac gc` | Garbage collect stopped containers and dangling images |

## Supply chain commands

| Command | Description |
|---|---|
| `ac lock` | Generate a lockfile pinning image digests, MCP servers, and org policy |
| `ac verify` | Verify the lockfile against the registry (signatures, SBOM, staleness) |
| `ac sign` | Sign OCI artifacts with Sigstore |
| `ac attest` | Create SLSA provenance attestations |
| `ac sbom` | Generate SBOM for the container image |
| `ac drift` | Check for semantic drift between locked and current state |

## Enforcement commands

| Command | Description |
|---|---|
| `ac enforcer start` | Start the BPF enforcer sidecar |
| `ac enforcer stop` | Stop the enforcer sidecar |
| `ac enforcer status` | Show enforcer status and enforcement stats |
| `ac enforcer diagnose` | Run diagnostics on enforcer connectivity and BPF programs |

## Audit commands

| Command | Description |
|---|---|
| `ac audit events` | Stream enforcement events in real time |
| `ac audit summary` | Show aggregated enforcement statistics |

## Policy commands

| Command | Description |
|---|---|
| `ac policy pull <ref>` | Fetch an org policy from an OCI registry |
| `ac policy push <file> <ref>` | Push a local policy file to an OCI registry |
| `ac policy validate <file>` | Validate a policy file for internal consistency |
| `ac policy diff <old> <new>` | Show differences between two policy files |

## Global flags

| Flag | Description |
|---|---|
| `--runtime <type>` | Container runtime: `auto`, `docker`, `compose`, `sandbox` |
| `--config <path>` | Path to `agentcontainer.json` |
| `--org-policy <ref>` | OCI reference for org policy overlay |
| `--verbose` / `-v` | Increase log verbosity |
| `--version` | Print version information |
