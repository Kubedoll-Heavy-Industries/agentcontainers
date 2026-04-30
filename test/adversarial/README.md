# Adversarial Dogfood Harness

This directory tracks hostile-agent scenarios for agentcontainers dogfooding.
The executable Go harness lives in `internal/adversarial` and the first Docker
scenarios live in `internal/integration/adversarial_test.go`.

Run unit-level harness tests:

```sh
mise run test:adversarial
```

Run Docker-backed adversarial scenarios:

```sh
mise run test:adversarial:integration
```

Run the full adversarial dogfood pass:

```sh
mise run test:dogfood
```

Run the TypeScript testcontainers integration suite:

```sh
mise run test:integration:ts
```

Create a disposable locked-down container for manual Codex escape testing:

```sh
mise run redteam:codex
```

The task creates a temporary workspace, writes host and workspace canaries,
starts `ac run --detach`, and prints a scoped prompt plus cleanup commands. Use
`mise run redteam:codex -- --no-start` to only prepare the fixtures and inspect
the generated config.

Initial invariants:

- Host canaries outside the workspace must not appear in container stdout or stderr.
- Common host control sockets such as Docker and containerd sockets must not be readable.
- Canary tokens placed inside the workspace must not reach a controlled listener when network policy is `none`.

Harness split:

- Go tests own deterministic canary generation, leak detection, and runtime/enforcer regression probes.
- TypeScript testcontainers tests are preferred for multi-service fixtures such as fake metadata endpoints, callback sinks, registries, secret providers, and ecosystem compatibility stacks.

When an adversarial probe succeeds, add a regression scenario before fixing the
runtime or enforcer path.
