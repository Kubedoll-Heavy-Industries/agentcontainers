---
title: Security
description: Security policy and vulnerability reporting.
---

## Reporting vulnerabilities

If you discover a security vulnerability, please report it responsibly. Do **not** open a public GitHub issue.

Email: security@agentcontainers.dev

We aim to acknowledge reports within 48 hours and provide a fix timeline within 7 days.

## Security model

agentcontainers is designed with a defense-in-depth security model. See the [Enforcement](/concepts/enforcement/) page for details on the six enforcement layers.

Key security properties:

- **Default-deny**: Omitting any capability section denies that capability entirely
- **Fail-closed**: If the enforcer sidecar cannot start, the session fails
- **No ambient credentials**: The container never has access to host credential stores
- **Short-lived secrets**: All credentials have TTLs and are rotated automatically
- **Kernel-level enforcement**: BPF LSM hooks enforce policy at the kernel, not in userspace
