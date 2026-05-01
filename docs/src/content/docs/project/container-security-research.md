---
title: Container Security Research
description: Contemporary container escape research mapped to agentcontainers hardening work.
---

Last reviewed: May 1, 2026.

This page tracks container-security work that is directly relevant to adversarial AI agent workloads. It is intentionally defensive: it maps public research and vendor guidance to invariants that `agentcontainer dojo` profiles should test.

## Current Signals

| Signal | Why it matters for agentcontainers | Primary source |
|---|---|---|
| OCI runtime bugs still cluster around runtime setup, procfs/sysfs writes, bind mounts, console setup, and path races. | The runtime is part of the trusted computing base. A hostile image or config can target privileged setup code before the agent ever starts. | [runc 2025 procfs breakout advisory](https://www.openwall.com/lists/oss-security/2025/11/05/3), [runc advisories](https://github.com/opencontainers/runc/security/advisories) |
| User namespaces are now a mainstream Kubernetes hardening primitive. | UID 0 in a container should not map to UID 0 on the host. This matters even when capabilities are dropped. | [Kubernetes v1.36 user namespaces GA](https://kubernetes.io/blog/2026/04/23/kubernetes-v1-36-userns-ga/), [Kubernetes user namespaces docs](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/) |
| Docker and containerd both document rootless operation and user namespace based isolation. | The project should test both rootful and rootless hosts, and document which features degrade or fail under each. | [Docker rootless mode](https://docs.docker.com/engine/security/rootless/), [Docker userns-remap](https://docs.docker.com/engine/security/userns-remap/), [containerd rootless](https://containerd.io/docs/2.1/rootless/) |
| Docker Desktop Enhanced Container Isolation uses Sysbox-style isolation for developer machines. | The high bar for agent development containers is no longer just "drop caps"; it includes userns, protected bind mounts, syscall mediation, and procfs/sysfs information hiding. | [Docker ECI docs](https://docs.docker.com/enterprise/security/hardened-desktop/enhanced-container-isolation/), [Sysbox project](https://github.com/nestybox/sysbox) |
| Kubernetes Pod Security Standards still capture the minimum dangerous knobs. | The dojo Kubernetes profile should assert no privileged pods, no host namespaces, no HostPath mounts, dropped caps, seccomp, and no privilege escalation. | [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/), [Kubernetes seccomp docs](https://kubernetes.io/docs/reference/node/seccomp/) |
| Device and CDI paths are active container escape surfaces, especially GPU stacks. | Agent workloads often target AI/ML projects, so GPU support must be treated as a separate threat surface rather than a regular `/dev` pass-through. | [NVIDIA July 2025 Container Toolkit bulletin](https://nvidia.custhelp.com/app/answers/detail/a_id/5659/~/security-bulletin%3A-nvidia-container-toolkit---july-2025), [NVIDIA February 2025 bulletin](https://nvidia.custhelp.com/app/answers/detail/a_id/5616/~/security-bulletin%3A-nvidia-container-toolkit---11-february-2025) |
| eBPF is both an enforcement tool and an attack surface. | The enforcer sidecar needs the minimum privileges required to load policy, while the agent container must not be able to load BPF, access perf events, or introspect host workloads. | [USENIX Security 2023 eBPF cross-container paper](https://www.usenix.org/conference/usenixsecurity23/presentation/he), [Tetragon overview](https://tetragon.io/docs/overview/), [Tetragon enforcement docs](https://tetragon.io/docs/getting-started/enforcement/) |

## Threat Taxonomy

| Class | Example boundary question | Expected invariant |
|---|---|---|
| Runtime setup confusion | Can a crafted image or mount cause the runtime to write to host procfs/sysfs or follow a path outside the container root? | Host canary remains unreadable. `/proc/sys`, `/sys`, and cgroup mounts are read-only or unavailable from the agent. |
| Ambient root | Does container root map to host root, or retain useful capabilities? | Red-team images run as non-root where practical. Capability effective, permitted, and bounding sets are empty for the agent process. |
| Host control sockets | Is Docker, containerd, CRI-O, Podman, kubelet, or a Kubernetes service account token exposed? | Runtime sockets and service account tokens are absent unless explicitly mounted by a trusted profile. |
| Metadata service and egress | Can the agent reach cloud metadata, arbitrary outbound hosts, DNS exfil paths, or webhook endpoints not in policy? | The default dojo profile blocks metadata IPs and only allows declared model/API egress needed for the harness. |
| Mount metadata leakage | Does `/proc/self/mountinfo` disclose host paths, overlay internals, or runtime implementation details that help stage an attack? | Metadata leaks are inventoried. Profiles should minimize mount path disclosure where the runtime allows it. |
| Interpreter and tool escapes | Can a permitted shell, Python, Node, package manager, or VCS command spawn unapproved behavior? | Shell capability tests cover direct binary execution, interpreter flags, child processes, and reverse-shell-like connects. |
| Secret handling | Can canary tokens be read from env, process memory, `/proc/1/environ`, file descriptors, or stale mounts? | Secrets are not placed in ambient env. Secret canaries are readable only through declared tmpfs paths and TTL-gated ACLs. |
| eBPF and perf | Can the agent call `bpf(2)`, use `bpftool`, access `perf_event_open`, or inspect host/kernel state? | BPF, perf, kernel module, and privileged tracing paths return `EPERM` or are absent inside the agent container. |
| Devices and CDI | Are unexpected host devices, GPU hooks, CDI specs, or helper binaries available to an untrusted image? | `/dev` is minimal by default. Device profiles are opt-in and have separate regression tests. |
| Ptrace and process introspection | Can the agent inspect PID 1, sibling processes, or host processes? | Self/child tracing may be allowed for debuggers only when declared; cross-process and host-process tracing must fail. |

## Dojo Profile Roadmap

| Profile | Purpose | Status |
|---|---|---|
| `codex-redteam` | Drop into a locked-down Codex agent container with workspace and host canaries. | Shipped. Keep it as the default smoke harness. |
| `procfs-runc` | Regression suite for procfs/sysfs/cgroup write, mask, console, and bind-mount confusion classes. | Next. |
| `userns-matrix` | Compare Docker rootful, Docker userns-remap, Docker rootless, containerd rootless, and Docker Desktop behavior. | Next. |
| `runtime-sockets` | Assert Docker, containerd, CRI-O, Podman, kubelet, and Kubernetes token absence. | Next. |
| `network-canary` | Exercise allowlisted model egress, metadata denial, DNS behavior, and denied webhook canaries. | Next. |
| `metadata-min` | Inventory `/proc`, `/sys`, mountinfo, cgroups, hostname, env, and runtime metadata exposure. | Next. |
| `device-cdi` | Exercise GPU/CDI/device-plugin surfaces without exposing host helper hooks to untrusted images. | Planned. |
| `k8s-kind` | Run the same canary suite inside kind with Pod Security, seccomp, userns, and service-account variations. | Planned. |
| `ebpf-tcb` | Verify the enforcer sidecar privilege boundary and agent inability to load or manipulate BPF. | Planned. |

## Alpha Acceptance Criteria

Before the first serious alpha, the repo should meet these criteria:

- `agentcontainer dojo` works as the primary manual adversarial harness on macOS Docker Desktop and Linux Docker Engine.
- The default red-team image runs as a non-root user, has no SUID/SGID files, has no effective/permitted/bounding capabilities, and can still launch the target agent.
- Host canaries, runtime sockets, Kubernetes tokens, metadata endpoints, and secret canaries are negative tests, not just documented assumptions.
- Network, filesystem, process, and credential enforcement have fail-closed tests for Docker and Sandbox backends where the enforcer is required.
- Every known metadata leak has an owner: accepted limitation, runtime bug, documentation update, or hardening task.
- The release notes identify the exact runtime versions tested for Docker Desktop, Docker Engine, containerd, runc, and Kubernetes.
- GPU/device support remains opt-in until `device-cdi` has a regression profile.
- The threat model, security policy, and research baseline are published with the docs and have no "coming soon" placeholders on core safety pages.

## Operating Rule

Agent containers should be tested as if prompt injection has full control of the agent process. The defensive target is not "the model behaves"; it is "the runtime still holds when the model behaves adversarially."
