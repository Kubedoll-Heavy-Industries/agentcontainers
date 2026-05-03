---
title: Runtime Matrix
description: Planned backend, runtime, orchestrator, and workload matrix for agentcontainers hardening.
---

Last reviewed: May 2, 2026.

agentcontainers should not claim safety in the abstract. It should claim tested behavior across named host operating systems, container runtimes, orchestrators, and agent workload profiles.

This matrix separates those layers so different systems are compared on the right axis. Talos and Sysbox are a good example: Talos is a hardened Kubernetes node operating system; Sysbox is a container runtime boundary. They can complement each other, but they do not answer the same security question.

## Axes

| Axis | Examples | Boundary question |
|---|---|---|
| Host OS / node environment | Docker Desktop VM, Ubuntu, Talos Linux | If the container boundary fails, what kind of host environment does the agent land in? |
| Container runtime | runc, Sysbox, gVisor `runsc`, Kata Containers, Firecracker-backed runtime | What isolates the agent process from the host kernel and runtime control plane? |
| Orchestrator | Docker, containerd, Kubernetes, kind, Talos Kubernetes | How are pods, service accounts, runtime sockets, RuntimeClass, and policy admission exposed? |
| Agent workload profile | Codex, Claude Code, nested Docker, build tools, GPU/CDI workloads | Which realistic developer workflow pressures the isolation boundary? |
| Enforcement mode | Runtime-only, enforcer sidecar, Sandbox VM, Kubernetes policy, brokered approvals | Which agentcontainers controls are active and fail-closed? |

## Baseline Matrix

| Profile | Host / orchestrator | Runtime boundary | Why it matters | First verdicts to capture |
|---|---|---|---|---|
| `docker-desktop-runc` | Docker Desktop Linux VM | Docker default runc | Common local developer path. Container escape lands in the Docker Desktop VM, not directly on macOS/Windows, but VM/runtime metadata and sockets still matter. | Host canary, Docker socket, metadata endpoint, mountinfo leakage, uid map, capabilities, proc/sys/cgroup state. |
| `docker-desktop-eci` | Docker Desktop with Enhanced Container Isolation | Sysbox-backed ECI | Docker documents ECI as Sysbox-backed isolation with user namespaces, protected bind mounts, namespace isolation enforcement, syscall protection, and proc/sys information hiding. | UID/GID map, blocked host namespace sharing, Docker socket mount behavior, proc/sys emulation, compatibility with `agentcontainer run`. |
| `linux-docker-rootful` | General Linux host | Docker + runc | Lowest-friction Linux deployment and likely first self-hosted dogfood path. | Whether container root maps to host root, cgroup and mountinfo leakage, runtime socket absence, enforcer attach behavior. |
| `linux-docker-userns` | General Linux host | Docker userns-remap + runc | User namespace remapping changes the blast radius of container root and should become a recommended hardening baseline where compatible. | UID/GID map, bind mount ownership, enforcer attach behavior, workspace write compatibility. |
| `linux-docker-rootless` | General Linux host | Docker rootless | Removes the rootful daemon from the TCB for many workflows, but can alter networking, cgroups, and BPF behavior. | Enforcer support/degradation, cgroup availability, port/network policy behavior, workspace mounts. |
| `containerd-rootless` | General Linux host | containerd rootless | Useful for non-Docker production nodes and a stepping stone to Kubernetes/containerd integration. | CRI/containerd socket exposure, cgroup model, userns behavior, enforcer attach support. |
| `k8s-kind` | kind on Docker/containerd | Kubernetes + runc | Cheap local Kubernetes control-plane coverage before real cluster backends. | Service-account token policy, Pod Security, RuntimeClass wiring, hostPath denial, metadata egress, enforcer deployment model. |
| `talos-k8s` | Talos Linux node | Kubernetes + containerd | Talos hardens the node environment with API-only management, no SSH/shell workflow, immutable/read-only OS model, and declarative configuration. | Talos API credential exposure, Kubernetes token exposure, HostPath behavior, RuntimeClass support, enforcer sidecar viability, system extension requirements. |
| `sysbox` | Docker or Kubernetes node | Sysbox runtime | Sysbox applies user namespaces, procfs/sysfs virtualization, host-info hiding, and system-container support. Strong candidate for nested Docker/build/Kubernetes workflows without privileged containers. | Proc/sys/mount metadata reduction, nested Docker/build support, host socket absence, enforcer attach behavior through Sysbox. |
| `gvisor` | Docker or Kubernetes node | gVisor `runsc` userspace kernel | gVisor inserts an application kernel that intercepts Linux syscalls, reducing direct host-kernel exposure at the cost of compatibility differences. | Syscall compatibility, BPF/enforcer interaction, filesystem behavior, debugger/ptrace expectations, performance for agent workloads. |
| `kata-firecracker` | Kubernetes/containerd node | Kata Containers or Firecracker microVM | Hardware virtualization puts each pod/container group behind a VM boundary. This is the high-isolation path for untrusted agents. | Startup overhead, workspace sharing, enforcer-in-guest vs host-side model, metadata service exposure, nested runtime compatibility. |
| `device-cdi` | Kubernetes or Docker with devices | Runtime + CDI/device plugin | GPU and device workloads are common for AI projects and have a separate escape surface. Keep opt-in until tested. | CDI spec exposure, GPU helper binaries, `/dev` surface, NVIDIA toolkit behavior, device plugin service-account scope. |

## Talos vs Sysbox

| Question | Talos | Sysbox |
|---|---|---|
| Layer | Host/node operating system for Kubernetes. | OCI-compatible container runtime. |
| Primary security value | Reduces node attack surface and mutable host state. | Strengthens the container boundary itself. |
| Management model | API-driven Talos control plane; no normal SSH/shell workflow. | Normal Docker/Kubernetes workflows using a different runtime. |
| Isolation mechanics | Immutable/read-only OS model, minimal node services, declarative config, Kubernetes/containerd focus. | User namespaces, procfs/sysfs virtualization, host information hiding, locked initial mounts, safer system containers. |
| Best fit | Production-like Kubernetes nodes for agent workloads. | Local or cluster workloads needing nested Docker, systemd, buildkit, or Kubernetes-in-container behavior without privileged mode. |
| agentcontainers question | Can the enforcer and dojo harness run cleanly on a hardened Kubernetes node? | Can agentcontainers get stronger isolation and nested workflow support without breaking policy enforcement? |

## Profile Backlog

| Dojo profile | Owner question | Starting point |
|---|---|---|
| `runtime-matrix` | Which host/runtime/orchestrator tuple is under test, and what invariants apply? | Generate a manifest and checklist for a selected row. |
| `userns-matrix` | How do uid/gid maps, bind mounts, and capabilities differ across rootful, remapped, and rootless modes? | Docker rootful, Docker userns-remap, Docker rootless, containerd rootless. |
| `metadata-min` | Which runtime hides the most host metadata without breaking agent workflows? | Compare runc, Docker ECI/Sysbox, gVisor, Kata. |
| `talos-k8s` | Does Talos change the impact of runtime escape and Kubernetes credential exposure? | kind-style canaries plus Talos API credential checks. |
| `sysbox` | Can nested Docker/build/Kubernetes workflows run without privileged containers or host socket mounts? | Docker ECI where available; standalone Sysbox where supported. |
| `gvisor` | Which agent workflows break under a userspace kernel, and does that improve host-kernel isolation? | RuntimeClass or Docker `runsc` profile. |
| `kata-firecracker` | What changes when the agent is behind a microVM boundary? | Kubernetes RuntimeClass with Kata/Firecracker where available. |
| `device-cdi` | What extra surfaces appear when GPU/CDI support is enabled? | NVIDIA toolkit/CDI fixtures with host canaries and device inventory. |

## Required Verdicts

Every matrix row should report the same top-level verdicts:

- Host canary readable: yes/no.
- Workspace canary readable: yes/no; expected yes unless profile says otherwise.
- Runtime sockets exposed: Docker, containerd, CRI-O, Podman, BuildKit, kubelet.
- Kubernetes service-account token exposed: yes/no and automount configuration.
- Cloud metadata endpoint: blocked, timed out, reachable, or not routed.
- UID/GID mapping: full host map, remapped, rootless, or unknown.
- Capability sets: effective, permitted, bounding, ambient.
- `NoNewPrivs`, seccomp, AppArmor/SELinux/LSM status where available.
- `/proc`, `/sys`, cgroup, and mountinfo leakage summary.
- `/dev` and CDI/device exposure summary.
- Enforcer mode: attached, optional, unsupported, or degraded.
- Agent-local sensitive state: auth/session/history/log files inventoried with redacted values.

## Sources

- [Talos Linux FAQ](https://www.talos.dev/v1.11/learn-more/faqs/)
- [Talos Linux philosophy](https://www.talos.dev/v1.11/learn-more/philosophy/)
- [Talos system extensions](https://www.talos.dev/latest/talos-guides/configuration/system-extensions/)
- [Talos containerd configuration](https://www.talos.dev/v1.10/talos-guides/configuration/containerd/)
- [Sysbox project](https://github.com/nestybox/sysbox)
- [Docker Enhanced Container Isolation](https://docs.docker.com/enterprise/security/hardened-desktop/enhanced-container-isolation/)
- [Kubernetes RuntimeClass](https://kubernetes.io/docs/concepts/containers/runtime-class)
- [Kubernetes user namespaces](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/)
- [gVisor overview](https://gvisor.dev/docs/)
- [Kata Containers](https://katacontainers.io/)
- [Firecracker](https://firecracker-microvm.github.io/)
