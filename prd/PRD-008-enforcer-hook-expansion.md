# PRD-008: Enforcer Hook Expansion

| Field | Value |
|-------|-------|
| Status | Draft |
| Author | Cadence + Claude |
| Created | 2026-04-19 |
| Milestone | M5 |

## Overview

Expand the Rust/Aya BPF enforcer from its current hook set (network connect/sendmsg, LSM file_open, LSM bprm_check) to a comprehensive enforcement surface that covers process-tree-aware exec policy, fileless execution, reverse shells, privilege escalation, DNS exfiltration, and listening socket control. All additions extend the existing enforcer infrastructure — no external dependencies (no Falco, no Tetragon, no seccomp USER_NOTIF).

The headline feature is **process-tree exec policy**: deny-set propagation through the process tree with SELinux-style domain transitions, enabling rules like "npm can spawn node but not sh" enforced at the kernel level regardless of process tree depth.

## Goals

1. Block execution of binaries based on parent process identity, not just a flat allowlist.
2. Detect and block fileless execution (memfd_create + execveat).
3. Detect and kill reverse shells (socket-to-stdin redirection on shell processes).
4. Block listening sockets in agent containers (bind shells).
5. Detect privilege escalation attempts (capability probing).
6. Detect DNS-based data exfiltration via query payload inspection.
7. Generate restrictive seccomp profiles from declared capabilities.
8. Ship composable tool profiles (npm, pip, cargo, etc.) for process-tree policy.
9. Provide a learn mode for discovering legitimate process trees.

## Non-Goals

- Replacing the existing flat inode allowlist in bprm_check. Deny-sets layer on top.
- Runtime anomaly detection / behavioral analysis (Falco-style). Detection is a side effect of enforcement, not a goal.
- Content inspection of HTTP/HTTPS traffic. Network enforcement operates at the connection level.
- Timing channel or steganographic exfiltration detection. These require hardware-level isolation.
- Kubernetes-specific features. The enforcer is container-runtime-scoped.

## Background

### Current Hook Coverage

| Hook | Attachment | Purpose |
|------|-----------|---------|
| `cgroup/connect4` | cgroup_sock_addr | IPv4 outbound connection enforcement |
| `cgroup/connect6` | cgroup_sock_addr | IPv6 outbound connection enforcement |
| `cgroup/sendmsg4` | cgroup_sock_addr | IPv4 UDP send enforcement |
| `cgroup/sendmsg6` | cgroup_sock_addr | IPv6 UDP send enforcement |
| `security_bprm_check` | LSM | Binary exec allowlist (inode-based, default-deny) |
| `security_file_open` | LSM | Credential file gating (SECRET_ACLS) |

### Gaps Identified

1. **Process-tree blindness.** The exec allowlist is flat — `sh` is allowed or denied globally, with no awareness of who spawned it. This is the gap exploited by supply chain attacks like TeamPCP (malicious npm postinstall scripts spawning shells).

2. **Fileless execution.** `memfd_create` + `execveat` bypasses inode-based allowlisting because the binary has no file path. The exec allowlist checks inodes, but memfd inodes are ephemeral.

3. **No bind control.** Agent containers can bind listening sockets, enabling bind shells as a reverse-shell alternative.

4. **No reverse shell detection.** A shell with stdin redirected from a socket (classic `dup2(sockfd, 0)`) is indistinguishable from a legitimate shell at the exec level.

5. **No privilege escalation visibility.** Capability checks are denied by dropped caps, but the enforcer has no visibility into the attempts.

6. **No DNS exfil detection.** The sendmsg hooks check destination address but not payload content. DNS tunneling encodes data in query names to allowed resolvers.

7. **No seccomp hardening.** Containers run with Docker's default seccomp profile, not a profile tailored to declared capabilities.

### Research Findings

- **seccomp USER_NOTIF** is unsuitable for security enforcement (TOCTOU on userspace pointer arguments; the mechanism's author explicitly warns against it).
- **Hermes agent** uses regex-based command matching, which is trivially bypassable with obfuscation. Their security audit found 4 critical vulnerabilities.
- **Tetragon** uses the same BPF LSM hooks we use but attaches via kprobes (less stable ABI). Since we already have the Aya BPF infrastructure, expanding our hooks is preferable to adding Tetragon as a dependency.
- **Falco** is detect-only with 100ms+ latency to action. Useful for logging but not for inline enforcement.
- **LD_PRELOAD** is not a security boundary (bypassed by static binaries, Go, inline assembly).
- **BPF LSM bprm_check** (our current approach) is the recommended mechanism for synchronous exec interception. No TOCTOU — the kernel resolves the path and populates the inode before the hook fires.

## Technical Design

### 1. Process-Tree Exec Policy

#### Deny-Set Propagation

Each binary in the tool profile is assigned a `deny_set_id` (u32). The deny-set defines which child binaries the process (and all its descendants) may exec. Enforcement is default-deny: if a `(deny_set_id, target_inode)` pair is not in the allow map, the exec is blocked.

On `fork()`, the child inherits the parent's deny_set_id. On `exec()`, if the target binary is allowed and a domain transition is defined, the process transitions to the target's own deny_set_id. This is analogous to SELinux domain transitions.

Key property: **deny-sets propagate through the entire subtree regardless of depth.** There is no tree walk — the BPF program does a single O(1) map lookup. An attacker cannot escape enforcement by adding hops to the process chain.

#### BPF Maps

| Map | Type | Key | Value | Max Entries |
|-----|------|-----|-------|-------------|
| `PROC_DENY_SETS` | HashMap | `u32` (pid) | `u32` (deny_set_id) | 8192 |
| `DENY_SET_POLICY` | HashMap | `DenySetKey { deny_set_id: u32, inode: u64, dev_major: u32, dev_minor: u32 }` | `u8` (1 = allow) | 16384 |
| `DENY_SET_TRANSITIONS` | HashMap | `DenySetKey` | `u32` (child_deny_set_id) | 4096 |

#### BPF Hook: `sched_process_fork`

Tracepoint attachment. On fork in an enforced cgroup:
1. Read parent PID from tracepoint context.
2. Look up parent's deny_set_id in `PROC_DENY_SETS`.
3. If present, insert `{child_pid → parent_deny_set_id}` into `PROC_DENY_SETS`.
4. If parent has no deny_set_id, skip (process is not under process-tree enforcement).

#### BPF Hook: `bprm_check_security` (extended)

The existing bprm_check hook is extended. After the existing inode allowlist check passes:
1. Look up current PID's deny_set_id in `PROC_DENY_SETS`.
2. If no deny_set_id, allow (not under process-tree enforcement — falls back to flat allowlist only).
3. Look up `(deny_set_id, target_inode, dev)` in `DENY_SET_POLICY`.
4. If not found, deny. Emit `ExecEvent` with deny reason = `DENY_SET_VIOLATION`.
5. If found, check `DENY_SET_TRANSITIONS` for `(deny_set_id, target_inode, dev)`.
6. If transition exists, update `PROC_DENY_SETS` for current PID to the new deny_set_id.
7. Allow exec.

#### PID Cleanup

Processes that exit must be removed from `PROC_DENY_SETS` to prevent map exhaustion and stale entries. Hook `sched_process_exit` tracepoint: if the exiting PID is in `PROC_DENY_SETS`, delete the entry.

#### Approval Flow (Mode C)

When a deny-set violation occurs:
1. BPF denies exec and emits event to `PROC_EVENTS` ring buffer.
2. Enforcer daemon reads the event.
3. Daemon forwards the event to the CLI via gRPC `EnforcementEvent` stream.
4. CLI prompts the user: `"npm (pid 1234) wants to exec sh. Allow for this session? [y/N]"`
5. If approved, CLI sends `UpdateDenySetPolicy` RPC to the enforcer daemon.
6. Daemon inserts `(deny_set_id, inode, dev) → allow` into `DENY_SET_POLICY` map.
7. Agent retries the command. BPF allows it.

Approved pairs persist for the container's lifetime only. They are not written back to the sealed profile.

### 2. Learn Mode

`agentcontainer learn` starts the container with process-tree enforcement in observation mode:

1. The `bprm_check` hook **allows** all execs but emits a `LEARN_EVENT` for every `(parent_deny_set_id, child_inode)` pair observed.
2. Network, filesystem, and credential enforcement remain fully active.
3. The enforcer daemon collects observed pairs into a process-tree graph.
4. On container stop, the CLI writes `process-profile.json` to the workspace.

The user reviews the generated profile, removes anything suspicious, and commits it. Subsequent `agentcontainer run` enforces the reviewed profile.

**Learn mode is not a security mode.** It is a profiling tool. A compromised dependency during learn mode would get its malicious exec chain recorded as legitimate.

**Session export:** `agentcontainer learn --from-session` exports parent→child pairs that were approved via the interactive prompt (Mode C) during a normal run. This avoids requiring a dedicated learn run — the user's interactive approvals become the profile.

### 3. Fileless Execution Blocking (memfd_create)

#### Hook

Tracepoint on `sys_enter_memfd_create`. Block creation of executable anonymous memory regions at the syscall entry point, before the FD is created. This is cleaner than blocking at `file_open` — it prevents the anonymous FD from existing at all.

#### Rationale

There is no legitimate reason for an AI agent's toolchain to create executable anonymous memory regions. This is the standard technique for fileless malware and is used by exploit frameworks (Metasploit, Cobalt Strike) for in-memory execution.

#### Not Configurable

This hook is always active for enforced cgroups. No configuration knob.

### 4. Listening Socket Blocking (bind4/bind6)

#### Hooks

| Hook | Attachment | Purpose |
|------|-----------|---------|
| `cgroup/bind4` | cgroup_sock_addr | Block IPv4 bind |
| `cgroup/bind6` | cgroup_sock_addr | Block IPv6 bind |

#### Policy

Default-deny for enforced cgroups. Agent containers should not bind listening sockets unless explicitly permitted.

#### Config Extension

```jsonc
{
  "agent": {
    "capabilities": {
      "network": {
        "listen": [
          { "port": 8080, "protocol": "tcp" }
        ]
      }
    }
  }
}
```

Empty `listen` array (the default) means no listening sockets allowed.

#### BPF Map

| Map | Type | Key | Value | Max Entries |
|-----|------|-----|-------|-------------|
| `ALLOWED_BINDS` | HashMap | `BindKey { port: u16, protocol: u8 }` | `u8` | 256 |

#### Not Configurable

Bind enforcement is always active. The `listen` config controls what's allowed, not whether enforcement is active.

### 5. Reverse Shell Detection (dup2/dup3)

#### Hook

Kprobe on `__x64_sys_dup2` and `__x64_sys_dup3` (architecture-specific).

#### Detection Logic

1. Process is in an enforced cgroup.
2. `newfd` is 0 (stdin) or 1 (stdout).
3. `oldfd` refers to a socket (check via `sock_from_file` or `fget` + `S_ISSOCK`).
4. Process comm matches a known shell: `sh`, `bash`, `dash`, `zsh`, `fish`, `python`, `python3`, `perl`, `ruby`, `node`.
5. If all conditions met: send SIGKILL via `bpf_send_signal(SIGKILL)`.

#### Configurable

Via `agent.capabilities.shell.reverseShellDetection`:

| Value | Behavior |
|-------|----------|
| `"enforce"` | SIGKILL on detection (default) |
| `"log"` | Emit event but allow |
| `"off"` | Disabled |

#### BPF Map

| Map | Type | Key | Value | Max Entries |
|-----|------|-----|-------|-------------|
| `REVERSE_SHELL_MODE` | Array | index 0 | `u8` (0=enforce, 1=log, 2=off) | 1 |

### 6. Privilege Escalation Detection (security_capable)

#### Hook

LSM `capable`. Fires on every capability check in the kernel for processes in enforced cgroups.

#### Behavior

Log all capability check attempts to `PROC_EVENTS` ring buffer with the capability number and result. The kernel already denies capabilities that were dropped — this hook provides visibility into probing attempts, which indicate exploitation.

#### Not Configurable

Always active for enforced cgroups. Logging only — the kernel handles the actual deny.

### 7. DNS Payload Inspection

#### Hook

Extended `sendmsg4` / `sendmsg6` (existing hooks). For UDP packets destined to port 53, read the DNS query section and measure the total query name length.

#### Detection Logic

1. Packet is UDP to port 53.
2. Parse DNS header (12 bytes) to find the question section.
3. Walk the QNAME labels, summing total length.
4. If total length exceeds threshold, block or log.

Legitimate DNS queries rarely exceed 60 bytes in the query name. Exfiltration queries encode data in subdomains and routinely exceed 128 bytes.

#### Configurable

Via `agent.capabilities.network.dnsInspection`:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | string | `"off"` | `"off"`, `"log"`, `"enforce"` |
| `maxQueryLength` | int | 128 | Query name byte threshold |

#### BPF Map

| Map | Type | Key | Value | Max Entries |
|-----|------|-----|-------|-------------|
| `DNS_INSPECTION_CONFIG` | Array | index 0 | `DnsConfig { mode: u8, max_len: u16 }` | 1 |

### 8. Seccomp Profile Generation

#### Mechanism

Go-side feature in `internal/container/`. Generate a seccomp profile from `agentcontainer.json` capabilities and apply it to the container at creation time via Docker's `SecurityOpt: ["seccomp=<profile>"]`.

#### Default Blocked Syscalls

`mount`, `umount2`, `ptrace`, `unshare`, `setns`, `pivot_root`, `kexec_load`, `kexec_file_load`, `bpf`, `add_key`, `keyctl`, `request_key`, `userfaultfd`, `perf_event_open`, `init_module`, `finit_module`, `delete_module`, `reboot`, `swapon`, `swapoff`, `sethostname`, `setdomainname`, `iopl`, `ioperm`, `create_module`, `get_kernel_syms`, `query_module`, `nfsservctl`, `acct`, `lookup_dcookie`, `mbind`, `move_pages`.

#### Configurable

Via `agent.seccomp`:

| Value | Behavior |
|-------|----------|
| `"default"` | Generated restrictive profile (default) |
| `"strict"` | Tighter profile, blocks additional syscalls including `clone3` flags |
| `"none"` | No custom seccomp (Docker default applies) |
| `"<path>"` | User-provided profile path |

### 9. Profile Registry

#### Profile Format

```jsonc
{
  "name": "npm",
  "version": 1,
  "description": "Process-tree policy for npm (Node Package Manager)",
  "binary": "npm",
  "allowChildren": ["node", "npm", "npx"],
  "transitions": {
    "node": "node@1"
  }
}
```

- `allowChildren`: binaries this tool may exec. Default-deny for anything not listed.
- `transitions`: when an allowed child execs, which deny-set it transitions to. If no transition is defined, the child inherits the parent's deny-set.

#### Registry Sources (Resolution Order)

1. **Inline `processPolicy`** in `agentcontainer.json` — user overrides (highest priority).
2. **Org policy layer** in the container image — team/org standards.
3. **Built-in profiles** embedded in the `agentcontainer` binary — baseline defaults.

#### Composition

Multiple profiles are merged at build time (`agentcontainer build`). Merge rule: **intersection of allowChildren.** If org policy says npm can spawn `[node]` and the built-in profile says `[node, npx]`, the result is `[node]`. Most restrictive wins, consistent with existing org policy merge semantics.

#### Seal

The merged profile set is written into the container image as part of the policy layer. At runtime, the enforcer daemon reads the sealed profiles and populates the BPF maps. No runtime profile resolution.

#### deny_set_id Assignment

The enforcer daemon assigns numeric IDs at startup. The mapping `(profile_name → deny_set_id)` is ephemeral and local to each container lifecycle. Profiles reference each other by name; the daemon resolves names to IDs when populating maps.

#### Shipped Profiles

Initial set:

| Profile | Binary | allowChildren | Notes |
|---------|--------|---------------|-------|
| `npm@1` | npm | node, npm, npx | Covers lifecycle scripts via node |
| `node@1` | node | node | Worker child processes |
| `pip@1` | pip | python, python3 | Build backends |
| `cargo@1` | cargo | rustc, cargo | Build scripts |
| `git@1` | git | git, ssh, gpg | Clone, fetch, push |
| `make@1` | make | sh, gcc, g++, cc, ld, ar | Build toolchain |

The `make@1` profile is notable: make legitimately spawns `sh` for recipe execution. The `sh` spawned by make would inherit make's deny-set, which allows build tools but not network tools. This is where the deny-set transition model shines — sh is allowed in the make context but blocked in the npm context.

## Config Schema Summary

New fields added to `agentcontainer.json`:

```jsonc
{
  "agent": {
    "capabilities": {
      "shell": {
        "commands": ["git", "npm test"],
        "profiles": ["npm@1", "node@1", "git@1"],
        "processPolicy": {
          "npm": {
            "allowChildren": ["node", "npm"]
          }
        },
        "reverseShellDetection": "enforce"
      },
      "network": {
        "listen": [],
        "dnsInspection": {
          "mode": "off",
          "maxQueryLength": 128
        }
      }
    },
    "seccomp": "default"
  }
}
```

## Testing

### Unit Tests (Rust)

- Deny-set map population and lookup correctness.
- Transition logic: parent set A + child inode → child set B.
- PID cleanup on process exit.
- DNS query name length parsing.
- Seccomp profile generation from capabilities.

### BPF Integration Tests

Require `CONFIG_BPF_LSM=y`. Run on self-hosted runners or locally with `sudo`.

- Process-tree enforcement: spawn a denied child, verify EPERM.
- Deny-set inheritance: verify grandchild inherits deny-set.
- Domain transition: verify child gets new deny-set after exec of allowed binary.
- memfd_create blocking: create memfd, attempt exec, verify EPERM.
- bind blocking: attempt bind on disallowed port, verify EACCES.
- dup2 reverse shell: redirect shell stdin from socket, verify SIGKILL.
- DNS inspection: send long query name to port 53, verify block in enforce mode.
- Learn mode: verify events emitted but exec allowed.

### End-to-End Tests

- `agentcontainer learn` generates profile matching observed process tree.
- `agentcontainer run` with profile enforces deny-sets.
- Interactive approval (Mode C) adds pairs to session policy.
- `agentcontainer learn --from-session` exports approved pairs.
- Profile composition: org policy + built-in → intersection.
- Seccomp profile applied to container.

## Open Questions

1. **PID namespace interaction.** Enforced containers run in their own PID namespace. The BPF programs see the host PID. The `PROC_DENY_SETS` map uses host PIDs. Verify that `bpf_get_current_pid_tgid()` returns the host PID in all contexts (it should — BPF runs in the host kernel).

2. **Map size bounds.** `PROC_DENY_SETS` is sized at 8192 entries. A fork bomb inside the container could exhaust this map. Consider: should map exhaustion trigger deny-all (fail-closed) or should we use a per-cgroup counter to bound total tracked PIDs?

3. **Learn mode duration.** Should learn mode run for a fixed duration, until the user stops it, or until a specific workload completes? Current design: until container stop. May need a `--timeout` flag.

4. **Profile versioning.** Profiles are versioned (`npm@1`). What happens when a profile is updated (`npm@2`)? The org policy layer references profiles by name+version. Upgrading requires rebuilding the image. This is intentional (immutable sealed policy), but should be documented clearly.
