---
title: Enforcement
description: Defense-in-depth security model with BPF LSM hooks, network enforcement, and credential gating.
---

agentcontainers uses a defense-in-depth approach with multiple enforcement layers. Even if one layer is bypassed, the others catch the violation.

## Enforcement layers

### Layer 1: Container isolation

Standard OCI container hardening:
- Dropped Linux capabilities (only declared caps retained)
- seccomp syscall filtering
- Read-only root filesystem
- No access to host credential stores

### Layer 2: Network enforcement

BPF cgroup hooks gate all network egress at the kernel level:

| Hook | Protocol | Purpose |
|---|---|---|
| `connect4` | TCP (IPv4) | Gate outbound TCP connections |
| `connect6` | TCP (IPv6) | Gate outbound TCP connections |
| `sendmsg4` | UDP (IPv4) | Gate UDP datagram sends |
| `sendmsg6` | UDP (IPv6) | Gate UDP datagram sends |

All protocols are enforced. Unlike Docker's proxy-based enforcement (gVisor netstack), BPF hooks cannot be bypassed via unbound UDP exfiltration.

Allowed endpoints are declared in `agent.capabilities.network`:

```jsonc
{
  "agent": {
    "capabilities": {
      "network": {
        "allow": [
          "api.github.com:443",
          "registry.npmjs.org:443"
        ]
      }
    }
  }
}
```

### Layer 3: Filesystem enforcement

The BPF LSM `file_open` hook enforces inode-level access control:

- **DENIED_INODES**: Explicitly blocked files (e.g., host credential stores)
- **ALLOWED_INODES**: Explicitly permitted files
- **Default deny**: Anything not in the allow list is blocked

Filesystem capabilities are declared in `agent.capabilities.filesystem`:

```jsonc
{
  "agent": {
    "capabilities": {
      "filesystem": {
        "read": ["/workspace/**", "/usr/**"],
        "write": ["/workspace/**", "/tmp/**"],
        "deny": ["/etc/shadow", "/root/.ssh/**"]
      }
    }
  }
}
```

### Layer 4: Process enforcement

The BPF LSM `bprm_check_security` hook validates every binary execution against the declared shell capabilities:

```jsonc
{
  "agent": {
    "capabilities": {
      "shell": {
        "allow": ["git", "npm", "node", "python3"],
        "deny": ["curl", "wget", "sudo", "su"]
      }
    }
  }
}
```

Interpreter injection attacks (e.g., `python3 -c 'import os; os.system("curl ...")'`) are blocked by detecting and denying `-c` and `-e` flags on interpreters.

### Layer 5: Credential enforcement (CREDLSM)

The BPF LSM `file_open` hook includes a `SECRET_ACLS` map that gates per-cgroup access to secret files:

- Each secret file's inode is registered with `(inode, device, cgroup_id)` as the key
- The ACL value includes TTL expiry (`expires_at_ns`) and permission flags
- If a cgroup has no ACL entry for a secret file, access is denied
- If the TTL has expired, access is denied
- Write access to secrets is always denied unless explicitly permitted

Block reasons are tracked:
- **No ACL entry**: The cgroup is not authorized for this secret
- **TTL expired**: The credential has expired and needs rotation
- **Write denied**: Write access to credential files is blocked

Credential events are emitted to a dedicated `CRED_EVENTS` ring buffer for audit logging.

### Layer 6: Approval broker

The approval broker wraps the container runtime (decorator pattern) and intercepts capability changes. When an agent requests a capability not declared in the original config, the broker:

1. Pauses the request
2. Shows the user a diff of what changed
3. Waits for explicit approval
4. Only then applies the capability change

This is the human-in-the-loop layer for runtime escalation.

## Enforcement strategy

The enforcer uses a **gRPC sidecar** architecture:

```
ac runtime ──gRPC──► ac-enforcer sidecar ──BPF──► kernel
```

- The Go runtime sends policy via gRPC to the Rust enforcer sidecar
- The enforcer attaches Aya BPF programs to the container's cgroup
- All enforcement happens at the kernel level (no userspace bypass)
- The enforcer is fail-closed: if it cannot start, the session fails

There is no in-process BPF and no iptables/nftables. The sidecar model ensures:
- The BPF programs run with the minimum required privileges
- The agent container has no access to the enforcement mechanism
- Policy updates are applied atomically via gRPC `Apply` calls

## Stats and audit

The enforcer tracks per-cgroup statistics:

| Counter | Description |
|---|---|
| `network_allowed` | Network connections permitted |
| `network_blocked` | Network connections denied |
| `filesystem_allowed` | File opens permitted |
| `filesystem_blocked` | File opens denied |
| `process_allowed` | Process executions permitted |
| `process_blocked` | Process executions denied |
| `credential_allowed` | Secret file reads permitted |
| `credential_blocked` | Secret file reads denied |

Events are emitted to per-domain ring buffers (`NET_EVENTS`, `FS_EVENTS`, `PROC_EVENTS`, `CRED_EVENTS`) for real-time audit logging.

View enforcement stats:

```bash
ac enforcer status
ac enforcer diagnose
ac audit events
ac audit summary
```

## Enforcement in Sandbox mode

When using Docker Sandbox (microVM), **both** enforcement layers are active:

1. **Docker's proxy enforcement** (gVisor netstack `ProxyEnforcingDialer`) provides coarse-grained network control
2. **BPF enforcer inside the VM** provides precise, kernel-level enforcement with no bypasses

The BPF enforcer runs inside the Sandbox VM, not on the host. This provides defense-in-depth: the proxy catches most violations, and the BPF hooks catch anything that slips through (including unbound UDP exfiltration).
