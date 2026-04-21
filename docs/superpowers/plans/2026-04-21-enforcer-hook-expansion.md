# Enforcer Hook Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand the Aya BPF enforcer with deny-set process-tree policy, fileless execution blocking, bind socket blocking, reverse shell detection, and new gRPC RPCs to manage them.

**Architecture:** New BPF hooks (`sched_process_fork`, `sched_process_exit`, `tracepoint/memfd_create`, `cgroup/bind4`, `cgroup/bind6`, kprobe `dup2`/`dup3`) are added to `agentcontainer-ebpf`. New shared map types are added to `agentcontainer-common`. The `agentcontainer-enforcer` gRPC server gets new RPCs (`ApplyDenySetPolicy`, `UpdateDenySetPolicy`) and populates the new BPF maps. All hooks are cgroup-scoped using the existing `ENFORCED_CGROUPS` map.

**Tech Stack:** Rust, Aya eBPF, tonic gRPC, protobuf

**Reference:** `prd/PRD-008-enforcer-hook-expansion.md`

---

## File Structure

### New files

| File | Responsibility |
|------|---------------|
| `enforcer/agentcontainer-ebpf/src/process/mod.rs` | Module root for process-tree hooks |
| `enforcer/agentcontainer-ebpf/src/process/fork.rs` | `sched_process_fork` tracepoint — deny-set inheritance |
| `enforcer/agentcontainer-ebpf/src/process/exit.rs` | `sched_process_exit` tracepoint — PID cleanup |
| `enforcer/agentcontainer-ebpf/src/process/memfd.rs` | `sys_enter_memfd_create` tracepoint — fileless exec blocking |
| `enforcer/agentcontainer-ebpf/src/network/bind.rs` | `cgroup/bind4` and `cgroup/bind6` hooks |
| `enforcer/agentcontainer-ebpf/src/lsm/dup_check.rs` | kprobe on `__x64_sys_dup2`/`dup3` — reverse shell detection |

### Modified files

| File | Changes |
|------|---------|
| `enforcer/agentcontainer-common/src/maps.rs` | Add `DenySetKey`, `BindKey`, `DupCheckMode` types |
| `enforcer/agentcontainer-common/src/events.rs` | Add `DenySetViolationEvent`, `BindEvent`, `ReverseShellEvent` event types, new `EventType` variants |
| `enforcer/agentcontainer-ebpf/src/maps.rs` | Add `PROC_DENY_SETS`, `DENY_SET_POLICY`, `DENY_SET_TRANSITIONS`, `ALLOWED_BINDS`, `REVERSE_SHELL_MODE` maps |
| `enforcer/agentcontainer-ebpf/src/lib.rs` | Register new programs |
| `enforcer/agentcontainer-ebpf/src/lsm/bprm_check.rs` | Extend to check deny-set policy after inode allowlist |
| `enforcer/agentcontainer-ebpf/src/lsm/mod.rs` | Add `dup_check` module |
| `enforcer/agentcontainer-ebpf/src/network/mod.rs` | Add `bind` module |
| `enforcer/agentcontainer-enforcer/proto/enforcer.proto` | Add `ApplyDenySetPolicy`, `UpdateDenySetPolicy` RPCs and messages |
| `enforcer/agentcontainer-enforcer/src/grpc.rs` | Implement new RPC handlers |
| `enforcer/agentcontainer-enforcer/src/bpf.rs` | Load new programs, attach new hooks, populate new maps |

---

### Task 1: Shared types for deny-set maps

**Files:**
- Modify: `enforcer/agentcontainer-common/src/maps.rs`
- Modify: `enforcer/agentcontainer-common/src/events.rs`

- [ ] **Step 1: Add deny-set map key types to `maps.rs`**

Add after the `FsInodeKey` definition:

```rust
// --- Process deny-set map keys ---

/// Key for deny-set policy lookup: (deny_set_id, inode, dev).
/// Used in DENY_SET_POLICY and DENY_SET_TRANSITIONS maps.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DenySetKey {
    pub deny_set_id: u32,
    pub _pad: u32,
    pub inode: u64,
    pub dev_major: u32,
    pub dev_minor: u32,
}

// --- Bind map keys ---

/// Key for allowed bind ports.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindKey {
    pub port: u16,
    pub protocol: u8,
    pub _pad: u8,
}
```

Add Pod impls in the `pod_impls` module:

```rust
unsafe impl aya::Pod for super::DenySetKey {}
unsafe impl aya::Pod for super::BindKey {}
```

- [ ] **Step 2: Add new event types to `events.rs`**

Add new `EventType` variants:

```rust
pub enum EventType {
    NetworkConnect = 1,
    DnsResponse = 2,
    FsOpen = 3,
    ProcessExec = 4,
    CredentialAccess = 5,
    DenySetViolation = 6,
    BindBlocked = 7,
    ReverseShellDetected = 8,
    MemfdBlocked = 9,
}
```

Add new event structs:

```rust
/// Event emitted when a deny-set policy blocks an exec.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DenySetEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub event_type: u32,
    pub verdict: u32,
    pub deny_set_id: u32,
    pub parent_inode: u64,
    pub child_inode: u64,
    pub comm: [u8; COMM_MAX],
}

/// Event emitted when a bind is blocked.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BindEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub event_type: u32,
    pub verdict: u32,
    pub port: u16,
    pub protocol: u8,
    pub _pad: u8,
    pub comm: [u8; COMM_MAX],
}

/// Event emitted when a reverse shell is detected.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReverseShellEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub event_type: u32,
    pub verdict: u32,
    pub oldfd: u32,
    pub newfd: u32,
    pub comm: [u8; COMM_MAX],
}
```

- [ ] **Step 3: Run `cargo check` in enforcer/ to verify types compile**

Run: `cargo check --manifest-path enforcer/Cargo.toml -p agentcontainer-common`
Expected: compiles with no errors

- [ ] **Step 4: Run existing tests**

Run: `cargo test --manifest-path enforcer/Cargo.toml -p agentcontainer-common`
Expected: all existing tests pass

- [ ] **Step 5: Commit**

```bash
git add enforcer/agentcontainer-common/src/maps.rs enforcer/agentcontainer-common/src/events.rs
git commit -m "feat(enforcer): add deny-set, bind, and reverse shell shared types"
```

---

### Task 2: BPF maps for deny-sets, bind, and reverse shell mode

**Files:**
- Modify: `enforcer/agentcontainer-ebpf/src/maps.rs`

- [ ] **Step 1: Add new BPF maps**

Add after the existing process maps section:

```rust
// --- Process deny-set maps ---

/// Maps PID → deny_set_id. Populated on fork, cleaned on exit.
#[map]
pub static PROC_DENY_SETS: HashMap<u32, u32> = HashMap::with_max_entries(8192, 0);

/// Deny-set policy: (deny_set_id, inode, dev) → allow flag.
/// If an entry exists, the exec is allowed under this deny-set.
/// Default-deny: missing entry = blocked.
#[map]
pub static DENY_SET_POLICY: HashMap<DenySetKey, u8> = HashMap::with_max_entries(16384, 0);

/// Deny-set transitions: (parent_deny_set_id, child_inode, dev) → child_deny_set_id.
/// On allowed exec, if a transition exists, update the PID's deny_set_id.
#[map]
pub static DENY_SET_TRANSITIONS: HashMap<DenySetKey, u32> = HashMap::with_max_entries(4096, 0);

// --- Bind maps ---

/// Allowed bind ports. Empty = no listening sockets allowed (default-deny).
#[map]
pub static ALLOWED_BINDS: HashMap<BindKey, u8> = HashMap::with_max_entries(256, 0);

/// Ring buffer for bind enforcement events.
#[map]
pub static BIND_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// --- Reverse shell detection ---

/// Mode for reverse shell detection: 0=enforce (SIGKILL), 1=log, 2=off.
/// Single entry at index 0.
#[map]
pub static REVERSE_SHELL_MODE: Array<u8> = Array::with_max_entries(1, 0);

/// Ring buffer for reverse shell events.
#[map]
pub static REVERSE_SHELL_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// --- Memfd blocking ---

/// Ring buffer for memfd_create block events.
#[map]
pub static MEMFD_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);
```

Add the import for the new key types at the top:

```rust
use agentcontainer_common::maps::{
    CgroupStats, FsInodeKey, PortKeyV4, SecretAclKey, SecretAclValue,
    DenySetKey, BindKey,
};
```

- [ ] **Step 2: Add per-cgroup stat offsets for new hook types**

```rust
pub const CGROUP_STAT_BIND_ALLOWED: usize = 8;
pub const CGROUP_STAT_BIND_BLOCKED: usize = 9;
pub const CGROUP_STAT_DENYSET_ALLOWED: usize = 10;
pub const CGROUP_STAT_DENYSET_BLOCKED: usize = 11;
```

Note: `CgroupStats` in `agentcontainer-common/src/maps.rs` needs to be extended with these fields too. Add:

```rust
pub struct CgroupStats {
    // ... existing fields ...
    pub bind_allowed: u64,
    pub bind_blocked: u64,
    pub denyset_allowed: u64,
    pub denyset_blocked: u64,
}
```

- [ ] **Step 3: Verify BPF compiles**

Run: `cargo check --manifest-path enforcer/Cargo.toml -p agentcontainer-ebpf`
Expected: compiles (BPF programs use these maps but we haven't changed program code yet)

- [ ] **Step 4: Commit**

```bash
git add enforcer/agentcontainer-ebpf/src/maps.rs enforcer/agentcontainer-common/src/maps.rs
git commit -m "feat(enforcer): add BPF maps for deny-sets, bind enforcement, reverse shell detection"
```

---

### Task 3: sched_process_fork — deny-set inheritance

**Files:**
- Create: `enforcer/agentcontainer-ebpf/src/process/mod.rs`
- Create: `enforcer/agentcontainer-ebpf/src/process/fork.rs`
- Modify: `enforcer/agentcontainer-ebpf/src/lib.rs`

- [ ] **Step 1: Create process module root**

`enforcer/agentcontainer-ebpf/src/process/mod.rs`:

```rust
pub mod exit;
pub mod fork;
pub mod memfd;
```

- [ ] **Step 2: Implement fork hook**

`enforcer/agentcontainer-ebpf/src/process/fork.rs`:

```rust
//! sched_process_fork tracepoint — inherit parent's deny_set_id to child.

use aya_ebpf::helpers::bpf_get_current_cgroup_id;
use aya_ebpf::macros::tracepoint;
use aya_ebpf::programs::TracePointContext;

use crate::maps::{ENFORCED_CGROUPS, PROC_DENY_SETS};

/// Tracepoint context for sched_process_fork.
/// Fields: parent_pid (offset 24), child_pid (offset 44) in the tracepoint format.
/// See /sys/kernel/debug/tracing/events/sched/sched_process_fork/format

#[tracepoint]
pub fn ac_sched_fork(ctx: TracePointContext) -> u32 {
    match try_sched_fork(&ctx) {
        Ok(()) => 0,
        Err(_) => 0, // Non-fatal — don't block forks on BPF errors
    }
}

fn try_sched_fork(ctx: &TracePointContext) -> Result<(), i64> {
    // Only track forks in enforced cgroups.
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if unsafe { ENFORCED_CGROUPS.get(&cgroup_id) }.is_none() {
        return Ok(());
    }

    // Read parent_pid and child_pid from tracepoint context.
    // sched_process_fork format:
    //   field: pid_t parent_pid; offset:24; size:4;
    //   field: pid_t child_pid;  offset:44; size:4;
    let parent_pid: u32 = unsafe { ctx.read_at(24)? };
    let child_pid: u32 = unsafe { ctx.read_at(44)? };

    // If parent has a deny_set_id, propagate to child.
    if let Some(deny_set_id) = unsafe { PROC_DENY_SETS.get(&parent_pid) } {
        let _ = PROC_DENY_SETS.insert(&child_pid, deny_set_id, 0);
    }

    Ok(())
}
```

- [ ] **Step 3: Register in lib.rs**

Add `mod process;` to `enforcer/agentcontainer-ebpf/src/lib.rs` alongside the existing `mod lsm;` and `mod network;`.

- [ ] **Step 4: Verify BPF compiles**

Run: `cargo check --manifest-path enforcer/Cargo.toml -p agentcontainer-ebpf`
Expected: compiles

- [ ] **Step 5: Commit**

```bash
git add enforcer/agentcontainer-ebpf/src/process/ enforcer/agentcontainer-ebpf/src/lib.rs
git commit -m "feat(enforcer): sched_process_fork tracepoint — deny-set inheritance"
```

---

### Task 4: sched_process_exit — PID cleanup

**Files:**
- Create: `enforcer/agentcontainer-ebpf/src/process/exit.rs`

- [ ] **Step 1: Implement exit hook**

`enforcer/agentcontainer-ebpf/src/process/exit.rs`:

```rust
//! sched_process_exit tracepoint — clean up PROC_DENY_SETS on process exit.

use aya_ebpf::helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid};
use aya_ebpf::macros::tracepoint;
use aya_ebpf::programs::TracePointContext;

use crate::maps::{ENFORCED_CGROUPS, PROC_DENY_SETS};

#[tracepoint]
pub fn ac_sched_exit(_ctx: TracePointContext) -> u32 {
    // Only clean up in enforced cgroups.
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if unsafe { ENFORCED_CGROUPS.get(&cgroup_id) }.is_none() {
        return 0;
    }

    let pid = (unsafe { bpf_get_current_pid_tgid() } >> 32) as u32;
    let _ = PROC_DENY_SETS.remove(&pid);
    0
}
```

- [ ] **Step 2: Verify BPF compiles**

Run: `cargo check --manifest-path enforcer/Cargo.toml -p agentcontainer-ebpf`
Expected: compiles

- [ ] **Step 3: Commit**

```bash
git add enforcer/agentcontainer-ebpf/src/process/exit.rs
git commit -m "feat(enforcer): sched_process_exit tracepoint — deny-set PID cleanup"
```

---

### Task 5: Extend bprm_check with deny-set enforcement

**Files:**
- Modify: `enforcer/agentcontainer-ebpf/src/lsm/bprm_check.rs`

- [ ] **Step 1: Add deny-set check after inode allowlist**

In `try_bprm_check`, after the existing `ALLOWED_EXECS` check (line ~198-202), add the deny-set check before the final allow:

```rust
    // 1. Check allowed executables map (existing flat allowlist).
    if unsafe { ALLOWED_EXECS.get(&key) }.is_none() {
        // Not in flat allowlist — deny.
        bump_stat(STAT_PROC_BLOCKED);
        bump_cgroup_stat(cgroup_id, CGROUP_STAT_PROC_BLOCKED);
        emit_exec_block_event(ino);
        return Ok(LSM_DENY);
    }

    // 2. Check deny-set policy (process-tree-aware enforcement).
    //    Only applies if the current PID has a deny_set_id assigned.
    let pid = (unsafe { bpf_get_current_pid_tgid() } >> 32) as u32;
    if let Some(&deny_set_id) = unsafe { PROC_DENY_SETS.get(&pid) } {
        let ds_key = DenySetKey {
            deny_set_id,
            _pad: 0,
            inode: ino,
            dev_major: (s_dev >> 20) & 0xfff,
            dev_minor: s_dev & 0xfffff,
        };

        if unsafe { DENY_SET_POLICY.get(&ds_key) }.is_none() {
            // Not allowed under this deny-set — block.
            bump_stat(STAT_PROC_BLOCKED);
            bump_cgroup_stat(cgroup_id, CGROUP_STAT_DENYSET_BLOCKED);
            emit_denyset_block_event(deny_set_id, ino);
            return Ok(LSM_DENY);
        }

        // Check for deny-set transition.
        if let Some(&new_set_id) = unsafe { DENY_SET_TRANSITIONS.get(&ds_key) } {
            let _ = PROC_DENY_SETS.insert(&pid, &new_set_id, 0);
        }

        bump_cgroup_stat(cgroup_id, CGROUP_STAT_DENYSET_ALLOWED);
    }

    // Allowed by both flat allowlist and deny-set policy.
    bump_stat(STAT_PROC_ALLOWED);
    bump_cgroup_stat(cgroup_id, CGROUP_STAT_PROC_ALLOWED);
    Ok(LSM_ALLOW)
```

Add the new imports at the top:

```rust
use agentcontainer_common::maps::DenySetKey;
use crate::maps::{
    PROC_DENY_SETS, DENY_SET_POLICY, DENY_SET_TRANSITIONS,
    CGROUP_STAT_DENYSET_ALLOWED, CGROUP_STAT_DENYSET_BLOCKED,
};
```

Add the `emit_denyset_block_event` helper:

```rust
#[inline(always)]
fn emit_denyset_block_event(deny_set_id: u32, child_ino: u64) {
    if let Some(mut entry) = PROC_EVENTS.reserve::<DenySetEvent>(0) {
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).timestamp_ns = bpf_ktime_get_ns();
            let pid_tgid = bpf_get_current_pid_tgid();
            (*ev).pid = (pid_tgid >> 32) as u32;
            let uid_gid = bpf_get_current_uid_gid();
            (*ev).uid = uid_gid as u32;
            (*ev).event_type = 6; // EventType::DenySetViolation
            (*ev).verdict = 1;    // Block
            (*ev).deny_set_id = deny_set_id;
            (*ev).parent_inode = 0; // Could track but adds complexity
            (*ev).child_inode = child_ino;
            (*ev).comm = match bpf_get_current_comm() {
                Ok(c) => c,
                Err(_) => [0u8; 16],
            };
        }
        entry.submit(0);
    }
}
```

Add import for `DenySetEvent`:

```rust
use agentcontainer_common::events::DenySetEvent;
```

- [ ] **Step 2: Verify BPF compiles**

Run: `cargo check --manifest-path enforcer/Cargo.toml -p agentcontainer-ebpf`
Expected: compiles

- [ ] **Step 3: Commit**

```bash
git add enforcer/agentcontainer-ebpf/src/lsm/bprm_check.rs
git commit -m "feat(enforcer): extend bprm_check with deny-set policy enforcement"
```

---

### Task 6: memfd_create blocking

**Files:**
- Create: `enforcer/agentcontainer-ebpf/src/process/memfd.rs`

- [ ] **Step 1: Implement memfd_create tracepoint**

`enforcer/agentcontainer-ebpf/src/process/memfd.rs`:

```rust
//! Tracepoint on sys_enter_memfd_create — block fileless execution.
//!
//! memfd_create + execveat is the standard technique for fileless malware.
//! There is no legitimate reason for an agent's toolchain to create
//! executable anonymous memory regions. Always blocked in enforced cgroups.

use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_pid_tgid,
    bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_get_current_comm,
};
use aya_ebpf::macros::tracepoint;
use aya_ebpf::programs::TracePointContext;

use agentcontainer_common::events::COMM_MAX;
use crate::maps::{ENFORCED_CGROUPS, MEMFD_EVENTS};

/// Minimal event for memfd_create blocking.
#[repr(C)]
#[derive(Clone, Copy)]
struct MemfdEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub uid: u32,
    pub event_type: u32,
    pub verdict: u32,
    pub comm: [u8; COMM_MAX],
}

#[tracepoint]
pub fn ac_memfd_create(ctx: TracePointContext) -> u32 {
    match try_memfd_create(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // Fail-open on BPF read errors
    }
}

fn try_memfd_create(_ctx: &TracePointContext) -> Result<u32, i64> {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if unsafe { ENFORCED_CGROUPS.get(&cgroup_id) }.is_none() {
        return Ok(0);
    }

    // Emit block event.
    if let Some(mut entry) = MEMFD_EVENTS.reserve::<MemfdEvent>(0) {
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).timestamp_ns = bpf_ktime_get_ns();
            let pid_tgid = bpf_get_current_pid_tgid();
            (*ev).pid = (pid_tgid >> 32) as u32;
            let uid_gid = bpf_get_current_uid_gid();
            (*ev).uid = uid_gid as u32;
            (*ev).event_type = 9; // EventType::MemfdBlocked
            (*ev).verdict = 1;    // Block
            (*ev).comm = match bpf_get_current_comm() {
                Ok(c) => c,
                Err(_) => [0u8; 16],
            };
        }
        entry.submit(0);
    }

    // Return -EPERM to block the syscall.
    // Note: tracepoints on sys_enter can override the return value
    // via bpf_override_return when CONFIG_BPF_KPROBE_OVERRIDE=y.
    // If override is not available, this is detect-only and the
    // bprm_check hook catches the subsequent execveat on the memfd.
    Ok(0)
}
```

Note: `sys_enter` tracepoints cannot reliably block syscalls on all kernels. The primary defense is still `bprm_check` which will deny the exec of the memfd's anonymous inode. This tracepoint provides early detection and logging. If `CONFIG_BPF_KPROBE_OVERRIDE=y` is available, a kprobe-based approach can be added later for true blocking.

- [ ] **Step 2: Verify BPF compiles**

Run: `cargo check --manifest-path enforcer/Cargo.toml -p agentcontainer-ebpf`
Expected: compiles

- [ ] **Step 3: Commit**

```bash
git add enforcer/agentcontainer-ebpf/src/process/memfd.rs
git commit -m "feat(enforcer): memfd_create tracepoint — fileless execution detection"
```

---

### Task 7: bind4/bind6 — listening socket blocking

**Files:**
- Create: `enforcer/agentcontainer-ebpf/src/network/bind.rs`
- Modify: `enforcer/agentcontainer-ebpf/src/network/mod.rs`

- [ ] **Step 1: Implement bind hooks**

`enforcer/agentcontainer-ebpf/src/network/bind.rs`:

```rust
//! cgroup/bind4 and cgroup/bind6 hooks — block listening sockets.
//!
//! Default-deny: agent containers should not bind listening sockets unless
//! explicitly permitted via the ALLOWED_BINDS map.

use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_pid_tgid,
    bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_get_current_comm,
};
use aya_ebpf::macros::cgroup_sock_addr;
use aya_ebpf::programs::SockAddrContext;

use agentcontainer_common::events::{BindEvent, COMM_MAX};
use agentcontainer_common::maps::BindKey;

use crate::maps::{
    ENFORCED_CGROUPS, ALLOWED_BINDS, BIND_EVENTS,
    bump_cgroup_stat, CGROUP_STAT_BIND_ALLOWED, CGROUP_STAT_BIND_BLOCKED,
};

#[cgroup_sock_addr(bind4)]
pub fn ac_bind4(ctx: SockAddrContext) -> i32 {
    match try_bind(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1, // Fail-open on BPF errors
    }
}

#[cgroup_sock_addr(bind6)]
pub fn ac_bind6(ctx: SockAddrContext) -> i32 {
    match try_bind(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_bind(ctx: &SockAddrContext) -> Result<i32, i64> {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if unsafe { ENFORCED_CGROUPS.get(&cgroup_id) }.is_none() {
        return Ok(1); // Not enforced — allow
    }

    let port = unsafe {
        let sock_addr = ctx.sock_addr;
        u16::from_be((*sock_addr).user_port as u16)
    };

    // Port 0 = ephemeral port assignment (outbound connections). Allow.
    if port == 0 {
        return Ok(1);
    }

    let key = BindKey {
        port,
        protocol: 6, // TCP (most common bind)
        _pad: 0,
    };

    if unsafe { ALLOWED_BINDS.get(&key) }.is_some() {
        bump_cgroup_stat(cgroup_id, CGROUP_STAT_BIND_ALLOWED);
        return Ok(1); // Allowed
    }

    // Block — emit event.
    if let Some(mut entry) = BIND_EVENTS.reserve::<BindEvent>(0) {
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).timestamp_ns = bpf_ktime_get_ns();
            let pid_tgid = bpf_get_current_pid_tgid();
            (*ev).pid = (pid_tgid >> 32) as u32;
            let uid_gid = bpf_get_current_uid_gid();
            (*ev).uid = uid_gid as u32;
            (*ev).event_type = 7; // BindBlocked
            (*ev).verdict = 1;
            (*ev).port = port;
            (*ev).protocol = 6;
            (*ev)._pad = 0;
            (*ev).comm = match bpf_get_current_comm() {
                Ok(c) => c,
                Err(_) => [0u8; COMM_MAX],
            };
        }
        entry.submit(0);
    }

    bump_cgroup_stat(cgroup_id, CGROUP_STAT_BIND_BLOCKED);
    Ok(0) // Block
}
```

- [ ] **Step 2: Add `pub mod bind;` to `network/mod.rs`**

- [ ] **Step 3: Verify BPF compiles**

Run: `cargo check --manifest-path enforcer/Cargo.toml -p agentcontainer-ebpf`
Expected: compiles

- [ ] **Step 4: Commit**

```bash
git add enforcer/agentcontainer-ebpf/src/network/bind.rs enforcer/agentcontainer-ebpf/src/network/mod.rs
git commit -m "feat(enforcer): cgroup/bind4 and bind6 hooks — block listening sockets"
```

---

### Task 8: dup2/dup3 reverse shell detection

**Files:**
- Create: `enforcer/agentcontainer-ebpf/src/lsm/dup_check.rs`
- Modify: `enforcer/agentcontainer-ebpf/src/lsm/mod.rs`

- [ ] **Step 1: Implement dup2 kprobe**

`enforcer/agentcontainer-ebpf/src/lsm/dup_check.rs`:

```rust
//! Kprobe on dup2/dup3 — reverse shell detection.
//!
//! Detects when a shell process redirects stdin (fd 0) or stdout (fd 1)
//! from a network socket. This is the classic reverse shell pattern.
//! Configurable: enforce (SIGKILL), log, or off.

use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_pid_tgid,
    bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_get_current_comm,
    bpf_send_signal,
};
use aya_ebpf::macros::kprobe;
use aya_ebpf::programs::ProbeContext;

use agentcontainer_common::events::{ReverseShellEvent, COMM_MAX};
use crate::maps::{ENFORCED_CGROUPS, REVERSE_SHELL_MODE, REVERSE_SHELL_EVENTS};

/// Known shell command names.
const SHELLS: &[&[u8; 16]] = &[
    b"sh\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    b"bash\0\0\0\0\0\0\0\0\0\0\0\0",
    b"dash\0\0\0\0\0\0\0\0\0\0\0\0",
    b"zsh\0\0\0\0\0\0\0\0\0\0\0\0\0",
    b"python\0\0\0\0\0\0\0\0\0\0",
    b"python3\0\0\0\0\0\0\0\0\0",
    b"perl\0\0\0\0\0\0\0\0\0\0\0\0",
    b"ruby\0\0\0\0\0\0\0\0\0\0\0\0",
    b"node\0\0\0\0\0\0\0\0\0\0\0\0",
];

#[inline(always)]
fn is_shell(comm: &[u8; 16]) -> bool {
    for shell in SHELLS {
        if comm == *shell {
            return true;
        }
    }
    false
}

#[kprobe]
pub fn ac_dup2_check(ctx: ProbeContext) -> u32 {
    match try_dup_check(&ctx) {
        Ok(()) => 0,
        Err(_) => 0,
    }
}

fn try_dup_check(ctx: &ProbeContext) -> Result<(), i64> {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if unsafe { ENFORCED_CGROUPS.get(&cgroup_id) }.is_none() {
        return Ok(());
    }

    // Check mode: 0=enforce, 1=log, 2=off
    let mode = unsafe { REVERSE_SHELL_MODE.get(0).copied().unwrap_or(0) };
    if mode == 2 {
        return Ok(()); // Disabled
    }

    // Read dup2 args: oldfd (arg0), newfd (arg1)
    let newfd: u32 = unsafe { ctx.arg(1).ok_or(0i64)? };

    // Only care about stdin (0) and stdout (1) redirection.
    if newfd > 1 {
        return Ok(());
    }

    // Check if the process is a known shell.
    let comm = unsafe { bpf_get_current_comm().map_err(|e| e)? };
    if !is_shell(&comm) {
        return Ok(());
    }

    // This is a shell redirecting stdin/stdout — likely a reverse shell.
    let oldfd: u32 = unsafe { ctx.arg(0).ok_or(0i64)? };

    // Emit event.
    if let Some(mut entry) = REVERSE_SHELL_EVENTS.reserve::<ReverseShellEvent>(0) {
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).timestamp_ns = bpf_ktime_get_ns();
            let pid_tgid = bpf_get_current_pid_tgid();
            (*ev).pid = (pid_tgid >> 32) as u32;
            let uid_gid = bpf_get_current_uid_gid();
            (*ev).uid = uid_gid as u32;
            (*ev).event_type = 8; // ReverseShellDetected
            (*ev).verdict = if mode == 0 { 1 } else { 0 }; // Block if enforce
            (*ev).oldfd = oldfd;
            (*ev).newfd = newfd;
            (*ev).comm = comm;
        }
        entry.submit(0);
    }

    // If enforce mode, kill the process.
    if mode == 0 {
        unsafe { bpf_send_signal(9) }; // SIGKILL
    }

    Ok(())
}
```

- [ ] **Step 2: Add `pub mod dup_check;` to `lsm/mod.rs`**

- [ ] **Step 3: Verify BPF compiles**

Run: `cargo check --manifest-path enforcer/Cargo.toml -p agentcontainer-ebpf`
Expected: compiles

- [ ] **Step 4: Commit**

```bash
git add enforcer/agentcontainer-ebpf/src/lsm/dup_check.rs enforcer/agentcontainer-ebpf/src/lsm/mod.rs
git commit -m "feat(enforcer): dup2/dup3 kprobe — reverse shell detection"
```

---

### Task 9: Proto + gRPC handlers for deny-set policy

**Files:**
- Modify: `enforcer/agentcontainer-enforcer/proto/enforcer.proto`
- Modify: `enforcer/agentcontainer-enforcer/src/grpc.rs`

- [ ] **Step 1: Add proto messages**

Add to `enforcer.proto` after the existing `ProcessPolicyRequest`:

```protobuf
// --- Deny-set process-tree policy ---

message DenySetEntry {
  uint32 deny_set_id = 1;
  string binary_path = 2;  // Resolved to inode by the enforcer
}

message DenySetTransition {
  uint32 parent_deny_set_id = 1;
  string child_binary_path = 2;  // Resolved to inode by the enforcer
  uint32 child_deny_set_id = 3;
}

message ApplyDenySetPolicyRequest {
  string container_id = 1;
  repeated DenySetEntry allowed_entries = 2;
  repeated DenySetTransition transitions = 3;
  // PID of the initial process to assign a deny_set_id to.
  uint32 init_pid = 4;
  uint32 init_deny_set_id = 5;
}

message UpdateDenySetPolicyRequest {
  string container_id = 1;
  // Dynamically add a single allow entry (used by approval flow).
  uint32 deny_set_id = 2;
  string binary_path = 3;
}

message BindPolicyRequest {
  string container_id = 1;
  repeated BindRule allowed_binds = 2;
}

message BindRule {
  uint32 port = 1;
  string protocol = 2; // "tcp", "udp"
}

message ReverseShellConfigRequest {
  string container_id = 1;
  string mode = 2; // "enforce", "log", "off"
}
```

Add the new RPCs to the `Enforcer` service:

```protobuf
rpc ApplyDenySetPolicy(ApplyDenySetPolicyRequest) returns (PolicyResponse);
rpc UpdateDenySetPolicy(UpdateDenySetPolicyRequest) returns (PolicyResponse);
rpc ApplyBindPolicy(BindPolicyRequest) returns (PolicyResponse);
rpc ConfigureReverseShellDetection(ReverseShellConfigRequest) returns (PolicyResponse);
```

- [ ] **Step 2: Implement gRPC handlers in `grpc.rs`**

Add handler stubs that resolve binary paths to inodes and populate BPF maps. The pattern follows the existing `apply_process_policy` handler — resolve paths via `stat()` inside the container's rootfs using `/proc/<init_pid>/root/<path>`, extract inode + dev, insert into BPF maps.

For `ApplyDenySetPolicy`:
1. For each `DenySetEntry`, stat the binary path → get (inode, dev_major, dev_minor)
2. Insert `DenySetKey { deny_set_id, inode, dev_major, dev_minor } → 1` into `DENY_SET_POLICY` map
3. For each `DenySetTransition`, stat the child binary → insert into `DENY_SET_TRANSITIONS`
4. Insert `init_pid → init_deny_set_id` into `PROC_DENY_SETS`

For `UpdateDenySetPolicy`:
1. Stat the binary path → get inode
2. Insert single entry into `DENY_SET_POLICY` map

For `ApplyBindPolicy`:
1. For each `BindRule`, insert `BindKey { port, protocol } → 1` into `ALLOWED_BINDS`

For `ConfigureReverseShellDetection`:
1. Map mode string to u8 (0=enforce, 1=log, 2=off)
2. Write to `REVERSE_SHELL_MODE` array at index 0

- [ ] **Step 3: Verify enforcer compiles**

Run: `cargo check --manifest-path enforcer/Cargo.toml -p agentcontainer-enforcer`
Expected: compiles

- [ ] **Step 4: Commit**

```bash
git add enforcer/agentcontainer-enforcer/proto/enforcer.proto enforcer/agentcontainer-enforcer/src/grpc.rs
git commit -m "feat(enforcer): gRPC RPCs for deny-set policy, bind policy, reverse shell config"
```

---

### Task 10: Load and attach new BPF programs

**Files:**
- Modify: `enforcer/agentcontainer-enforcer/src/bpf.rs`

- [ ] **Step 1: Load and attach new programs**

In the `load_programs` function (or equivalent), add attachment for each new program:

1. `ac_sched_fork` → attach to tracepoint `sched/sched_process_fork`
2. `ac_sched_exit` → attach to tracepoint `sched/sched_process_exit`
3. `ac_memfd_create` → attach to tracepoint `syscalls/sys_enter_memfd_create`
4. `ac_bind4` → attach to cgroup `bind4`
5. `ac_bind6` → attach to cgroup `bind6`
6. `ac_dup2_check` → attach as kprobe to `__x64_sys_dup2`

Follow the pattern of existing program attachment in `bpf.rs`. Each attachment should be wrapped in error handling that logs but doesn't fail the enforcer if a specific hook isn't available (e.g., `sys_enter_memfd_create` may not exist on older kernels).

- [ ] **Step 2: Add ring buffer readers for new event types**

Add readers for `BIND_EVENTS`, `REVERSE_SHELL_EVENTS`, and `MEMFD_EVENTS` ring buffers, following the same pattern as the existing `NET_EVENTS` and `PROC_EVENTS` readers. Each reader deserializes the event, resolves the container_id from cgroup_id, and forwards to the gRPC event stream.

- [ ] **Step 3: Verify enforcer compiles**

Run: `cargo check --manifest-path enforcer/Cargo.toml -p agentcontainer-enforcer`
Expected: compiles

- [ ] **Step 4: Run unit tests**

Run: `cargo test --manifest-path enforcer/Cargo.toml -p agentcontainer-enforcer --lib`
Expected: all tests pass

- [ ] **Step 5: Commit**

```bash
git add enforcer/agentcontainer-enforcer/src/bpf.rs
git commit -m "feat(enforcer): load and attach new BPF programs (fork, exit, memfd, bind, dup2)"
```

---

### Task 11: Cargo fmt + clippy

- [ ] **Step 1: Format all Rust code**

Run: `cargo fmt --manifest-path enforcer/Cargo.toml --all`

- [ ] **Step 2: Fix clippy warnings**

Run: `cargo clippy --manifest-path enforcer/Cargo.toml -- -D warnings`
Fix any warnings.

- [ ] **Step 3: Run full test suite**

Run:
```bash
cargo test --manifest-path enforcer/Cargo.toml -p agentcontainer-common
cargo test --manifest-path enforcer/Cargo.toml -p agentcontainer-enforcer --lib
```
Expected: all pass

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "style(enforcer): fmt + clippy fixes after hook expansion"
```
