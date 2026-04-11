//! LSM bprm_check_security hook for process execution enforcement.
//!
//! Intercepts execve() and checks the binary's inode against an allowlist:
//! 0. Check cgroup scoping -- skip non-enforced cgroups.
//! 1. Read executable inode from linux_binprm->file->f_path.dentry->d_inode.
//! 2. Check allowed executables map -- allow if inode is present.
//! 3. Default deny -- block, emit ExecEvent to ring buffer.
//!
//! Ported from C implementation in internal/ebpf/bpf/lsm/bprm_check.c.

use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
    bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel,
};
use aya_ebpf::macros::lsm;
use aya_ebpf::programs::LsmContext;

use ac_common::events::{ExecEvent, STAT_PROC_ALLOWED, STAT_PROC_BLOCKED};
use ac_common::maps::{FsInodeKey, LSM_ALLOW, LSM_DENY};

use crate::maps::{
    bump_cgroup_stat, ALLOWED_EXECS, CGROUP_STAT_PROC_ALLOWED, CGROUP_STAT_PROC_BLOCKED,
    ENFORCED_CGROUPS, PROC_EVENTS, PROC_STATS,
};

// ---------------------------------------------------------------------------
// Kernel struct definitions for reading linux_binprm fields via bpf_probe_read_kernel.
// These must match the kernel's in-memory layout.
// ---------------------------------------------------------------------------

#[repr(C)]
struct LinuxBinprm {
    file: *const File,
}

#[repr(C)]
struct File {
    f_path: Path,
}

#[repr(C)]
struct Path {
    mnt: *const u8,
    dentry: *const Dentry,
}

#[repr(C)]
struct Dentry {
    d_inode: *const Inode,
}

#[repr(C)]
struct Inode {
    i_ino: u64,
    i_sb: *const SuperBlock,
}

#[repr(C)]
struct SuperBlock {
    s_dev: u32,
}

// ---------------------------------------------------------------------------
// Inline helpers
// ---------------------------------------------------------------------------

/// Bump a per-CPU stats counter by index.
#[inline(always)]
fn bump_stat(idx: u32) {
    unsafe {
        if let Some(val) = PROC_STATS.get_ptr_mut(idx) {
            *val += 1;
        }
    }
}

/// Check if the current cgroup is enforced. Returns Some(cgroup_id) if enforcement applies.
#[inline(always)]
fn get_enforced_cgroup() -> Option<u64> {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if unsafe { ENFORCED_CGROUPS.get(&cgroup_id) }.is_some() {
        Some(cgroup_id)
    } else {
        None
    }
}

/// Emit a block event for a denied process execution to the PROC_EVENTS ring buffer.
#[inline(always)]
fn emit_exec_block_event(ino: u64) {
    if let Some(mut entry) = PROC_EVENTS.reserve::<ExecEvent>(0) {
        let ev = entry.as_mut_ptr();
        unsafe {
            (*ev).timestamp_ns = bpf_ktime_get_ns();

            let pid_tgid = bpf_get_current_pid_tgid();
            (*ev).pid = (pid_tgid >> 32) as u32;

            let uid_gid = bpf_get_current_uid_gid();
            (*ev).uid = uid_gid as u32;

            (*ev).event_type = 4; // EventType::ProcessExec
            (*ev).verdict = 1; // Verdict::Block

            (*ev).inode = ino;

            // Zero out variable-length fields before populating.
            (*ev).binary = [0u8; 256];

            (*ev).comm = match bpf_get_current_comm() {
                Ok(c) => c,
                Err(_) => [0u8; 16],
            };
        }
        entry.submit(0);
    }
}

// ---------------------------------------------------------------------------
// lsm/bprm_check_security -- intercepts process execution (execve).
// ---------------------------------------------------------------------------

#[lsm(hook = "bprm_check_security")]
pub fn ac_bprm_check(ctx: LsmContext) -> i32 {
    match try_bprm_check(&ctx) {
        Ok(ret) => ret,
        Err(_) => LSM_ALLOW, // Fail-open on BPF read errors (match C behavior)
    }
}

fn try_bprm_check(ctx: &LsmContext) -> Result<i32, i64> {
    // 0. Cgroup scoping: only enforce for processes in target containers.
    //    LSM hooks are system-wide; skip all non-container processes.
    let cgroup_id = match get_enforced_cgroup() {
        Some(id) => id,
        None => return Ok(LSM_ALLOW),
    };

    // Read the linux_binprm pointer from the LSM hook's first argument.
    let bprm_ptr: *const LinuxBinprm = unsafe { ctx.arg(0) };

    // Read the executable file pointer from linux_binprm.
    let file_ptr: *const File =
        unsafe { bpf_probe_read_kernel(&(*bprm_ptr).file as *const _ as *const _).map_err(|e| e)? };
    if file_ptr.is_null() {
        bump_stat(STAT_PROC_ALLOWED);
        bump_cgroup_stat(cgroup_id, CGROUP_STAT_PROC_ALLOWED);
        return Ok(LSM_ALLOW);
    }

    // Read the dentry pointer from file->f_path.dentry.
    let dentry_ptr: *const Dentry = unsafe {
        bpf_probe_read_kernel(&(*file_ptr).f_path.dentry as *const _ as *const _).map_err(|e| e)?
    };
    if dentry_ptr.is_null() {
        bump_stat(STAT_PROC_ALLOWED);
        bump_cgroup_stat(cgroup_id, CGROUP_STAT_PROC_ALLOWED);
        return Ok(LSM_ALLOW);
    }

    // Read the inode pointer from dentry->d_inode.
    let inode_ptr: *const Inode = unsafe {
        bpf_probe_read_kernel(&(*dentry_ptr).d_inode as *const _ as *const _).map_err(|e| e)?
    };
    if inode_ptr.is_null() {
        bump_stat(STAT_PROC_ALLOWED);
        bump_cgroup_stat(cgroup_id, CGROUP_STAT_PROC_ALLOWED);
        return Ok(LSM_ALLOW);
    }

    // Read the inode number.
    let ino: u64 = unsafe {
        bpf_probe_read_kernel(&(*inode_ptr).i_ino as *const _ as *const _).map_err(|e| e)?
    };

    // Read the superblock pointer to get the device number.
    let sb_ptr: *const SuperBlock = unsafe {
        bpf_probe_read_kernel(&(*inode_ptr).i_sb as *const _ as *const _).map_err(|e| e)?
    };
    if sb_ptr.is_null() {
        bump_stat(STAT_PROC_ALLOWED);
        bump_cgroup_stat(cgroup_id, CGROUP_STAT_PROC_ALLOWED);
        return Ok(LSM_ALLOW);
    }

    let s_dev: u32 =
        unsafe { bpf_probe_read_kernel(&(*sb_ptr).s_dev as *const _ as *const _).map_err(|e| e)? };

    // Build lookup key with device major/minor numbers.
    // Linux dev_t: MAJOR = (dev >> 20) & 0xfff, MINOR = dev & 0xfffff.
    let key = FsInodeKey {
        inode: ino,
        dev_major: (s_dev >> 20) & 0xfff,
        dev_minor: s_dev & 0xfffff,
    };

    // 1. Check allowed executables map.
    if unsafe { ALLOWED_EXECS.get(&key) }.is_some() {
        bump_stat(STAT_PROC_ALLOWED);
        bump_cgroup_stat(cgroup_id, CGROUP_STAT_PROC_ALLOWED);
        return Ok(LSM_ALLOW);
    }

    // 2. Default deny -- block execution, emit audit event.
    bump_stat(STAT_PROC_BLOCKED);
    bump_cgroup_stat(cgroup_id, CGROUP_STAT_PROC_BLOCKED);
    emit_exec_block_event(ino);
    Ok(LSM_DENY)
}
