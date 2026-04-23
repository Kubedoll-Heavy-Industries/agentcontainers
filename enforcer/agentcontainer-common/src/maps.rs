//! BPF map key and value types shared between kernel and userspace.
//!
//! These types must have a stable memory layout (`repr(C)`) and match exactly
//! between the BPF programs and the userspace map operations.

// --- Network map keys ---

/// Key for IPv4 LPM trie (longest prefix match).
/// `prefixlen` MUST be the first field for BPF LPM trie compatibility.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LpmKeyV4 {
    pub prefixlen: u32,
    pub addr: u32,
}

/// Key for IPv6 LPM trie (longest prefix match).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LpmKeyV6 {
    pub prefixlen: u32,
    pub addr: [u32; 4],
}

/// Key for the allowed ports hash map (IPv4).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortKeyV4 {
    pub ip: u32,
    pub port: u16,
    pub protocol: u8,
    pub _pad: u8,
}

// --- Filesystem map keys ---

/// Key for the filesystem inode allow/deny maps.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsInodeKey {
    pub inode: u64,
    pub dev_major: u32,
    pub dev_minor: u32,
}

// --- Process deny-set map keys ---

/// Key for deny-set policy lookup: (deny_set_id, inode, dev).
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

// --- Credential map keys ---

/// Key for credential/secret ACL enforcement.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretAclKey {
    pub inode: u64,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub cgroup_id: u64,
}

/// Value for credential/secret ACL entries.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretAclValue {
    pub expires_at_ns: u64,
    pub allowed_ops: u8,
    pub _pad: [u8; 7],
}

// --- Permission constants ---

pub const FS_PERM_READ: u8 = 0x01;
pub const FS_PERM_WRITE: u8 = 0x02;

// --- Per-cgroup statistics ---

/// Per-cgroup enforcement statistics tracked in BPF per-CPU hash maps.
///
/// Each enforced cgroup gets one entry in the `CGROUP_STATS` per-CPU hash map.
/// BPF programs increment the relevant counter on each enforcement decision.
/// Userspace sums across CPUs to get totals.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CgroupStats {
    pub network_allowed: u64,
    pub network_blocked: u64,
    pub filesystem_allowed: u64,
    pub filesystem_blocked: u64,
    pub process_allowed: u64,
    pub process_blocked: u64,
    pub credential_allowed: u64,
    pub credential_blocked: u64,
    pub bind_allowed: u64,
    pub bind_blocked: u64,
    pub denyset_allowed: u64,
    pub denyset_blocked: u64,
}

// --- Verdicts ---

pub const VERDICT_ALLOW: i32 = 1;
pub const VERDICT_BLOCK: i32 = 0;

// --- LSM verdicts ---

pub const LSM_ALLOW: i32 = 0;
pub const LSM_DENY: i32 = -13; // -EACCES

// --- Procfs ---

pub const PROC_SUPER_MAGIC: u64 = 0x9fa0;
pub const DENTRY_NAME_LEN: usize = 32;

// --- aya Pod impls (userspace only) ---

// SAFETY: All types are #[repr(C)], Copy, and 'static — they satisfy Pod requirements.
// Pod is needed for aya's userspace HashMap/LpmTrie map operations.
#[cfg(target_os = "linux")]
mod pod_impls {
    unsafe impl aya::Pod for super::PortKeyV4 {}
    unsafe impl aya::Pod for super::FsInodeKey {}
    unsafe impl aya::Pod for super::SecretAclKey {}
    unsafe impl aya::Pod for super::SecretAclValue {}
    unsafe impl aya::Pod for super::LpmKeyV4 {}
    unsafe impl aya::Pod for super::LpmKeyV6 {}
    unsafe impl aya::Pod for super::CgroupStats {}
    unsafe impl aya::Pod for super::DenySetKey {}
    unsafe impl aya::Pod for super::BindKey {}
}
