//! LSM (Linux Security Module) BPF programs.
//!
//! - `file_open`: Filesystem access control via inode allow/deny lists
//! - `bprm_check`: Process execution control via binary allowlist

pub mod bprm_check;
pub mod file_open;
