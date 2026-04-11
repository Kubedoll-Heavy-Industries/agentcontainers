//! Shared types for agentcontainers BPF enforcement.
//!
//! This crate is `no_std` compatible so it can be used in both BPF programs
//! (`ac-ebpf`) and the userspace enforcer (`ac-enforcer`). Types defined here
//! are the single source of truth for map keys, event structs, and policy
//! specs — no codegen, no manual struct matching.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod bundle;
pub mod events;
pub mod helpers;
pub mod maps;
pub mod policy;
pub mod siphash;
