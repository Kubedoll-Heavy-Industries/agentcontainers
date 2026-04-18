//! Policy specification types.
//!
//! These types are used by the userspace enforcer to translate high-level
//! policy (from gRPC requests) into BPF map entries. They are NOT used in
//! BPF programs directly — BPF programs only see map keys and values from
//! the `maps` module.

// Policy types require std (String, Vec).
#![cfg_attr(not(feature = "std"), allow(dead_code))]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
use std::{string::String, vec::Vec};

/// Network egress policy for a single container.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Default)]
pub struct NetworkPolicy {
    /// Hostnames to resolve and allow (all ports).
    pub allowed_hosts: Vec<String>,
    /// Specific host:port:protocol rules.
    pub egress_rules: Vec<EgressRule>,
    /// DNS server IPs (restrict DNS queries to these).
    pub dns_servers: Vec<String>,
}

/// A specific egress rule with host, port, and protocol.
#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct EgressRule {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}

/// Filesystem access policy for a single container.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Default)]
pub struct FilesystemPolicy {
    /// Paths allowed for read access.
    pub read_paths: Vec<String>,
    /// Paths allowed for read+write access.
    pub write_paths: Vec<String>,
    /// Paths explicitly denied.
    pub deny_paths: Vec<String>,
}

/// Process execution policy for a single container.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Default)]
pub struct ProcessPolicy {
    /// Paths to binaries that are allowed to execute.
    pub allowed_binaries: Vec<String>,
}

/// Credential access policy for a single container.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Default)]
pub struct CredentialPolicy {
    /// Per-secret ACL entries.
    pub secret_acls: Vec<SecretAcl>,
}

/// Access control entry for a single secret file.
#[cfg(feature = "std")]
#[derive(Clone, Debug)]
pub struct SecretAcl {
    /// Path to the secret file.
    pub path: String,
    /// Tool/binary names allowed to read this secret.
    pub allowed_tools: Vec<String>,
    /// Time-to-live in seconds (0 = no expiry).
    pub ttl_seconds: u64,
}
