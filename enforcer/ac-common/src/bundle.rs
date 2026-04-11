//! Signed policy bundle types.
//!
//! A `PolicyBundle` is a JSON document that captures the maximum-permissible
//! policy for a container as agreed upon at session start (signed by the
//! agentcontainers CLI before the enforcer is launched).  The ac-enforcer
//! deserialises this bundle on startup and uses it as the authoritative
//! baseline: any subsequent `ApplyXxxPolicy` RPC that would grant *more*
//! permission than the bundle allows is rejected with `PermissionDenied`.
//!
//! The bundle does NOT need to be cryptographically verified inside the
//! enforcer itself — the CLI is responsible for producing a correct bundle.
//! Future work (M4-POLICY) will add signature verification here.
//!
//! ## Wire format
//!
//! ```json
//! {
//!   "network": {
//!     "allowed_hosts": ["api.example.com"],
//!     "egress_rules": [{"host": "db.internal", "port": 5432, "protocol": "tcp"}],
//!     "dns_servers": ["8.8.8.8"]
//!   },
//!   "filesystem": {
//!     "read_paths": ["/etc", "/usr"],
//!     "write_paths": ["/tmp"],
//!     "deny_paths": ["/etc/shadow"]
//!   },
//!   "process": {
//!     "allowed_binaries": ["/bin/sh", "/usr/bin/node"]
//!   },
//!   "credential": {
//!     "secret_acls": [
//!       {"path": "/run/secrets/token", "allowed_tools": ["curl"], "ttl_seconds": 3600}
//!     ]
//!   }
//! }
//! ```

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "user")]
use serde::{Deserialize, Serialize};

/// The maximum-permissible policy for a container session.
///
/// Loaded from `--policy-bundle` at enforcer startup.  Every
/// `ApplyXxxPolicy` RPC is validated against this baseline before being
/// forwarded to the BPF enforcement layer.
#[cfg(feature = "user")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PolicyBundle {
    /// Maximum-permissible network egress policy.
    #[serde(default)]
    pub network: BundleNetworkPolicy,

    /// Maximum-permissible filesystem access policy.
    #[serde(default)]
    pub filesystem: BundleFilesystemPolicy,

    /// Maximum-permissible process execution policy.
    #[serde(default)]
    pub process: BundleProcessPolicy,

    /// Maximum-permissible credential access policy.
    #[serde(default)]
    pub credential: BundleCredentialPolicy,
}

#[cfg(feature = "user")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BundleNetworkPolicy {
    /// Hostnames allowed for outbound connections.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,

    /// Specific host:port:protocol egress rules.
    #[serde(default)]
    pub egress_rules: Vec<BundleEgressRule>,

    /// DNS server IPs (restrict DNS queries to these).
    #[serde(default)]
    pub dns_servers: Vec<String>,
}

#[cfg(feature = "user")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleEgressRule {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}

#[cfg(feature = "user")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BundleFilesystemPolicy {
    /// Paths allowed for read access.
    #[serde(default)]
    pub read_paths: Vec<String>,

    /// Paths allowed for read+write access.
    #[serde(default)]
    pub write_paths: Vec<String>,

    /// Paths explicitly denied (takes precedence over allow).
    #[serde(default)]
    pub deny_paths: Vec<String>,
}

#[cfg(feature = "user")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BundleProcessPolicy {
    /// Binary paths allowed for execution.
    #[serde(default)]
    pub allowed_binaries: Vec<String>,
}

#[cfg(feature = "user")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BundleCredentialPolicy {
    /// Per-secret ACL entries.
    #[serde(default)]
    pub secret_acls: Vec<BundleSecretAcl>,
}

#[cfg(feature = "user")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BundleSecretAcl {
    /// Path to the secret file inside the container.
    pub path: String,
    /// Tool/binary names allowed to read this secret.
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    /// Time-to-live in seconds (0 = no expiry).
    #[serde(default)]
    pub ttl_seconds: u64,
}

#[cfg(feature = "user")]
impl PolicyBundle {
    /// Deserialise a `PolicyBundle` from a JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialise this bundle to a JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("PolicyBundle serialization is infallible")
    }

    /// Returns `true` if the proposed network policy is at most as permissive
    /// as this bundle allows.  A policy is more permissive if it requests hosts
    /// or egress rules not in the bundle.
    pub fn allows_network(
        &self,
        allowed_hosts: &[String],
        egress_rules: &[BundleEgressRule],
    ) -> bool {
        for host in allowed_hosts {
            if !self.network.allowed_hosts.iter().any(|h| h == host) {
                return false;
            }
        }
        for rule in egress_rules {
            if !self.network.egress_rules.iter().any(|r| r == rule) {
                return false;
            }
        }
        true
    }

    /// Returns `true` if the proposed filesystem policy is at most as
    /// permissive as this bundle allows.
    pub fn allows_filesystem(&self, read_paths: &[String], write_paths: &[String]) -> bool {
        for p in read_paths {
            if !self.filesystem.read_paths.iter().any(|r| r == p)
                && !self.filesystem.write_paths.iter().any(|r| r == p)
            {
                return false;
            }
        }
        for p in write_paths {
            if !self.filesystem.write_paths.iter().any(|r| r == p) {
                return false;
            }
        }
        true
    }

    /// Returns `true` if all proposed binaries are in the bundle's allowlist.
    pub fn allows_process(&self, allowed_binaries: &[String]) -> bool {
        for bin in allowed_binaries {
            if !self.process.allowed_binaries.iter().any(|b| b == bin) {
                return false;
            }
        }
        true
    }

    /// Returns `true` if each proposed secret ACL is present in the bundle
    /// (matched by path) and does not expand the tool list or TTL beyond
    /// what the bundle permits.
    pub fn allows_credential(&self, secret_acls: &[BundleSecretAcl]) -> bool {
        for acl in secret_acls {
            match self
                .credential
                .secret_acls
                .iter()
                .find(|b| b.path == acl.path)
            {
                None => return false,
                Some(bundle_acl) => {
                    for tool in &acl.allowed_tools {
                        if !bundle_acl.allowed_tools.iter().any(|t| t == tool) {
                            return false;
                        }
                    }
                    // ttl_seconds 0 means no expiry; a shorter TTL is fine, longer is not.
                    if bundle_acl.ttl_seconds != 0
                        && (acl.ttl_seconds == 0 || acl.ttl_seconds > bundle_acl.ttl_seconds)
                    {
                        return false;
                    }
                }
            }
        }
        true
    }
}

#[cfg(test)]
#[cfg(feature = "user")]
mod tests {
    use super::*;

    fn sample_bundle() -> PolicyBundle {
        PolicyBundle {
            network: BundleNetworkPolicy {
                allowed_hosts: vec!["api.example.com".into()],
                egress_rules: vec![BundleEgressRule {
                    host: "db.internal".into(),
                    port: 5432,
                    protocol: "tcp".into(),
                }],
                dns_servers: vec!["8.8.8.8".into()],
            },
            filesystem: BundleFilesystemPolicy {
                read_paths: vec!["/etc".into(), "/usr".into()],
                write_paths: vec!["/tmp".into()],
                deny_paths: vec!["/etc/shadow".into()],
            },
            process: BundleProcessPolicy {
                allowed_binaries: vec!["/bin/sh".into(), "/usr/bin/node".into()],
            },
            credential: BundleCredentialPolicy {
                secret_acls: vec![BundleSecretAcl {
                    path: "/run/secrets/token".into(),
                    allowed_tools: vec!["curl".into()],
                    ttl_seconds: 3600,
                }],
            },
        }
    }

    #[test]
    fn test_roundtrip_json() {
        let bundle = sample_bundle();
        let json = bundle.to_json();
        let parsed = PolicyBundle::from_json(&json).expect("parse failed");
        assert_eq!(parsed.network.allowed_hosts, bundle.network.allowed_hosts);
        assert_eq!(parsed.filesystem.read_paths, bundle.filesystem.read_paths);
        assert_eq!(
            parsed.process.allowed_binaries,
            bundle.process.allowed_binaries
        );
    }

    #[test]
    fn test_allows_network_exact() {
        let bundle = sample_bundle();
        // Exact match should pass.
        assert!(bundle.allows_network(
            &["api.example.com".to_string()],
            &[BundleEgressRule {
                host: "db.internal".into(),
                port: 5432,
                protocol: "tcp".into()
            }],
        ));
    }

    #[test]
    fn test_allows_network_unknown_host() {
        let bundle = sample_bundle();
        assert!(!bundle.allows_network(&["evil.example.com".to_string()], &[],));
    }

    #[test]
    fn test_allows_filesystem_read_subset() {
        let bundle = sample_bundle();
        // Requesting a subset is fine.
        assert!(bundle.allows_filesystem(&["/etc".to_string()], &[]));
    }

    #[test]
    fn test_allows_filesystem_extra_read() {
        let bundle = sample_bundle();
        assert!(!bundle.allows_filesystem(&["/root".to_string()], &[]));
    }

    #[test]
    fn test_allows_process_allowed() {
        let bundle = sample_bundle();
        assert!(bundle.allows_process(&["/bin/sh".to_string()]));
    }

    #[test]
    fn test_allows_process_denied() {
        let bundle = sample_bundle();
        assert!(!bundle.allows_process(&["/usr/bin/wget".to_string()]));
    }

    #[test]
    fn test_allows_credential_valid() {
        let bundle = sample_bundle();
        assert!(bundle.allows_credential(&[BundleSecretAcl {
            path: "/run/secrets/token".into(),
            allowed_tools: vec!["curl".into()],
            ttl_seconds: 1800, // shorter TTL — fine
        }]));
    }

    #[test]
    fn test_allows_credential_extra_tool() {
        let bundle = sample_bundle();
        assert!(!bundle.allows_credential(&[BundleSecretAcl {
            path: "/run/secrets/token".into(),
            allowed_tools: vec!["curl".into(), "wget".into()],
            ttl_seconds: 3600,
        }]));
    }

    #[test]
    fn test_allows_credential_unknown_path() {
        let bundle = sample_bundle();
        assert!(!bundle.allows_credential(&[BundleSecretAcl {
            path: "/run/secrets/other".into(),
            allowed_tools: vec![],
            ttl_seconds: 0,
        }]));
    }

    #[test]
    fn test_allows_credential_longer_ttl() {
        let bundle = sample_bundle();
        // bundle allows 3600s, requesting 7200s is MORE permissive — reject
        assert!(!bundle.allows_credential(&[BundleSecretAcl {
            path: "/run/secrets/token".into(),
            allowed_tools: vec!["curl".into()],
            ttl_seconds: 7200,
        }]));
    }

    #[test]
    fn test_allows_credential_no_expiry_when_bundle_requires() {
        let bundle = sample_bundle();
        // bundle has ttl_seconds=3600, requesting 0 (no expiry) is more permissive — reject
        assert!(!bundle.allows_credential(&[BundleSecretAcl {
            path: "/run/secrets/token".into(),
            allowed_tools: vec!["curl".into()],
            ttl_seconds: 0,
        }]));
    }

    #[test]
    fn test_empty_bundle_allows_nothing() {
        let bundle = PolicyBundle::default();
        assert!(!bundle.allows_network(&["any.host".to_string()], &[]));
        assert!(!bundle.allows_filesystem(&["/etc".to_string()], &[]));
        assert!(!bundle.allows_process(&["/bin/sh".to_string()]));
    }

    #[test]
    fn test_empty_requests_always_allowed() {
        let bundle = PolicyBundle::default();
        // Empty requests are vacuously permissive — always allowed.
        assert!(bundle.allows_network(&[], &[]));
        assert!(bundle.allows_filesystem(&[], &[]));
        assert!(bundle.allows_process(&[]));
        assert!(bundle.allows_credential(&[]));
    }
}
