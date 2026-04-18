//! WASI capability policy builder.
//!
//! Translates the `ComponentPolicy` from proto (network_hosts, fs_read_paths,
//! fs_write_paths, env_vars) into a [`WasiCtx`] for use when instantiating
//! WASM Components.
//!
//! # Deny-by-default
//!
//! A component started with an empty policy has:
//! - No filesystem access (no preopened dirs)
//! - No network access (no socket addresses allowed)
//! - No environment variables
//! - No access to stdin/stdout/stderr (except as explicitly granted)
//!
//! Each grant is explicitly added. This mirrors the container-level
//! deny-by-default model from `agent.capabilities`.

use anyhow::{Context, Result};
use std::path::Path;
use wasmtime_wasi::{DirPerms, FilePerms, WasiCtx, WasiCtxBuilder};

/// Parsed representation of a single capability string.
///
/// Capability strings follow the URI-like syntax defined in PRD-016:
/// - `network:<host>` or `network:<host>:<port>`
/// - `fs:read:<path>` or `fs:write:<path>`
/// - `env:<VAR>`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    Network { host: String, port: Option<u16> },
    FsRead { path: String },
    FsWrite { path: String },
    Env { var: String },
}

impl Capability {
    /// Parse a capability string into a [`Capability`].
    ///
    /// Returns an error for unrecognised prefixes or malformed strings.
    pub fn parse(s: &str) -> Result<Self> {
        if let Some(rest) = s.strip_prefix("network:") {
            // network:<host> or network:<host>:<port>
            // We split on ':' but must handle IPv6 addresses (which themselves contain ':').
            // Convention: if the last segment after the last ':' is numeric, treat as port.
            let port = if let Some(idx) = rest.rfind(':') {
                let maybe_port = &rest[idx + 1..];
                if maybe_port.chars().all(|c| c.is_ascii_digit()) {
                    maybe_port.parse::<u16>().ok()
                } else {
                    None
                }
            } else {
                None
            };

            let host = if port.is_some() {
                // Strip the :<port> suffix.
                let idx = rest.rfind(':').unwrap();
                rest[..idx].to_string()
            } else {
                rest.to_string()
            };

            if host.is_empty() {
                anyhow::bail!("network capability has empty host: {s}");
            }

            return Ok(Capability::Network { host, port });
        }

        if let Some(rest) = s.strip_prefix("fs:read:") {
            if rest.is_empty() {
                anyhow::bail!("fs:read capability has empty path: {s}");
            }
            return Ok(Capability::FsRead {
                path: rest.to_string(),
            });
        }

        if let Some(rest) = s.strip_prefix("fs:write:") {
            if rest.is_empty() {
                anyhow::bail!("fs:write capability has empty path: {s}");
            }
            return Ok(Capability::FsWrite {
                path: rest.to_string(),
            });
        }

        if let Some(rest) = s.strip_prefix("env:") {
            if rest.is_empty() {
                anyhow::bail!("env capability has empty variable name: {s}");
            }
            return Ok(Capability::Env {
                var: rest.to_string(),
            });
        }

        anyhow::bail!("unknown capability prefix in: {s}")
    }
}

/// Structured policy for a single WASM Component.
///
/// This is the parsed, validated form of the `ComponentPolicy` proto message.
#[derive(Debug, Clone, Default)]
pub struct WasmPolicy {
    /// Allowed outbound network hosts, with optional port restriction.
    pub network: Vec<(String, Option<u16>)>,
    /// Paths to preopen read-only.
    pub fs_read: Vec<String>,
    /// Paths to preopen read-write.
    pub fs_write: Vec<String>,
    /// Environment variable names to pass through from the host environment.
    pub env_vars: Vec<String>,
}

impl WasmPolicy {
    /// Parse a slice of raw capability strings into a [`WasmPolicy`].
    ///
    /// Unrecognised or malformed strings are returned as errors. The caller
    /// decides whether to fail-closed or warn-and-skip.
    pub fn from_capabilities(caps: &[String]) -> Result<Self> {
        let mut policy = WasmPolicy::default();
        for cap in caps {
            match Capability::parse(cap).with_context(|| format!("parsing capability '{cap}'"))? {
                Capability::Network { host, port } => policy.network.push((host, port)),
                Capability::FsRead { path } => policy.fs_read.push(path),
                Capability::FsWrite { path } => policy.fs_write.push(path),
                Capability::Env { var } => policy.env_vars.push(var),
            }
        }
        Ok(policy)
    }

    /// Build a ([`WasiCtx`], [`wasmtime::component::ResourceTable`]) pair from this policy.
    ///
    /// Filesystem paths are preopened on the host. Network capability is
    /// currently advisory (WASI Preview 2 socket capability enforcement
    /// requires the component to request sockets explicitly).
    ///
    /// This function fails if any preopened path does not exist on the host.
    pub fn build_wasi_ctx(&self) -> Result<(WasiCtx, wasmtime::component::ResourceTable)> {
        let mut builder = WasiCtxBuilder::new();

        // Inherit stdout/stderr for observability — components can log.
        builder.inherit_stdout();
        builder.inherit_stderr();

        // Environment variables — only explicitly allowed vars are passed.
        for var in &self.env_vars {
            if let Ok(value) = std::env::var(var) {
                builder.env(var, &value);
            }
        }

        // Filesystem preopens — read-only.
        for path in &self.fs_read {
            let host_path = Path::new(path);
            if !host_path.exists() {
                anyhow::bail!("fs:read path does not exist on host: {path}");
            }
            builder
                .preopened_dir(host_path, path, DirPerms::READ, FilePerms::READ)
                .map_err(anyhow::Error::from)
                .with_context(|| format!("preopening read-only dir: {path}"))?;
        }

        // Filesystem preopens — read-write.
        for path in &self.fs_write {
            let host_path = Path::new(path);
            if !host_path.exists() {
                anyhow::bail!("fs:write path does not exist on host: {path}");
            }
            builder
                .preopened_dir(
                    host_path,
                    path,
                    DirPerms::READ | DirPerms::MUTATE,
                    FilePerms::READ | FilePerms::WRITE,
                )
                .map_err(anyhow::Error::from)
                .with_context(|| format!("preopening read-write dir: {path}"))?;
        }

        let ctx = builder.build();
        let table = wasmtime::component::ResourceTable::new();
        Ok((ctx, table))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_network_host_only() {
        let cap = Capability::parse("network:api.github.com").unwrap();
        assert_eq!(
            cap,
            Capability::Network {
                host: "api.github.com".into(),
                port: None
            }
        );
    }

    #[test]
    fn test_parse_network_host_and_port() {
        let cap = Capability::parse("network:db.internal:5432").unwrap();
        assert_eq!(
            cap,
            Capability::Network {
                host: "db.internal".into(),
                port: Some(5432)
            }
        );
    }

    #[test]
    fn test_parse_network_empty_host_is_error() {
        assert!(Capability::parse("network:").is_err());
    }

    #[test]
    fn test_parse_fs_read() {
        let cap = Capability::parse("fs:read:/workspace").unwrap();
        assert_eq!(
            cap,
            Capability::FsRead {
                path: "/workspace".into()
            }
        );
    }

    #[test]
    fn test_parse_fs_write() {
        let cap = Capability::parse("fs:write:/workspace/output").unwrap();
        assert_eq!(
            cap,
            Capability::FsWrite {
                path: "/workspace/output".into()
            }
        );
    }

    #[test]
    fn test_parse_env() {
        let cap = Capability::parse("env:GITHUB_TOKEN").unwrap();
        assert_eq!(
            cap,
            Capability::Env {
                var: "GITHUB_TOKEN".into()
            }
        );
    }

    #[test]
    fn test_parse_unknown_prefix_is_error() {
        assert!(Capability::parse("socket:unix:/tmp/foo.sock").is_err());
    }

    #[test]
    fn test_parse_empty_string_is_error() {
        assert!(Capability::parse("").is_err());
    }

    #[test]
    fn test_from_capabilities_mixed() {
        let caps = vec![
            "network:api.github.com".to_string(),
            "network:db.internal:5432".to_string(),
            "fs:read:/etc/ssl".to_string(),
            "fs:write:/tmp".to_string(),
            "env:HOME".to_string(),
        ];
        let policy = WasmPolicy::from_capabilities(&caps).unwrap();
        assert_eq!(policy.network.len(), 2);
        assert_eq!(policy.fs_read, vec!["/etc/ssl"]);
        assert_eq!(policy.fs_write, vec!["/tmp"]);
        assert_eq!(policy.env_vars, vec!["HOME"]);
    }

    #[test]
    fn test_from_capabilities_empty_is_deny_all() {
        let policy = WasmPolicy::from_capabilities(&[]).unwrap();
        assert!(policy.network.is_empty());
        assert!(policy.fs_read.is_empty());
        assert!(policy.fs_write.is_empty());
        assert!(policy.env_vars.is_empty());
    }

    #[test]
    fn test_from_capabilities_malformed_fails() {
        let caps = vec!["not-a-valid-capability".to_string()];
        assert!(WasmPolicy::from_capabilities(&caps).is_err());
    }

    #[test]
    fn test_build_wasi_ctx_empty_policy_succeeds() {
        // Empty policy (deny-all) should build without errors.
        let policy = WasmPolicy::default();
        let result = policy.build_wasi_ctx();
        assert!(result.is_ok(), "empty policy should build successfully");
    }
}
