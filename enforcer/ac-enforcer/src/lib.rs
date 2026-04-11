//! ac-enforcer library crate.
//!
//! Exposes the BPF policy manager, event pipeline, policy types, and
//! WASM Component hosting for integration tests and external consumers.

pub mod bpf;
pub mod events;
pub mod grpc;
pub mod policy;
#[cfg(feature = "otel")]
pub mod telemetry;
pub mod wasm;
