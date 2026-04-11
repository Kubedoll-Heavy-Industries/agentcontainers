//! WASM Component hosting layer for the ac-enforcer sidecar.
//!
//! This module adds a third responsibility to the enforcer alongside
//! BPF program management and gRPC policy serving: hosting WASM Components
//! compiled to the WebAssembly Component Model.
//!
//! # Architecture
//!
//! ```text
//! ComponentRegistry        (this module)
//!   ├── wasmtime Engine    (shared, AOT-compile cache)
//!   ├── wasmtime Linker    (WASI bindings pre-linked)
//!   └── components map     (container_id + name → LoadedComponent)
//!        └── per-invocation Store  (WASI ctx from policy, fuel budget)
//! ```
//!
//! # Phase A scope
//!
//! - Load from raw WASM bytes (OCI fetch is Phase C)
//! - WIT export introspection via wasmtime component types
//! - JSON marshalling for primitive types (bool, int, float, string, option, list)
//! - WASI capability policy building from `capabilities` strings
//! - Fuel metering (when `limits.fuel > 0`)
//!
//! # Deny-by-default
//!
//! Components start with zero WASI capabilities. Each capability must be
//! explicitly granted via the `capabilities` array in `agentcontainer.json`.
//! This mirrors the container-level deny-by-default model.

pub mod bridge;
pub mod policy;
pub mod registry;

pub use bridge::ToolDefinition;
pub use policy::{Capability, WasmPolicy};
pub use registry::{CallResult, ComponentInfo, ComponentLimits, ComponentRegistry};
