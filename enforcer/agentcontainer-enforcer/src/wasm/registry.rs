//! ComponentRegistry — load, unload, list, and invoke WASM Components.
//!
//! This is the central coordinator for the WASM hosting layer. It manages:
//! - A wasmtime [`Engine`] (shared, AOT-compile cache)
//! - A map of loaded components keyed by `(container_id, component_name)`
//! - Per-invocation [`Store`] creation with WASI context from policy
//!
//! # Threading
//!
//! The registry itself is not `Send + Sync`. Callers wrap it in
//! `Arc<tokio::sync::Mutex<...>>` to share across async tasks.
//! Engine, Linker, and Component are all `Send + Sync`. Stores are
//! per-invocation and short-lived.
//!
//! # Phase A scope
//!
//! - Load from raw WASM bytes (OCI fetch is Phase C)
//! - Tool definitions extracted via wasmtime type inspection
//! - Call dispatch via wasmtime component model
//! - No fuel metering yet (Phase E)

use std::collections::HashMap;

use anyhow::{Context, Result};
use wasmtime::component::ResourceTable;
use wasmtime::{
    component::{Component, Linker},
    Engine, Store,
};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};

use crate::wasm::bridge::{extract_tool_definitions, ToolDefinition};
use crate::wasm::policy::WasmPolicy;

// ---------------------------------------------------------------------------
// Key type
// ---------------------------------------------------------------------------

/// Unique key for a loaded component: (container_id, component_name).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ComponentKey {
    pub container_id: String,
    pub component_name: String,
}

// ---------------------------------------------------------------------------
// Loaded component entry
// ---------------------------------------------------------------------------

/// A loaded WASM Component and its associated metadata.
pub struct LoadedComponent {
    pub component: Component,
    pub oci_reference: String,
    pub policy: WasmPolicy,
    pub limits: ComponentLimits,
    pub tools: Vec<ToolDefinition>,
}

/// Resource limits for a component invocation.
#[derive(Debug, Clone, Default)]
pub struct ComponentLimits {
    /// Maximum linear memory in bytes (0 = wasmtime default ~4 GiB).
    pub memory_bytes: u64,
    /// Instruction fuel budget per call (0 = unlimited).
    pub fuel: u64,
    /// Wall-clock timeout per call in milliseconds (0 = no timeout).
    pub timeout_ms: u64,
}

// ---------------------------------------------------------------------------
// WASI store state
// ---------------------------------------------------------------------------

/// Per-invocation state held in the wasmtime Store.
pub struct WasiState {
    ctx: WasiCtx,
    table: ResourceTable,
}

impl WasiView for WasiState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

// ---------------------------------------------------------------------------
// ComponentRegistry
// ---------------------------------------------------------------------------

/// Manages the lifecycle of loaded WASM Components.
pub struct ComponentRegistry {
    engine: Engine,
    linker: Linker<WasiState>,
    components: HashMap<ComponentKey, LoadedComponent>,
}

impl ComponentRegistry {
    /// Create a new registry with a default wasmtime Engine configured for
    /// the Component Model.
    pub fn new() -> Result<Self> {
        let mut config = wasmtime::Config::new();
        config.wasm_component_model(true);

        let engine = Engine::new(&config)
            .map_err(anyhow::Error::from)
            .context("creating wasmtime engine")?;

        let mut linker: Linker<WasiState> = Linker::new(&engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)
            .map_err(anyhow::Error::from)
            .context("adding WASI to linker")?;

        Ok(Self {
            engine,
            linker,
            components: HashMap::new(),
        })
    }

    /// Load a WASM Component from raw bytes.
    ///
    /// Compiles the component bytes using the shared Engine (AOT-cached),
    /// extracts tool definitions from its WIT exports, and registers it
    /// under `(container_id, component_name)`.
    ///
    /// Returns an error if:
    /// - The bytes are not a valid WASM Component
    /// - A component with the same key is already loaded
    pub fn load(
        &mut self,
        container_id: &str,
        component_name: &str,
        oci_reference: &str,
        wasm_bytes: &[u8],
        policy: WasmPolicy,
        limits: ComponentLimits,
    ) -> Result<Vec<ToolDefinition>> {
        let key = ComponentKey {
            container_id: container_id.to_string(),
            component_name: component_name.to_string(),
        };

        if self.components.contains_key(&key) {
            anyhow::bail!(
                "component '{component_name}' is already loaded for container '{container_id}'"
            );
        }

        let component = Component::from_binary(&self.engine, wasm_bytes)
            .map_err(anyhow::Error::from)
            .context("compiling WASM component")?;

        let tools = extract_tool_definitions(&component, component_name)
            .context("extracting tool definitions")?;

        self.components.insert(
            key,
            LoadedComponent {
                component,
                oci_reference: oci_reference.to_string(),
                policy,
                limits,
                tools: tools.clone(),
            },
        );

        tracing::info!(
            container_id,
            component_name,
            tools = tools.len(),
            "loaded WASM component"
        );

        Ok(tools)
    }

    /// Unload a component. Returns an error if the component is not loaded.
    pub fn unload(&mut self, container_id: &str, component_name: &str) -> Result<()> {
        let key = ComponentKey {
            container_id: container_id.to_string(),
            component_name: component_name.to_string(),
        };

        if self.components.remove(&key).is_none() {
            anyhow::bail!(
                "component '{component_name}' is not loaded for container '{container_id}'"
            );
        }

        tracing::info!(container_id, component_name, "unloaded WASM component");
        Ok(())
    }

    /// List all loaded components, optionally filtered by container_id.
    ///
    /// An empty `container_id` returns all components across all containers.
    pub fn list(&self, container_id: &str) -> Vec<ComponentInfo> {
        self.components
            .iter()
            .filter(|(key, _)| container_id.is_empty() || key.container_id == container_id)
            .map(|(key, entry)| ComponentInfo {
                container_id: key.container_id.clone(),
                component_name: key.component_name.clone(),
                oci_reference: entry.oci_reference.clone(),
                tools: entry.tools.clone(),
            })
            .collect()
    }

    /// List tool definitions for loaded components, optionally filtered.
    ///
    /// If `component_name` is empty, returns tools for all components in
    /// the container. If both are empty, returns all tools everywhere.
    pub fn list_tools(&self, container_id: &str, component_name: &str) -> Vec<ToolDefinition> {
        self.components
            .iter()
            .filter(|(key, _)| {
                (container_id.is_empty() || key.container_id == container_id)
                    && (component_name.is_empty() || key.component_name == component_name)
            })
            .flat_map(|(_, entry)| entry.tools.clone())
            .collect()
    }

    /// Invoke a tool call on a loaded component.
    ///
    /// Phase A: calls the exported function by name and marshals the result
    /// to JSON. Fuel metering is applied if `limits.fuel > 0`.
    ///
    /// Returns the JSON-encoded result, execution time, and fuel consumed.
    pub fn call_tool(
        &self,
        container_id: &str,
        component_name: &str,
        tool_name: &str,
        arguments_json: &str,
    ) -> Result<CallResult> {
        let key = ComponentKey {
            container_id: container_id.to_string(),
            component_name: component_name.to_string(),
        };

        let entry = self.components.get(&key).ok_or_else(|| {
            anyhow::anyhow!(
                "component '{component_name}' is not loaded for container '{container_id}'"
            )
        })?;

        // Verify the tool exists in this component's exported definitions.
        let tool_exists = entry.tools.iter().any(|t| t.tool_name == tool_name);
        if !tool_exists {
            anyhow::bail!("tool '{tool_name}' not found in component '{component_name}'");
        }

        // Build per-invocation WASI context from policy.
        let (wasi_ctx, table) = entry
            .policy
            .build_wasi_ctx()
            .context("building WASI context for invocation")?;
        let state = WasiState {
            ctx: wasi_ctx,
            table,
        };
        let mut store = Store::new(&self.engine, state);

        // Apply fuel budget if configured.
        if entry.limits.fuel > 0 {
            store
                .set_fuel(entry.limits.fuel)
                .map_err(anyhow::Error::from)
                .context("setting fuel budget")?;
        }

        // I5: Warn about unenforced limits (Phase E will implement these).
        if entry.limits.memory_bytes > 0 {
            tracing::warn!(
                memory_bytes = entry.limits.memory_bytes,
                "memory_bytes limit is not yet enforced; will be implemented in Phase E"
            );
        }
        if entry.limits.timeout_ms > 0 {
            tracing::warn!(
                timeout_ms = entry.limits.timeout_ms,
                "timeout_ms limit is not yet enforced; will be implemented in Phase E"
            );
        }

        // Instantiate the component.
        let instance = self
            .linker
            .instantiate(&mut store, &entry.component)
            .map_err(anyhow::Error::from)
            .context("instantiating WASM component")?;

        let start = std::time::Instant::now();

        // Locate and invoke the exported function.
        let result = call_export(&mut store, &instance, tool_name, arguments_json);

        let elapsed_ns = start.elapsed().as_nanos() as u64;

        // Read fuel consumed (if metering was enabled).
        let fuel_consumed = if entry.limits.fuel > 0 {
            entry
                .limits
                .fuel
                .saturating_sub(store.get_fuel().unwrap_or(entry.limits.fuel))
        } else {
            0
        };

        let result_json = result.context("invoking WASM tool")?;

        Ok(CallResult {
            result_json,
            execution_time_ns: elapsed_ns,
            fuel_consumed,
        })
    }
}

/// Result of a successful tool call.
#[derive(Debug)]
pub struct CallResult {
    /// JSON-encoded result from the tool.
    pub result_json: String,
    /// Wall-clock time for the invocation, in nanoseconds.
    pub execution_time_ns: u64,
    /// Fuel consumed (0 if fuel metering is disabled).
    pub fuel_consumed: u64,
}

/// Info about a loaded component (for ListComponents response).
#[derive(Debug, Clone)]
pub struct ComponentInfo {
    pub container_id: String,
    pub component_name: String,
    pub oci_reference: String,
    pub tools: Vec<ToolDefinition>,
}

// ---------------------------------------------------------------------------
// Call helpers
// ---------------------------------------------------------------------------

/// Invoke an exported function by name, handling both top-level and
/// interface-scoped names (e.g., "mcp:filesystem/read-file").
fn call_export(
    store: &mut Store<WasiState>,
    instance: &wasmtime::component::Instance,
    tool_name: &str,
    arguments_json: &str,
) -> Result<String> {
    // Look up the exported function by name (handles both cases).
    let func = instance
        .get_func(&mut *store, tool_name)
        .ok_or_else(|| anyhow::anyhow!("exported function '{tool_name}' not found in component"))?;

    invoke_func(store, &func, arguments_json)
}

/// Invoke a typed [`wasmtime::component::Func`] with JSON-encoded arguments.
///
/// Phase A: supports functions with no parameters or basic typed parameters,
/// returning results marshalled to JSON.
///
/// I1: `arguments_json` is parsed exactly once into a `serde_json::Value`
/// and then the parsed value is passed to each per-parameter helper.
fn invoke_func(
    store: &mut Store<WasiState>,
    func: &wasmtime::component::Func,
    arguments_json: &str,
) -> Result<String> {
    use wasmtime::component::Val;

    // I1: parse once up front.
    let parsed: serde_json::Value =
        serde_json::from_str(arguments_json).context("parsing arguments_json")?;

    let func_type = func.ty(&*store);
    let params: Vec<Val> = func_type
        .params()
        .enumerate()
        .map(|(i, (name, ty))| json_to_val(&parsed, i, name, &ty))
        .collect::<Result<Vec<_>>>()?;

    let result_count = func_type.results().count();
    let mut results = vec![Val::Bool(false); result_count];

    func.call(&mut *store, &params, &mut results)
        .map_err(anyhow::Error::from)
        .context("calling WASM function")?;

    // Encode results as JSON.
    let result_vals: Vec<serde_json::Value> = results.iter().map(val_to_json).collect();
    let result_json = if result_vals.len() == 1 {
        serde_json::to_string(&result_vals[0])
    } else {
        serde_json::to_string(&result_vals)
    }
    .context("serialising result to JSON")?;

    Ok(result_json)
}

/// Convert a pre-parsed JSON value + parameter metadata into a wasmtime [`Val`].
///
/// I1: accepts an already-parsed `&serde_json::Value` to avoid re-parsing.
/// I2: when the JSON is an object, looks up the parameter by its WIT `name`
///     rather than by positional index (fixes BTreeMap alphabetical ordering bug).
fn json_to_val(
    parsed: &serde_json::Value,
    index: usize,
    name: &str,
    ty: &wasmtime::component::Type,
) -> Result<wasmtime::component::Val> {
    use serde_json::Value as JVal;

    let arg = match parsed {
        // I2: named lookup by WIT parameter name, not positional index.
        JVal::Object(map) => map.get(name).cloned().unwrap_or(JVal::Null),
        JVal::Array(arr) => arr.get(index).cloned().unwrap_or(JVal::Null),
        other => {
            if index == 0 {
                other.clone()
            } else {
                JVal::Null
            }
        }
    };

    json_to_wit_val(&arg, ty)
}

fn json_to_wit_val(
    v: &serde_json::Value,
    ty: &wasmtime::component::Type,
) -> Result<wasmtime::component::Val> {
    use serde_json::Value as JVal;
    use wasmtime::component::{Type, Val};

    Ok(match (v, ty) {
        (JVal::Bool(b), Type::Bool) => Val::Bool(*b),
        (JVal::Number(n), Type::S8) => Val::S8(n.as_i64().unwrap_or(0) as i8),
        (JVal::Number(n), Type::S16) => Val::S16(n.as_i64().unwrap_or(0) as i16),
        (JVal::Number(n), Type::S32) => Val::S32(n.as_i64().unwrap_or(0) as i32),
        (JVal::Number(n), Type::S64) => Val::S64(n.as_i64().unwrap_or(0)),
        (JVal::Number(n), Type::U8) => Val::U8(n.as_u64().unwrap_or(0) as u8),
        (JVal::Number(n), Type::U16) => Val::U16(n.as_u64().unwrap_or(0) as u16),
        (JVal::Number(n), Type::U32) => Val::U32(n.as_u64().unwrap_or(0) as u32),
        (JVal::Number(n), Type::U64) => Val::U64(n.as_u64().unwrap_or(0)),
        (JVal::Number(n), Type::Float32) => Val::Float32(n.as_f64().unwrap_or(0.0) as f32),
        (JVal::Number(n), Type::Float64) => Val::Float64(n.as_f64().unwrap_or(0.0)),
        (JVal::String(s), Type::String) => Val::String(s.clone()),
        (JVal::String(s), Type::Char) => {
            let c = s.chars().next().unwrap_or('\0');
            Val::Char(c)
        }
        (JVal::Null, Type::Option(_)) => Val::Option(None),
        (v, Type::Option(opt)) => Val::Option(Some(Box::new(json_to_wit_val(v, &opt.ty())?))),
        (JVal::Array(arr), Type::List(list)) => {
            let item_ty = list.ty();
            let vals: Result<Vec<_>> = arr.iter().map(|v| json_to_wit_val(v, &item_ty)).collect();
            Val::List(vals?)
        }
        _ => anyhow::bail!("cannot convert JSON value {v:?} to WASM type {ty:?}"),
    })
}

/// Convert a wasmtime [`Val`] to a serde_json [`Value`].
fn val_to_json(v: &wasmtime::component::Val) -> serde_json::Value {
    use serde_json::{json, Value as JVal};
    use wasmtime::component::Val;

    match v {
        Val::Bool(b) => JVal::Bool(*b),
        Val::S8(n) => json!(*n),
        Val::S16(n) => json!(*n),
        Val::S32(n) => json!(*n),
        Val::S64(n) => json!(*n),
        Val::U8(n) => json!(*n),
        Val::U16(n) => json!(*n),
        Val::U32(n) => json!(*n),
        Val::U64(n) => json!(*n),
        Val::Float32(f) => json!(*f as f64),
        Val::Float64(f) => json!(*f),
        Val::Char(c) => JVal::String(c.to_string()),
        Val::String(s) => JVal::String(s.clone()),
        Val::List(items) => JVal::Array(items.iter().map(val_to_json).collect()),
        Val::Record(fields) => {
            let map: serde_json::Map<_, _> = fields
                .iter()
                .map(|(name, val)| (name.to_string(), val_to_json(val)))
                .collect();
            JVal::Object(map)
        }
        Val::Tuple(items) => JVal::Array(items.iter().map(val_to_json).collect()),
        Val::Variant(name, payload) => {
            let inner = payload
                .as_ref()
                .map(|v| val_to_json(v))
                .unwrap_or(JVal::Null);
            serde_json::json!({ "variant": name, "payload": inner })
        }
        Val::Enum(name) => JVal::String(name.to_string()),
        Val::Option(inner) => match inner {
            Some(v) => val_to_json(v),
            None => JVal::Null,
        },
        Val::Result(r) => match r {
            Ok(Some(v)) => serde_json::json!({ "ok": val_to_json(v) }),
            Ok(None) => serde_json::json!({ "ok": null }),
            Err(Some(e)) => serde_json::json!({ "err": val_to_json(e) }),
            Err(None) => serde_json::json!({ "err": null }),
        },
        Val::Flags(names) => {
            JVal::Array(names.iter().map(|n| JVal::String(n.to_string())).collect())
        }
        Val::Resource(_) => JVal::String("<resource handle>".into()),
        Val::Future(_) | Val::Stream(_) | Val::ErrorContext(_) => {
            JVal::String("<async type>".into())
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_new() {
        let registry = ComponentRegistry::new();
        assert!(registry.is_ok(), "registry creation should succeed");
    }

    #[test]
    fn test_list_empty() {
        let registry = ComponentRegistry::new().unwrap();
        let components = registry.list("");
        assert!(components.is_empty());
    }

    #[test]
    fn test_unload_nonexistent_returns_error() {
        let mut registry = ComponentRegistry::new().unwrap();
        let err = registry.unload("ctr-1", "nonexistent").unwrap_err();
        assert!(
            err.to_string().contains("not loaded"),
            "expected 'not loaded' error"
        );
    }

    #[test]
    fn test_list_tools_empty() {
        let registry = ComponentRegistry::new().unwrap();
        let tools = registry.list_tools("ctr-1", "");
        assert!(tools.is_empty());
    }

    #[test]
    fn test_call_tool_not_loaded_returns_error() {
        let registry = ComponentRegistry::new().unwrap();
        let err = registry
            .call_tool("ctr-1", "nonexistent", "echo", "{}")
            .unwrap_err();
        assert!(
            err.to_string().contains("not loaded"),
            "expected 'not loaded' error"
        );
    }

    #[test]
    fn test_val_to_json_primitives() {
        use wasmtime::component::Val;
        assert_eq!(val_to_json(&Val::Bool(true)), serde_json::json!(true));
        assert_eq!(val_to_json(&Val::S32(42)), serde_json::json!(42));
        assert_eq!(
            val_to_json(&Val::String("hello".into())),
            serde_json::json!("hello")
        );
        assert_eq!(val_to_json(&Val::Option(None)), serde_json::Value::Null);
    }

    #[test]
    fn test_val_to_json_list() {
        use wasmtime::component::Val;
        let list = Val::List(vec![Val::U32(1), Val::U32(2), Val::U32(3)]);
        assert_eq!(val_to_json(&list), serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn test_val_to_json_result_ok() {
        use wasmtime::component::Val;
        let r = Val::Result(Ok(Some(Box::new(Val::String("done".into())))));
        assert_eq!(val_to_json(&r), serde_json::json!({"ok": "done"}));
    }

    #[test]
    fn test_val_to_json_result_err() {
        use wasmtime::component::Val;
        let r = Val::Result(Err(Some(Box::new(Val::String("oops".into())))));
        assert_eq!(val_to_json(&r), serde_json::json!({"err": "oops"}));
    }
}
