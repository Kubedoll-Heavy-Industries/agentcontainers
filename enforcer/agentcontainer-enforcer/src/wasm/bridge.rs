//! WIT → MCP tool definition translation.
//!
//! WASM Components expose their API via WIT (WebAssembly Interface Types).
//! This module translates WIT export signatures into [`ToolDefinition`] structs
//! that are compatible with the MCP protocol and our gRPC API.
//!
//! # Phase A approach
//!
//! In Phase A (Foundation), we don't have `component2json` or `wassette`
//! integrated (those are external git dependencies that may be unstable).
//! Instead, we use wasmtime's built-in component type inspection via
//! `wasmtime::component::types::ComponentType`.
//!
//! The translation maps WIT primitive types to JSON Schema equivalents:
//! - `bool` → `"type": "boolean"`
//! - `s8`/`s16`/`s32`/`s64`/`u8`/`u16`/`u32`/`u64` → `"type": "integer"`
//! - `f32`/`f64` → `"type": "number"`
//! - `string` → `"type": "string"`
//! - `option<T>` → the schema for T, not required
//! - `list<T>` → `"type": "array", "items": <schema for T>`
//! - Records → `"type": "object"` with `"properties"`
//! - Results → wrapped object with `ok` / `err` fields

use anyhow::Result;
use wasmtime::component::{types, Component};

/// An MCP-compatible tool definition, derived from a WIT export.
#[derive(Debug, Clone)]
pub struct ToolDefinition {
    /// The component this tool belongs to.
    pub component_name: String,
    /// The exported function name (the tool name in MCP).
    pub tool_name: String,
    /// Human-readable description (from WIT doc comments if available,
    /// otherwise derived from the function name).
    pub description: String,
    /// JSON Schema string for the tool's input parameters.
    pub input_schema_json: String,
}

/// Inspect a [`Component`] and return all exported functions as [`ToolDefinition`]s.
///
/// In Phase A, this performs a best-effort extraction. Functions that cannot
/// be translated (e.g., they use resource handles) produce a schema with
/// `"type": "object"` and a note in the description.
pub fn extract_tool_definitions(
    component: &Component,
    component_name: &str,
) -> Result<Vec<ToolDefinition>> {
    let component_type = component.component_type();
    let mut tools = Vec::new();

    for (export_name, export_type) in component_type.exports(component.engine()) {
        match export_type {
            types::ComponentItem::ComponentFunc(func_type) => {
                let schema = func_params_to_schema(&func_type);
                let description = generate_description(export_name);
                tools.push(ToolDefinition {
                    component_name: component_name.to_string(),
                    tool_name: export_name.to_string(),
                    description,
                    input_schema_json: schema,
                });
            }
            types::ComponentItem::CoreFunc(_) => {
                // Skip raw core wasm exports — not useful as MCP tools.
            }
            types::ComponentItem::Module(_) => {
                // Nested modules — skip for now.
            }
            types::ComponentItem::Component(_) => {
                // Nested components — skip for now.
            }
            types::ComponentItem::ComponentInstance(instance_type) => {
                // An exported interface — extract its exported functions.
                for (iface_fn_name, iface_item) in instance_type.exports(component.engine()) {
                    if let types::ComponentItem::ComponentFunc(func_type) = iface_item {
                        let full_name = format!("{export_name}/{iface_fn_name}");
                        let schema = func_params_to_schema(&func_type);
                        let description = generate_description(&full_name);
                        tools.push(ToolDefinition {
                            component_name: component_name.to_string(),
                            tool_name: full_name,
                            description,
                            input_schema_json: schema,
                        });
                    }
                }
            }
            types::ComponentItem::Type(_) => {
                // Type exports — not callable tools.
            }
            types::ComponentItem::Resource(_) => {
                // Resource exports — skip for now.
            }
        }
    }

    Ok(tools)
}

/// Convert a WIT function's parameter types into a JSON Schema object string.
///
/// The schema is always `{"type": "object", "properties": {...}, "required": [...]}`.
fn func_params_to_schema(func: &types::ComponentFunc) -> String {
    let mut properties = Vec::new();
    let mut required = Vec::new();

    for (param_name, param_type) in func.params() {
        let schema = wit_type_to_json_schema(&param_type);
        let is_optional = matches!(param_type, types::Type::Option(_));
        properties.push(format!(r#""{param_name}": {schema}"#));
        if !is_optional {
            required.push(format!(r#""{param_name}""#));
        }
    }

    let props_str = properties.join(", ");
    let req_str = required.join(", ");

    if props_str.is_empty() {
        // No parameters — the tool takes no input.
        r#"{"type": "object", "properties": {}}"#.to_string()
    } else {
        format!(r#"{{"type": "object", "properties": {{{props_str}}}, "required": [{req_str}]}}"#)
    }
}

/// Recursively translate a WIT [`types::Type`] into a JSON Schema fragment.
fn wit_type_to_json_schema(ty: &types::Type) -> String {
    match ty {
        types::Type::Bool => r#"{"type": "boolean"}"#.to_string(),

        types::Type::S8
        | types::Type::S16
        | types::Type::S32
        | types::Type::S64
        | types::Type::U8
        | types::Type::U16
        | types::Type::U32
        | types::Type::U64 => r#"{"type": "integer"}"#.to_string(),

        types::Type::Float32 | types::Type::Float64 => r#"{"type": "number"}"#.to_string(),

        types::Type::Char | types::Type::String => r#"{"type": "string"}"#.to_string(),

        types::Type::List(list_type) => {
            let item_schema = wit_type_to_json_schema(&list_type.ty());
            format!(r#"{{"type": "array", "items": {item_schema}}}"#)
        }

        types::Type::Option(opt_type) => {
            // In JSON Schema, optional fields are expressed at the parent level.
            // For the type itself, we emit the inner schema (with nullable).
            let inner = wit_type_to_json_schema(&opt_type.ty());
            // We can't inline "nullable" cleanly without oneOf — use anyOf.
            format!(r#"{{"anyOf": [{inner}, {{"type": "null"}}]}}"#)
        }

        types::Type::Result(result_type) => {
            // Emit an object with ok/err fields.
            let ok_schema = result_type
                .ok()
                .map(|t| wit_type_to_json_schema(&t))
                .unwrap_or_else(|| r#"{"type": "null"}"#.to_string());
            let err_schema = result_type
                .err()
                .map(|t| wit_type_to_json_schema(&t))
                .unwrap_or_else(|| r#"{"type": "null"}"#.to_string());
            format!(
                r#"{{"type": "object", "properties": {{"ok": {ok_schema}, "err": {err_schema}}}}}"#
            )
        }

        types::Type::Tuple(tuple_type) => {
            // Represent as a fixed-length array.
            let items: Vec<String> = tuple_type
                .types()
                .map(|t| wit_type_to_json_schema(&t))
                .collect();
            let items_str = items.join(", ");
            format!(
                r#"{{"type": "array", "prefixItems": [{items_str}], "minItems": {}, "maxItems": {}}}"#,
                items.len(),
                items.len()
            )
        }

        types::Type::Record(record_type) => {
            let mut props = Vec::new();
            let mut required = Vec::new();
            for field in record_type.fields() {
                let field_schema = wit_type_to_json_schema(&field.ty);
                props.push(format!(r#""{}": {field_schema}"#, field.name));
                required.push(format!(r#""{}""#, field.name));
            }
            let props_str = props.join(", ");
            let req_str = required.join(", ");
            format!(
                r#"{{"type": "object", "properties": {{{props_str}}}, "required": [{req_str}]}}"#
            )
        }

        types::Type::Variant(variant_type) => {
            // Represent as an enum of the variant case names.
            let cases: Vec<String> = variant_type
                .cases()
                .map(|c| format!(r#""{}""#, c.name))
                .collect();
            let cases_str = cases.join(", ");
            format!(r#"{{"type": "string", "enum": [{cases_str}]}}"#)
        }

        types::Type::Enum(enum_type) => {
            let names: Vec<String> = enum_type.names().map(|n| format!(r#""{n}""#)).collect();
            let names_str = names.join(", ");
            format!(r#"{{"type": "string", "enum": [{names_str}]}}"#)
        }

        types::Type::Flags(flags_type) => {
            // Represent flags as an array of flag name strings.
            let names: Vec<String> = flags_type.names().map(|n| format!(r#""{n}""#)).collect();
            let names_str = names.join(", ");
            format!(r#"{{"type": "array", "items": {{"type": "string", "enum": [{names_str}]}}}}"#)
        }

        types::Type::Own(_) | types::Type::Borrow(_) => {
            // Resource handles — cannot be serialised to JSON.
            r#"{"type": "object", "description": "resource handle (not serialisable)"}"#.to_string()
        }
        types::Type::Future(_) | types::Type::Stream(_) | types::Type::ErrorContext => {
            // Async types from WASI 0.3 — not yet supported.
            r#"{"type": "object", "description": "async type (not yet supported)"}"#.to_string()
        }
    }
}

/// Generate a human-readable description from a function name.
///
/// Converts `kebab-case` and `snake_case` to `Title Case With Spaces`.
fn generate_description(name: &str) -> String {
    let cleaned = name.replace(['-', '_'], " ").replace('/', " / ");

    // Capitalise first letter of each word.
    cleaned
        .split_whitespace()
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => c.to_uppercase().to_string() + chars.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_description_kebab() {
        assert_eq!(generate_description("get-current-time"), "Get Current Time");
    }

    #[test]
    fn test_generate_description_snake() {
        assert_eq!(generate_description("fetch_url"), "Fetch Url");
    }

    #[test]
    fn test_generate_description_interface() {
        // The ':' in interface names is preserved; '/' becomes ' / '; '-' becomes ' '.
        assert_eq!(
            generate_description("mcp:filesystem/read-file"),
            "Mcp:filesystem / Read File"
        );
    }

    #[test]
    fn test_wit_type_bool() {
        // We can't easily construct wasmtime types outside the engine,
        // so we test the schema output of the helper function directly
        // using a string comparison approach.
        // Deeper component-model tests require a real .wasm binary.
        assert_eq!(
            wit_type_to_json_schema(&types::Type::Bool),
            r#"{"type": "boolean"}"#
        );
    }

    #[test]
    fn test_wit_type_integer_variants() {
        for ty in [
            types::Type::S8,
            types::Type::S16,
            types::Type::S32,
            types::Type::S64,
            types::Type::U8,
            types::Type::U16,
            types::Type::U32,
            types::Type::U64,
        ] {
            assert_eq!(
                wit_type_to_json_schema(&ty),
                r#"{"type": "integer"}"#,
                "failed for {ty:?}"
            );
        }
    }

    #[test]
    fn test_wit_type_float() {
        assert_eq!(
            wit_type_to_json_schema(&types::Type::Float32),
            r#"{"type": "number"}"#
        );
        assert_eq!(
            wit_type_to_json_schema(&types::Type::Float64),
            r#"{"type": "number"}"#
        );
    }

    #[test]
    fn test_wit_type_string() {
        assert_eq!(
            wit_type_to_json_schema(&types::Type::String),
            r#"{"type": "string"}"#
        );
    }

    #[test]
    fn test_wit_type_char() {
        assert_eq!(
            wit_type_to_json_schema(&types::Type::Char),
            r#"{"type": "string"}"#
        );
    }
}
