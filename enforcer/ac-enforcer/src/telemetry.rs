//! OpenTelemetry pipeline setup and custom attribute constants for ac-enforcer.
//!
//! This module is only compiled when the `otel` feature is enabled.
//! It provides:
//! - OTLP exporter initialisation (`init_tracer_provider`)
//! - Graceful shutdown (`shutdown_tracer_provider`)
//! - Custom `ac.*` attribute key constants for enforcer-specific metadata

use opentelemetry::KeyValue;
use opentelemetry_sdk::trace::SdkTracerProvider;

/// Supported OTLP transport protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtlpProtocol {
    Grpc,
    HttpProto,
}

impl std::str::FromStr for OtlpProtocol {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "grpc" => Ok(Self::Grpc),
            "http" | "http-proto" | "http/protobuf" => Ok(Self::HttpProto),
            other => anyhow::bail!("unknown OTLP protocol: {other} (expected grpc or http)"),
        }
    }
}

/// Initialise an OTLP trace exporter and return the [`SdkTracerProvider`].
///
/// The provider is configured with:
/// - `service.name = "ac-enforcer"`
/// - Batch span processor backed by the Tokio runtime
/// - OTLP exporter using either gRPC or HTTP/protobuf transport
pub fn init_tracer_provider(
    endpoint: &str,
    protocol: OtlpProtocol,
) -> anyhow::Result<SdkTracerProvider> {
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use opentelemetry_sdk::Resource;

    let resource = Resource::builder()
        .with_attributes([KeyValue::new("service.name", "ac-enforcer")])
        .build();

    let provider = match protocol {
        OtlpProtocol::Grpc => {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .build()?;
            SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(resource)
                .build()
        }
        OtlpProtocol::HttpProto => {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_endpoint(endpoint)
                .build()?;
            SdkTracerProvider::builder()
                .with_batch_exporter(exporter)
                .with_resource(resource)
                .build()
        }
    };

    Ok(provider)
}

/// Flush pending spans and shut down the tracer provider.
pub fn shutdown_tracer_provider(provider: &SdkTracerProvider) {
    if let Err(e) = provider.shutdown() {
        tracing::warn!(error = %e, "failed to shut down OTel tracer provider");
    }
}

/// Custom `ac.*` attribute keys for enforcer-specific observability.
///
/// These are set on OpenInference spans via `OpenTelemetrySpanExt::set_attribute()`
/// alongside the standard OpenInference attributes.
pub mod ac {
    use opentelemetry::Key;

    pub mod enforcement {
        use super::*;

        /// Enforcement domain: "network", "filesystem", "process", "credential".
        pub const DOMAIN: Key = Key::from_static_str("ac.enforcement.domain");

        /// Enforcement verdict: "allow" or "block".
        pub const VERDICT: Key = Key::from_static_str("ac.enforcement.verdict");

        /// Process ID of the subject process.
        pub const PID: Key = Key::from_static_str("ac.enforcement.pid");

        /// Process command name.
        pub const COMM: Key = Key::from_static_str("ac.enforcement.comm");

        /// Number of policy rules applied.
        pub const RULES_COUNT: Key = Key::from_static_str("ac.enforcement.rules_count");
    }

    pub mod container {
        use super::*;

        /// Container identifier.
        pub const ID: Key = Key::from_static_str("ac.container.id");

        /// Container cgroup path.
        pub const CGROUP_PATH: Key = Key::from_static_str("ac.container.cgroup_path");

        /// Container cgroup ID (u64).
        pub const CGROUP_ID: Key = Key::from_static_str("ac.container.cgroup_id");
    }

    pub mod tool {
        use super::*;

        /// WASM fuel units consumed during tool execution.
        pub const FUEL_CONSUMED: Key = Key::from_static_str("ac.tool.fuel_consumed");

        /// Execution wall-clock time in nanoseconds.
        pub const EXECUTION_TIME_NS: Key = Key::from_static_str("ac.tool.execution_time_ns");

        /// OCI artifact reference for the WASM component.
        pub const OCI_REFERENCE: Key = Key::from_static_str("ac.tool.oci_reference");

        /// WASM component name in the registry.
        pub const COMPONENT_NAME: Key = Key::from_static_str("ac.tool.component_name");
    }
}
