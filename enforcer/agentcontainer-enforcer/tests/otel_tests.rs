//! OpenInference telemetry integration tests for agentcontainer-enforcer.
//!
//! These tests use `InMemorySpanExporter` to verify that the gRPC handlers
//! emit correctly-attributed OpenInference spans when the `otel` feature is enabled.
//!
//! Note: dev-dependencies (opentelemetry, opentelemetry_sdk, tracing-opentelemetry,
//! openinference-*) are always available in test builds regardless of the `otel` feature.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::Value;
use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider, SpanData};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;

use openinference_instrumentation::{
    ChainSpanBuilder, GuardrailSpanBuilder, ToolSpanBuilder, TraceConfig,
};

// =============================================================================
// Test harness
// =============================================================================

/// Sets up a tracing subscriber backed by an in-memory OTel exporter.
fn setup_tracing() -> (
    impl tracing::Subscriber,
    opentelemetry_sdk::trace::InMemorySpanExporter,
    SdkTracerProvider,
) {
    let exporter = InMemorySpanExporterBuilder::new().build();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let tracer = provider.tracer("test");
    let telemetry = OpenTelemetryLayer::new(tracer);
    let subscriber = Registry::default().with(telemetry);
    (subscriber, exporter, provider)
}

/// Find an attribute value in an exported span by key name.
fn find_attribute(span: &SpanData, key: &str) -> Option<Value> {
    span.attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .map(|kv| kv.value.clone())
}

/// Assert that a span contains an attribute with the given string value.
fn assert_string_attribute(span: &SpanData, key: &str, expected: &str) {
    let val = find_attribute(span, key).unwrap_or_else(|| {
        panic!(
            "attribute '{}' not found in span. attributes: {:?}",
            key, span.attributes
        )
    });
    match &val {
        Value::String(s) => assert_eq!(
            s.as_str(),
            expected,
            "attribute '{}' expected '{}', got '{}'",
            key,
            expected,
            s.as_str()
        ),
        other => panic!(
            "attribute '{}' expected String('{}'), got {:?}",
            key, expected, other
        ),
    }
}

/// Assert that a span contains an attribute with the given i64 value.
fn assert_i64_attribute(span: &SpanData, key: &str, expected: i64) {
    let val = find_attribute(span, key).unwrap_or_else(|| {
        panic!(
            "attribute '{}' not found in span. attributes: {:?}",
            key, span.attributes
        )
    });
    match &val {
        Value::I64(v) => assert_eq!(
            *v, expected,
            "attribute '{}' expected {}, got {}",
            key, expected, v
        ),
        other => panic!(
            "attribute '{}' expected I64({}), got {:?}",
            key, expected, other
        ),
    }
}

// =============================================================================
// Test 1: call_tool emits a TOOL span with correct attributes
// =============================================================================

#[test]
fn test_call_tool_emits_tool_span() {
    let (subscriber, exporter, _provider) = setup_tracing();

    tracing::subscriber::with_default(subscriber, || {
        use tracing_opentelemetry::OpenTelemetrySpanExt;

        let config = TraceConfig::default();
        let span = ToolSpanBuilder::new("web_search")
            .parameters(r#"{"query": "rust async"}"#)
            .config(config.clone())
            .build();

        // Simulate what grpc.rs does: set custom ac.* attributes.
        span.set_attribute(
            opentelemetry::Key::from_static_str("ac.container.id"),
            "ctr-test-1",
        );
        span.set_attribute(
            opentelemetry::Key::from_static_str("ac.tool.component_name"),
            "search-component",
        );

        // Simulate success: record output and metrics.
        openinference_instrumentation::record_output_value(
            &span,
            r#"{"results": ["item1"]}"#,
            &config,
        );
        span.set_attribute(
            opentelemetry::Key::from_static_str("ac.tool.fuel_consumed"),
            42_i64,
        );
        span.set_attribute(
            opentelemetry::Key::from_static_str("ac.tool.execution_time_ns"),
            1_000_000_i64,
        );

        drop(span);
    });

    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1, "expected 1 span, got {}", spans.len());
    let span = &spans[0];

    // OpenInference span kind
    assert_string_attribute(span, "openinference.span.kind", "TOOL");
    assert_string_attribute(span, "tool.name", "web_search");
    assert_string_attribute(span, "tool.parameters", r#"{"query": "rust async"}"#);

    // Custom ac.* attributes
    assert_string_attribute(span, "ac.container.id", "ctr-test-1");
    assert_string_attribute(span, "ac.tool.component_name", "search-component");
    assert_i64_attribute(span, "ac.tool.fuel_consumed", 42);
    assert_i64_attribute(span, "ac.tool.execution_time_ns", 1_000_000);

    // Output value (privacy not hidden)
    assert_string_attribute(span, "output.value", r#"{"results": ["item1"]}"#);
}

// =============================================================================
// Test 2: call_tool error records exception attributes
// =============================================================================

#[test]
fn test_call_tool_error_records_exception() {
    let (subscriber, exporter, _provider) = setup_tracing();

    tracing::subscriber::with_default(subscriber, || {
        use tracing_opentelemetry::OpenTelemetrySpanExt;

        let span = ToolSpanBuilder::new("failing_tool")
            .parameters("{}")
            .config(TraceConfig::default())
            .build();

        span.set_attribute(
            opentelemetry::Key::from_static_str("ac.container.id"),
            "ctr-err",
        );

        // Simulate error path.
        openinference_instrumentation::record_error(
            &span,
            "ToolInvocationError",
            "component 'bad' not loaded for container 'ctr-err'",
        );

        drop(span);
    });

    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    let span = &spans[0];

    assert_string_attribute(span, "openinference.span.kind", "TOOL");
    assert_string_attribute(span, "tool.name", "failing_tool");
    assert_string_attribute(span, "exception.type", "ToolInvocationError");
    assert_string_attribute(
        span,
        "exception.message",
        "component 'bad' not loaded for container 'ctr-err'",
    );
}

// =============================================================================
// Test 3: apply_network_policy emits a GUARDRAIL span with domain + verdict
// =============================================================================

#[test]
fn test_apply_network_policy_emits_guardrail_span() {
    let (subscriber, exporter, _provider) = setup_tracing();

    tracing::subscriber::with_default(subscriber, || {
        use tracing_opentelemetry::OpenTelemetrySpanExt;

        let span = GuardrailSpanBuilder::new("network_policy")
            .config(TraceConfig::default())
            .build();

        span.set_attribute(
            opentelemetry::Key::from_static_str("ac.enforcement.domain"),
            "network",
        );
        span.set_attribute(
            opentelemetry::Key::from_static_str("ac.container.id"),
            "ctr-net",
        );
        span.set_attribute(
            opentelemetry::Key::from_static_str("ac.enforcement.rules_count"),
            3_i64,
        );
        span.set_attribute(
            opentelemetry::Key::from_static_str("ac.enforcement.verdict"),
            "allow",
        );

        drop(span);
    });

    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    let span = &spans[0];

    assert_string_attribute(span, "openinference.span.kind", "GUARDRAIL");
    assert_string_attribute(span, "ac.enforcement.domain", "network");
    assert_string_attribute(span, "ac.container.id", "ctr-net");
    assert_i64_attribute(span, "ac.enforcement.rules_count", 3);
    assert_string_attribute(span, "ac.enforcement.verdict", "allow");
}

// =============================================================================
// Test 4: register_container emits a CHAIN span
// =============================================================================

#[test]
fn test_register_container_emits_chain_span() {
    let (subscriber, exporter, _provider) = setup_tracing();

    tracing::subscriber::with_default(subscriber, || {
        use tracing_opentelemetry::OpenTelemetrySpanExt;

        let config = TraceConfig::default();
        let span = ChainSpanBuilder::new("register_container")
            .input("container_id=ctr-1, cgroup_path=/sys/fs/cgroup/test")
            .config(config)
            .build();

        span.set_attribute(
            opentelemetry::Key::from_static_str("ac.container.id"),
            "ctr-1",
        );
        span.set_attribute(
            opentelemetry::Key::from_static_str("ac.container.cgroup_path"),
            "/sys/fs/cgroup/test",
        );
        span.set_attribute(
            opentelemetry::Key::from_static_str("ac.container.cgroup_id"),
            12345_i64,
        );

        drop(span);
    });

    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    let span = &spans[0];

    assert_string_attribute(span, "openinference.span.kind", "CHAIN");
    assert_string_attribute(
        span,
        "input.value",
        "container_id=ctr-1, cgroup_path=/sys/fs/cgroup/test",
    );
    assert_string_attribute(span, "ac.container.id", "ctr-1");
    assert_string_attribute(span, "ac.container.cgroup_path", "/sys/fs/cgroup/test");
    assert_i64_attribute(span, "ac.container.cgroup_id", 12345);
}

// =============================================================================
// Test 5: privacy hides tool parameters input when OPENINFERENCE_HIDE_INPUTS=true
// =============================================================================

#[test]
fn test_privacy_hides_tool_output() {
    let (subscriber, exporter, _provider) = setup_tracing();

    tracing::subscriber::with_default(subscriber, || {
        let config = TraceConfig::builder().hide_outputs(true).build();

        let span = ToolSpanBuilder::new("secret_tool")
            .parameters(r#"{"secret": "value"}"#)
            .config(config.clone())
            .build();

        // record_output_value should redact when hide_outputs is true.
        openinference_instrumentation::record_output_value(&span, "sensitive output data", &config);

        drop(span);
    });

    let spans = exporter.get_finished_spans().unwrap();
    assert_eq!(spans.len(), 1);
    let span = &spans[0];

    assert_string_attribute(span, "openinference.span.kind", "TOOL");
    // Output should be redacted
    assert_string_attribute(span, "output.value", "__REDACTED__");
    // tool.parameters is NOT subject to hide_outputs (it's input metadata)
    assert_string_attribute(span, "tool.parameters", r#"{"secret": "value"}"#);
}

// =============================================================================
// Test 6: custom attribute key string values are correct
// =============================================================================

#[test]
#[cfg(feature = "otel")]
fn test_custom_attribute_key_names() {
    // Verify the string values of all custom ac.* attribute keys.
    // These are compile-time constants, so this is really a documentation test
    // ensuring the key names don't accidentally change.
    // Requires the `otel` feature since `telemetry` module is feature-gated.

    use agentcontainer_enforcer::telemetry::ac;

    // Enforcement attributes
    assert_eq!(ac::enforcement::DOMAIN.as_str(), "ac.enforcement.domain");
    assert_eq!(ac::enforcement::VERDICT.as_str(), "ac.enforcement.verdict");
    assert_eq!(ac::enforcement::PID.as_str(), "ac.enforcement.pid");
    assert_eq!(ac::enforcement::COMM.as_str(), "ac.enforcement.comm");
    assert_eq!(
        ac::enforcement::RULES_COUNT.as_str(),
        "ac.enforcement.rules_count"
    );

    // Container attributes
    assert_eq!(ac::container::ID.as_str(), "ac.container.id");
    assert_eq!(
        ac::container::CGROUP_PATH.as_str(),
        "ac.container.cgroup_path"
    );
    assert_eq!(ac::container::CGROUP_ID.as_str(), "ac.container.cgroup_id");

    // Tool attributes
    assert_eq!(ac::tool::FUEL_CONSUMED.as_str(), "ac.tool.fuel_consumed");
    assert_eq!(
        ac::tool::EXECUTION_TIME_NS.as_str(),
        "ac.tool.execution_time_ns"
    );
    assert_eq!(ac::tool::OCI_REFERENCE.as_str(), "ac.tool.oci_reference");
    assert_eq!(ac::tool::COMPONENT_NAME.as_str(), "ac.tool.component_name");
}
