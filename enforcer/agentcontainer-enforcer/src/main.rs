//! agentcontainer-enforcer: Userspace BPF enforcement daemon for agentcontainers.
//!
//! This binary:
//! 1. Loads BPF programs (network hooks, LSM hooks, DNS parser)
//! 2. Manages BPF maps (policy insertion, cgroup registration)
//! 3. Consumes ring buffer events and streams them via gRPC
//! 4. Serves a gRPC API for the Go CLI to apply/remove enforcement policies

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tracing::info;

/// Ephemeral session credentials written by the enforcer at startup.
struct SessionCerts {
    /// Server certificate PEM (for `tonic::transport::Identity`).
    server_cert_pem: Vec<u8>,
    /// Server private key PEM.
    server_key_pem: Vec<u8>,
    /// CA certificate PEM (trusted by both sides).
    ca_cert_pem: Vec<u8>,
}

/// Generate a self-signed CA, then issue a server cert and a client cert from it.
/// Writes five PEM files to `creds_dir` (created 0700 if it does not exist):
///   server.crt, server.key, client-ca.crt, client.crt, client.key
/// Returns the in-memory PEM data needed to build the Tonic ServerTlsConfig.
fn generate_session_certs(creds_dir: &str) -> anyhow::Result<SessionCerts> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose};

    // --- CA key pair + certificate (self-signed) ---
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "agentcontainer-enforcer ephemeral CA");
    ca_params.distinguished_name = ca_dn;
    ca_params.subject_alt_names = vec![];
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let ca_cert_pem = ca_cert.pem().into_bytes();
    let ca_key_pem = ca_key.serialize_pem().into_bytes();

    // --- Server cert (SAN = localhost / 127.0.0.1) ---
    let srv_key = KeyPair::generate()?;
    let srv_params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    let srv_cert = srv_params.signed_by(&srv_key, &ca_cert, &ca_key)?;
    let server_cert_pem = srv_cert.pem().into_bytes();
    let server_key_pem = srv_key.serialize_pem().into_bytes();

    // --- Client cert (signed by same CA) ---
    let cli_key = KeyPair::generate()?;
    let mut cli_params = CertificateParams::default();
    cli_params.subject_alt_names = vec![];
    let mut cli_dn = DistinguishedName::new();
    cli_dn.push(DnType::CommonName, "ac client");
    cli_params.distinguished_name = cli_dn;
    let cli_cert = cli_params.signed_by(&cli_key, &ca_cert, &ca_key)?;
    let client_cert_pem = cli_cert.pem().into_bytes();
    let client_key_pem = cli_key.serialize_pem().into_bytes();

    // Suppress unused variable warning for ca_key_pem (kept as documentation that
    // the key is available if we later write it for debugging purposes).
    let _ = &ca_key_pem;

    // --- Write files ---
    let dir = std::path::Path::new(creds_dir);
    std::fs::create_dir_all(dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }

    let write_0600 = |name: &str, data: &[u8]| -> anyhow::Result<()> {
        let path = dir.join(name);
        std::fs::write(&path, data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    };

    write_0600("server.crt", &server_cert_pem)?;
    write_0600("server.key", &server_key_pem)?;
    write_0600("client-ca.crt", &ca_cert_pem)?;
    write_0600("client.crt", &client_cert_pem)?;
    write_0600("client.key", &client_key_pem)?;

    info!(creds_dir = %creds_dir, "ephemeral session certs written");

    Ok(SessionCerts {
        server_cert_pem,
        server_key_pem,
        ca_cert_pem,
    })
}

use agentcontainer_common::bundle::PolicyBundle;
use agentcontainer_enforcer::{bpf, grpc, policy};

/// agentcontainer-enforcer — BPF enforcement daemon for agentcontainers.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// gRPC listen address.
    #[arg(long, default_value = "127.0.0.1:50051")]
    listen: String,

    /// Unix socket path (alternative to TCP).
    #[arg(long)]
    socket: Option<String>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, default_value = "info")]
    log_level: String,

    /// OTLP endpoint for trace export (e.g. http://localhost:4317).
    /// Also reads OTEL_EXPORTER_OTLP_ENDPOINT env var.
    #[cfg(feature = "otel")]
    #[arg(long, env = "OTEL_EXPORTER_OTLP_ENDPOINT")]
    otlp_endpoint: Option<String>,

    /// OTLP transport protocol: grpc or http.
    #[cfg(feature = "otel")]
    #[arg(long, default_value = "grpc")]
    otlp_protocol: String,

    // --- TLS ---
    /// Path to the server TLS certificate (PEM). When set, the server requires
    /// mTLS from all gRPC clients. If omitted, the server runs without TLS
    /// (suitable for local Unix-socket or loopback-only deployments).
    #[arg(long, env = "AC_ENFORCER_TLS_CERT")]
    tls_cert: Option<String>,

    /// Path to the server TLS private key (PEM).
    #[arg(long, env = "AC_ENFORCER_TLS_KEY")]
    tls_key: Option<String>,

    /// Path to the CA certificate (PEM) used to verify client certificates.
    /// Required when `--tls-cert` is provided to enforce mutual TLS.
    #[arg(long, env = "AC_ENFORCER_TLS_CA")]
    tls_ca: Option<String>,

    // --- Policy bundle ---
    /// Path to the signed policy bundle JSON file.  When provided, the enforcer
    /// validates every incoming `ApplyXxxPolicy` RPC against this baseline and
    /// rejects requests that would grant more permission than the bundle allows.
    #[arg(long, env = "AC_ENFORCER_POLICY_BUNDLE")]
    policy_bundle: Option<String>,

    // --- Ephemeral session credentials ---
    /// Directory where the enforcer writes its ephemeral session credentials
    /// (server cert/key + CA cert) so that the `ac` CLI can establish mTLS.
    /// The enforcer creates the directory (0700) and writes three files:
    ///   server.crt — server certificate (PEM)
    ///   server.key — server private key (PEM)
    ///   client-ca.crt — CA that the client cert must be issued by (same self-signed CA)
    ///   client.crt — client certificate for `ac` to present (PEM)
    ///   client.key — client private key for `ac` to present (PEM)
    ///
    /// When set, the enforcer ignores --tls-cert/--tls-key/--tls-ca and uses
    /// generated ephemeral certs instead.  This is the recommended mode for
    /// production; --tls-* flags are provided for testing and CI.
    #[arg(long, env = "AC_ENFORCER_CREDS_DIR")]
    creds_dir: Option<String>,
}

/// Drain period: time between setting NOT_SERVING and hard shutdown.
const DRAIN_DURATION: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // --- Tracing subscriber setup ---
    // When the `otel` feature is enabled AND an OTLP endpoint is provided,
    // we build a layered subscriber: fmt + OpenTelemetryLayer.
    // Otherwise, we use the plain fmt subscriber.
    #[cfg(feature = "otel")]
    let _otel_provider = {
        use agentcontainer_enforcer::telemetry;
        use opentelemetry::trace::TracerProvider as _;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        use tracing_subscriber::EnvFilter;

        if let Some(ref endpoint) = args.otlp_endpoint {
            let protocol: telemetry::OtlpProtocol = args.otlp_protocol.parse()?;
            let provider = telemetry::init_tracer_provider(endpoint, protocol)?;

            let otel_layer = tracing_opentelemetry::layer()
                .with_tracer(provider.tracer("agentcontainer-enforcer"));

            tracing_subscriber::registry()
                .with(EnvFilter::new(&args.log_level))
                .with(tracing_subscriber::fmt::layer())
                .with(otel_layer)
                .init();

            info!(endpoint = %endpoint, protocol = %args.otlp_protocol, "OTel tracing enabled");
            Some(provider)
        } else {
            tracing_subscriber::fmt()
                .with_env_filter(&args.log_level)
                .init();
            None
        }
    };

    #[cfg(not(feature = "otel"))]
    {
        tracing_subscriber::fmt()
            .with_env_filter(&args.log_level)
            .init();
    }

    info!("agentcontainer-enforcer starting");

    // --- Policy bundle ---
    // Load and validate the signed policy bundle if a path was provided.
    let policy_bundle: Option<Arc<PolicyBundle>> = if let Some(ref path) = args.policy_bundle {
        let json = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read policy bundle {path}: {e}"))?;
        let bundle = PolicyBundle::from_json(&json)
            .map_err(|e| anyhow::anyhow!("failed to parse policy bundle {path}: {e}"))?;
        info!(path = %path, "loaded policy bundle");
        Some(Arc::new(bundle))
    } else {
        info!("no policy bundle provided — ACL re-derivation disabled");
        None
    };

    // --- TLS configuration ---
    // When --creds-dir is set, generate ephemeral session certs and use them for
    // mTLS.  This is the recommended production mode.  --tls-cert/--tls-key/--tls-ca
    // are provided as an escape hatch for testing and CI environments that supply
    // their own certificates.
    let tls_config: Option<tonic::transport::ServerTlsConfig> = if let Some(ref creds_dir) =
        args.creds_dir
    {
        let session = generate_session_certs(creds_dir)?;
        let identity =
            tonic::transport::Identity::from_pem(session.server_cert_pem, session.server_key_pem);
        let ca = tonic::transport::Certificate::from_pem(session.ca_cert_pem);
        let cfg = tonic::transport::ServerTlsConfig::new()
            .identity(identity)
            .client_ca_root(ca);
        info!(creds_dir = %creds_dir, "ephemeral mTLS enabled");
        Some(cfg)
    } else {
        match (&args.tls_cert, &args.tls_key) {
            (Some(cert_path), Some(key_path)) => {
                let cert_pem = std::fs::read(cert_path)
                    .map_err(|e| anyhow::anyhow!("read TLS cert {cert_path}: {e}"))?;
                let key_pem = std::fs::read(key_path)
                    .map_err(|e| anyhow::anyhow!("read TLS key {key_path}: {e}"))?;
                let identity = tonic::transport::Identity::from_pem(cert_pem, key_pem);

                let mut cfg = tonic::transport::ServerTlsConfig::new().identity(identity);

                if let Some(ref ca_path) = args.tls_ca {
                    let ca_pem = std::fs::read(ca_path)
                        .map_err(|e| anyhow::anyhow!("read CA cert {ca_path}: {e}"))?;
                    let ca = tonic::transport::Certificate::from_pem(ca_pem);
                    cfg = cfg.client_ca_root(ca);
                    info!(cert = %cert_path, key = %key_path, ca = %ca_path, "mTLS enabled");
                } else {
                    info!(cert = %cert_path, key = %key_path, "TLS enabled (server-only, no client verification)");
                }
                Some(cfg)
            }
            (None, None) => {
                info!("TLS disabled — running in plaintext mode");
                None
            }
            _ => {
                anyhow::bail!("--tls-cert and --tls-key must both be provided together");
            }
        }
    };

    // Health check service.
    let (health_reporter, health_service) = tonic_health::server::health_reporter();

    // Build the enforcer gRPC service.
    // BpfPolicyManager uses real BPF on Linux, stub on macOS.
    let manager: Arc<dyn policy::PolicyManager> = Arc::new(bpf::BpfPolicyManager::new()?);
    let enforcer_service = grpc::make_server_with_bundle(manager, policy_bundle)?;

    // Mark the enforcer service as SERVING.
    health_reporter
        .set_serving::<grpc::proto::enforcer_server::EnforcerServer<grpc::EnforcerService>>()
        .await;

    // Shared shutdown signal: fires on ctrl_c or SIGTERM.
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());

    // Helper: build a Tonic server builder with optional TLS.
    let build_server = |tls: Option<tonic::transport::ServerTlsConfig>| {
        let mut b = tonic::transport::Server::builder();
        if let Some(cfg) = tls {
            b = b.tls_config(cfg).expect("invalid TLS config");
        }
        b
    };

    // Spawn TCP server.
    let tcp_handle = {
        let addr = args.listen.parse()?;
        let notify = shutdown_notify.clone();
        let enforcer_svc = enforcer_service.clone();
        let health_svc = health_service.clone();
        let tls = tls_config.clone();
        info!(listen = %addr, "starting gRPC TCP server");

        tokio::spawn(async move {
            build_server(tls)
                .add_service(health_svc)
                .add_service(enforcer_svc)
                .serve_with_shutdown(addr, notify.notified())
                .await
        })
    };

    // Optionally spawn UDS server.
    // UDS connections are inherently local so TLS is not applied.
    let uds_handle = if let Some(ref socket_path) = args.socket {
        let path = std::path::PathBuf::from(socket_path);

        // Remove stale socket file if it exists.
        if path.exists() {
            std::fs::remove_file(&path)?;
        }

        let uds = tokio::net::UnixListener::bind(&path)?;
        let uds_stream = tokio_stream::wrappers::UnixListenerStream::new(uds);
        let notify = shutdown_notify.clone();
        let enforcer_svc = enforcer_service.clone();
        let health_svc = health_service.clone();
        info!(socket = %path.display(), "starting gRPC UDS server");

        Some(tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(health_svc)
                .add_service(enforcer_svc)
                .serve_with_incoming_shutdown(uds_stream, notify.notified())
                .await
        }))
    } else {
        None
    };

    // Wait for shutdown signal (ctrl_c or SIGTERM).
    {
        let ctrl_c = tokio::signal::ctrl_c();

        #[cfg(unix)]
        {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to register SIGTERM handler");
            tokio::select! {
                _ = ctrl_c => {}
                _ = sigterm.recv() => {}
            }
        }

        #[cfg(not(unix))]
        {
            ctrl_c.await.ok();
        }
    }

    info!("shutdown signal received, draining");

    // Set health to NOT_SERVING for graceful drain.
    health_reporter
        .set_not_serving::<grpc::proto::enforcer_server::EnforcerServer<grpc::EnforcerService>>()
        .await;

    // Allow in-flight RPCs to complete.
    tokio::time::sleep(DRAIN_DURATION).await;

    // Signal all servers to stop.
    shutdown_notify.notify_waiters();

    // Wait for servers to finish.
    tcp_handle.await??;
    if let Some(h) = uds_handle {
        h.await??;
    }

    // Clean up UDS socket file.
    if let Some(ref socket_path) = args.socket {
        let _ = std::fs::remove_file(socket_path);
    }

    // Shut down OTel tracer provider (flush pending spans).
    #[cfg(feature = "otel")]
    if let Some(ref provider) = _otel_provider {
        agentcontainer_enforcer::telemetry::shutdown_tracer_provider(provider);
    }

    info!("shutdown complete");
    Ok(())
}
