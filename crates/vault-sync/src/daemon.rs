//! TCP sync daemon with TLS and HMAC authentication.
//!
//! Provides a TLS-encrypted TCP listener that handles sync requests from peers,
//! and a periodic sync loop that initiates sync with configured peers.
//! All frames are authenticated with HMAC-SHA256 derived from the vault passphrase.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{ClientConfig, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, error, info, warn};

use vault_core::config;
use vault_core::crypto;
use vault_core::db::CrSqliteDatabase;

use crate::capabilities::PeerCapabilities;
use crate::protocol::{
    MessageType, WireFrame, CONNECTION_TIMEOUT_SECS, HEADER_SIZE_V2, HMAC_SIZE, MAX_PAYLOAD_SIZE,
    READ_TIMEOUT_SECS,
};
use crate::serde_wire::{
    self, HelloAckMessage, HelloMessage, SyncRequest, SyncResponse, TriggerAck,
};

/// Get the PID file path (cross-platform).
fn pid_file_path() -> std::path::PathBuf {
    if cfg!(target_os = "windows") {
        // On Windows, use %TEMP% since there's no /tmp
        std::env::temp_dir().join("memxp-daemon.pid")
    } else {
        std::path::PathBuf::from("/tmp/memxp-daemon.pid")
    }
}

/// Configuration for the sync daemon.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub db_path: PathBuf,
    pub passphrase: String,
    pub extension_path: Option<PathBuf>,
    pub bind_address: String,
    pub port: u16,
    pub peers: Vec<String>,
    pub allowed_ips: Vec<String>,
    pub sync_interval_secs: u32,
    pub max_payload_bytes: usize,
    pub insecure_skip_tls_verify: bool,
    pub peer_cert_fingerprint: Option<String>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        // Default bind to Tailscale IP; fall back to 127.0.0.1 (never 0.0.0.0)
        let bind = config::get_local_machine_id();
        let bind_address = if bind.starts_with("100.") {
            bind
        } else {
            "127.0.0.1".to_string()
        };

        Self {
            db_path: config::db_path(),
            passphrase: String::new(),
            extension_path: Some(config::cr_sqlite_extension_path()),
            bind_address,
            port: vault_core::models::DEFAULT_SYNC_PORT,
            peers: Vec::new(),
            allowed_ips: Vec::new(),
            sync_interval_secs: vault_core::models::DEFAULT_SYNC_INTERVAL,
            max_payload_bytes: MAX_PAYLOAD_SIZE,
            insecure_skip_tls_verify: false,
            peer_cert_fingerprint: None,
        }
    }
}

fn certificate_fingerprint(cert: &CertificateDer<'_>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(cert.as_ref());
    let sum = hasher.finalize();
    sum.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn normalize_fingerprint(raw: &str) -> anyhow::Result<String> {
    let cleaned: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.is_empty() {
        anyhow::bail!("peer certificate fingerprint cannot be empty");
    }
    if cleaned.len() != 64 {
        anyhow::bail!("peer certificate fingerprint must be 32-byte SHA-256 hex (64 chars)");
    }
    for i in (0..cleaned.len()).step_by(2) {
        u8::from_str_radix(&cleaned[i..i + 2], 16)
            .map_err(|_| anyhow::anyhow!("peer certificate fingerprint is not valid hex"))?;
    }
    Ok(cleaned.to_ascii_lowercase())
}

#[derive(Debug)]
struct FingerprintVerifier {
    expected_fingerprint: String,
}

impl rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let actual = certificate_fingerprint(end_entity);
        if actual != self.expected_fingerprint {
            return Err(rustls::Error::General(format!(
                "peer certificate fingerprint mismatch: expected {}, got {}",
                self.expected_fingerprint, actual
            )));
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Return the TLS certificate/key directory (`~/.memxp/tls/`).
/// Creates the directory (mode 0o700 on Unix) if it does not exist.
fn cert_dir() -> std::io::Result<std::path::PathBuf> {
    let dir = vault_core::config::vault_base_dir().join("tls");
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(dir)
}

/// Load an existing self-signed cert/key from `tls_dir`, or generate and persist a new pair.
fn load_or_generate_cert_in(
    tls_dir: &std::path::Path,
) -> std::io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_path = tls_dir.join("daemon-cert.der");
    let key_path = tls_dir.join("daemon-key.der");

    if cert_path.exists() && key_path.exists() {
        let cert_bytes = std::fs::read(&cert_path)?;
        let key_bytes = std::fs::read(&key_path)?;
        let cert_der = CertificateDer::from(cert_bytes);
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes));
        info!(
            "Loaded existing TLS certificate from {}",
            cert_path.display()
        );
        return Ok((vec![cert_der], key_der));
    }

    // Generate a new self-signed certificate
    let cert = rcgen::generate_simple_self_signed(vec!["memxp.local".to_string()])
        .map_err(|e| std::io::Error::other(format!("TLS cert generation failed: {e}")))?;
    let cert_der = CertificateDer::from(cert.cert);
    let key_bytes = cert.key_pair.serialize_der();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_bytes.clone()));

    // Persist to disk
    std::fs::write(&cert_path, cert_der.as_ref())?;
    std::fs::write(&key_path, &key_bytes)?;

    // Restrict key file permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    let fp = certificate_fingerprint(&cert_der);
    info!(
        "Generated new TLS certificate (fingerprint: {fp}), saved to {}",
        cert_path.display()
    );

    Ok((vec![cert_der], key_der))
}

/// Load or generate a self-signed TLS certificate for the sync daemon.
/// Persists the cert and key to the vault data dir's `tls/` so the fingerprint is stable across restarts.
fn load_or_generate_cert() -> std::io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>
{
    let dir = cert_dir()?;
    load_or_generate_cert_in(&dir)
}

/// Build a TLS server config with a self-signed certificate.
fn build_tls_server_config() -> std::io::Result<Arc<ServerConfig>> {
    let (certs, key) = load_or_generate_cert()?;
    let fp = certificate_fingerprint(&certs[0]);
    info!("TLS server certificate fingerprint: {fp}");
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| std::io::Error::other(format!("TLS server config failed: {e}")))?;
    Ok(Arc::new(config))
}

/// Build a TLS client config.
/// - strict by default: requires peer cert fingerprint
/// - dev mode: `insecure_skip_tls_verify` keeps existing behavior
fn build_tls_client_config(
    insecure_skip_tls_verify: bool,
    peer_cert_fingerprint: Option<&str>,
) -> anyhow::Result<Arc<ClientConfig>> {
    if insecure_skip_tls_verify {
        warn!(
            "WARNING: TLS certificate verification disabled for daemon sync client. Development-only mode."
        );
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        return Ok(Arc::new(config));
    }

    let Some(raw_fingerprint) = peer_cert_fingerprint else {
        anyhow::bail!(
            "TLS certificate verification is strict by default. Set --peer-cert-fingerprint \
             (SHA-256 hex) or --insecure-skip-tls-verify."
        )
    };

    let expected_fingerprint = normalize_fingerprint(raw_fingerprint)?;
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(FingerprintVerifier {
            expected_fingerprint,
        }))
        .with_no_client_auth();

    Ok(Arc::new(config))
}

/// A certificate verifier that accepts any certificate.
/// Authentication is handled at the protocol layer via HMAC.
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Generate a random 16-byte nonce, hex-encoded.
fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    crypto::hex::encode(&bytes)
}

/// The sync daemon state.
pub struct SyncDaemon {
    config: DaemonConfig,
    db: Arc<Mutex<CrSqliteDatabase>>,
    peer_capabilities: Arc<Mutex<std::collections::HashMap<String, PeerCapabilities>>>,
    hmac_key: [u8; 32],
}

impl SyncDaemon {
    /// Create a new sync daemon.
    pub fn new(config: DaemonConfig, db: CrSqliteDatabase) -> Self {
        let hmac_key = crypto::derive_sync_hmac_key(&config.passphrase);
        Self {
            config,
            db: Arc::new(Mutex::new(db)),
            peer_capabilities: Arc::new(Mutex::new(std::collections::HashMap::new())),
            hmac_key,
        }
    }

    /// Run the sync daemon (TLS listener + periodic sync loop).
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = format!("{}:{}", self.config.bind_address, self.config.port);
        let listener = TcpListener::bind(&addr).await?;
        info!("Sync daemon listening on {addr} (TLS + HMAC v3)");

        // Write PID file
        let _ = write_pid_file();

        // Build TLS server config
        let tls_acceptor = TlsAcceptor::from(build_tls_server_config()?);

        let db = self.db.clone();
        let peer_caps = self.peer_capabilities.clone();
        let max_payload = self.config.max_payload_bytes;
        let hmac_key = self.hmac_key;

        // Compute effective allowlist: allowed_ips if set, otherwise peers
        let allowed = effective_allowed_ips(&self.config.allowed_ips, &self.config.peers);
        if allowed.is_empty() {
            warn!("No allowed IPs or peers configured — all incoming connections will be rejected");
        } else {
            info!("Peer allowlist: {:?}", allowed);
        }

        // Spawn listener task
        let listener_handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let peer_ip = addr.ip().to_string();
                        if !is_ip_allowed(&peer_ip, &allowed) {
                            warn!("Rejected connection from {addr} (not in allowlist)");
                            drop(stream);
                            continue;
                        }
                        debug!("Accepted connection from {addr}");

                        let tls_acceptor = tls_acceptor.clone();
                        let db = db.clone();
                        let caps = peer_caps.clone();
                        tokio::spawn(async move {
                            let tls_stream = match tls_acceptor.accept(stream).await {
                                Ok(s) => s,
                                Err(e) => {
                                    warn!("TLS handshake failed from {addr}: {e}");
                                    return;
                                }
                            };
                            if let Err(e) =
                                handle_connection(tls_stream, db, caps, max_payload, hmac_key).await
                            {
                                warn!("Connection error from {addr}: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        error!("Accept error: {e}");
                    }
                }
            }
        });

        // Spawn periodic sync task
        let peers = self.config.peers.clone();
        let interval = self.config.sync_interval_secs;
        let db = self.db.clone();
        let peer_caps = self.peer_capabilities.clone();
        let port = self.config.port;
        let max_payload = self.config.max_payload_bytes;
        let hmac_key = self.hmac_key;
        let insecure_skip_tls_verify = self.config.insecure_skip_tls_verify;
        let peer_cert_fingerprint = self.config.peer_cert_fingerprint.clone();

        let sync_handle = tokio::spawn(async move {
            let mut interval_timer =
                tokio::time::interval(tokio::time::Duration::from_secs(interval as u64));

            loop {
                interval_timer.tick().await;
                for peer in &peers {
                    let peer_addr = if peer.contains(':') {
                        peer.clone()
                    } else {
                        format!("{peer}:{port}")
                    };

                    debug!("Initiating sync with {peer_addr}");
                    if let Err(e) = initiate_sync(
                        &peer_addr,
                        &db,
                        &peer_caps,
                        max_payload,
                        &hmac_key,
                        insecure_skip_tls_verify,
                        peer_cert_fingerprint.as_deref(),
                    )
                    .await
                    {
                        warn!("Sync with {peer_addr} failed: {e}");
                    }
                }
            }
        });

        // Wait for either task to finish (they shouldn't)
        tokio::select! {
            _ = listener_handle => {},
            _ = sync_handle => {},
        }

        Ok(())
    }
}

/// Read a single authenticated frame from a stream.
async fn read_frame(
    stream: &mut (impl AsyncReadExt + Unpin),
    max_payload: usize,
    hmac_key: &[u8; 32],
) -> Result<WireFrame, Box<dyn std::error::Error + Send + Sync>> {
    let timeout = tokio::time::Duration::from_secs(READ_TIMEOUT_SECS);

    // Read header (30 bytes)
    let mut header = vec![0u8; HEADER_SIZE_V2];
    tokio::time::timeout(timeout, stream.read_exact(&mut header)).await??;

    // Parse payload length from header
    if &header[..9] != b"VAULT_P2P" {
        return Err("invalid magic".into());
    }
    let version = header[9];
    if version != 0x03 {
        return Err(format!("unsupported version: {version}").into());
    }
    let payload_len = u32::from_be_bytes([header[10], header[11], header[12], header[13]]) as usize;
    if payload_len > max_payload {
        return Err(format!("payload too large: {payload_len}").into());
    }

    // Read payload + HMAC
    let remaining = payload_len + HMAC_SIZE;
    let mut rest = vec![0u8; remaining];
    tokio::time::timeout(timeout, stream.read_exact(&mut rest)).await??;

    // Concatenate and verify
    let mut full_frame = Vec::with_capacity(HEADER_SIZE_V2 + remaining);
    full_frame.extend_from_slice(&header);
    full_frame.extend_from_slice(&rest);

    Ok(WireFrame::unpack_authenticated(&full_frame, hmac_key)?)
}

/// Write an authenticated frame to a stream.
async fn write_frame(
    stream: &mut (impl AsyncWriteExt + Unpin),
    frame: WireFrame,
    hmac_key: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let timeout = tokio::time::Duration::from_secs(READ_TIMEOUT_SECS);
    let packed = frame.pack_authenticated(hmac_key)?;
    tokio::time::timeout(timeout, stream.write_all(&packed)).await??;
    stream.flush().await?;
    Ok(())
}

/// Handle an incoming TLS connection (loops until client disconnects).
async fn handle_connection(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    db: Arc<Mutex<CrSqliteDatabase>>,
    peer_caps: Arc<Mutex<std::collections::HashMap<String, PeerCapabilities>>>,
    max_payload: usize,
    hmac_key: [u8; 32],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        let frame = match read_frame(&mut stream, max_payload, &hmac_key).await {
            Ok(f) => f,
            Err(e) => {
                // EOF or timeout = normal close
                debug!("Connection ended: {e}");
                break;
            }
        };

        let response = match frame.msg_type {
            MessageType::Hello => handle_hello(&frame.payload, &db, &peer_caps).await?,
            MessageType::SyncRequest => handle_sync_request(&frame.payload, &db).await?,
            MessageType::SyncTrigger => handle_sync_trigger(&frame.payload).await?,
            _ => {
                debug!("Ignoring message type: {:?}", frame.msg_type);
                continue;
            }
        };

        write_frame(&mut stream, response, &hmac_key).await?;
    }

    Ok(())
}

/// Handle a HELLO message.
async fn handle_hello(
    payload: &[u8],
    db: &Arc<Mutex<CrSqliteDatabase>>,
    peer_caps: &Arc<Mutex<std::collections::HashMap<String, PeerCapabilities>>>,
) -> Result<WireFrame, Box<dyn std::error::Error + Send + Sync>> {
    let hello: HelloMessage = serde_json::from_slice(payload)?;
    debug!("HELLO from site_id={}", hello.site_id);

    // Validate nonce is present
    if hello.nonce.is_empty() {
        return Err("HELLO missing nonce".into());
    }

    // Store peer capabilities
    let caps = PeerCapabilities {
        supported_tables: hello.supported_tables.into_iter().collect(),
        supported_features: hello.supported_features.into_iter().collect(),
        schema_version: hello.schema_version,
    };
    peer_caps.lock().await.insert(hello.site_id.clone(), caps);

    // Build HELLO_ACK
    let db = db.lock().await;
    let local_caps = PeerCapabilities::default();
    let site_id = db
        .conn()
        .query_row("SELECT hex(crsql_site_id())", [], |row| {
            row.get::<_, String>(0)
        })
        .unwrap_or_else(|_| "unknown".to_string());
    let db_version = db
        .conn()
        .query_row("SELECT crsql_db_version()", [], |row| row.get::<_, i64>(0))
        .unwrap_or(0);

    let ack = HelloAckMessage {
        site_id,
        protocol_version: crate::protocol::PROTOCOL_VERSION,
        supported_tables: local_caps.supported_tables.into_iter().collect(),
        supported_features: local_caps.supported_features.into_iter().collect(),
        schema_version: local_caps.schema_version,
        peer_nonce: hello.nonce,
        db_version,
    };

    let payload = serde_json::to_vec(&ack)?;
    Ok(WireFrame::new(MessageType::HelloAck, payload))
}

/// Handle a SYNC_REQUEST message.
async fn handle_sync_request(
    payload: &[u8],
    db: &Arc<Mutex<CrSqliteDatabase>>,
) -> Result<WireFrame, Box<dyn std::error::Error + Send + Sync>> {
    let request: SyncRequest = serde_json::from_slice(payload)?;
    debug!(
        "SYNC_REQUEST from site_id={}, db_version={}, changes={}",
        request.site_id,
        request.db_version,
        request.changes.len()
    );

    let db = db.lock().await;

    // Apply incoming changes
    let incoming = serde_wire::decode_changes(&request.changes);
    if !incoming.is_empty() {
        match db.apply_changes(&incoming) {
            Ok(n) => debug!("Applied {n} changes from {}", request.site_id),
            Err(e) => warn!("Failed to apply changes: {e}"),
        }
    }

    // Get changes to send back
    let outgoing = db
        .get_changes_since(request.last_seen_version)
        .unwrap_or_default();
    let encoded = serde_wire::encode_changes(&outgoing);

    let db_version = db
        .conn()
        .query_row("SELECT crsql_db_version()", [], |row| row.get::<_, i64>(0))
        .unwrap_or(0);

    let site_id = db
        .conn()
        .query_row("SELECT hex(crsql_site_id())", [], |row| {
            row.get::<_, String>(0)
        })
        .unwrap_or_else(|_| "unknown".to_string());

    let response = SyncResponse {
        site_id,
        db_version,
        changes: encoded,
        current_version: db_version,
        has_more_changes: false,
    };

    let payload = serde_json::to_vec(&response)?;
    Ok(WireFrame::new(MessageType::SyncResponse, payload))
}

/// Handle a SYNC_TRIGGER message.
async fn handle_sync_trigger(
    payload: &[u8],
) -> Result<WireFrame, Box<dyn std::error::Error + Send + Sync>> {
    let trigger: serde_wire::SyncTrigger = serde_json::from_slice(payload)?;
    debug!(
        "SYNC_TRIGGER from site_id={}, reason={}",
        trigger.site_id, trigger.reason
    );

    let ack = TriggerAck {
        status: "ok".to_string(),
        will_sync: true,
    };

    let payload = serde_json::to_vec(&ack)?;
    Ok(WireFrame::new(MessageType::TriggerAck, payload))
}

/// Initiate a sync with a remote peer over TLS.
///
/// IMPORTANT: DB lock is acquired only for brief DB operations, NOT held during
/// network I/O. This prevents deadlock when both peers initiate sync simultaneously
/// (each holds its DB lock while waiting for the other's response).
async fn initiate_sync(
    peer_addr: &str,
    db: &Arc<Mutex<CrSqliteDatabase>>,
    _peer_caps: &Arc<Mutex<std::collections::HashMap<String, PeerCapabilities>>>,
    max_payload: usize,
    hmac_key: &[u8; 32],
    insecure_skip_tls_verify: bool,
    peer_cert_fingerprint: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let conn_timeout = tokio::time::Duration::from_secs(CONNECTION_TIMEOUT_SECS);

    // Connect with TLS
    let tcp_stream =
        tokio::time::timeout(conn_timeout, tokio::net::TcpStream::connect(peer_addr)).await??;

    let tls_connector = TlsConnector::from(build_tls_client_config(
        insecure_skip_tls_verify,
        peer_cert_fingerprint,
    )?);
    let server_name =
        rustls::pki_types::ServerName::try_from("memxp.local").expect("valid server name");
    let mut stream = tls_connector.connect(server_name, tcp_stream).await?;

    // Brief lock: get site ID for HELLO
    let site_id = {
        let db = db.lock().await;
        db.conn()
            .query_row("SELECT hex(crsql_site_id())", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap_or_else(|_| "unknown".to_string())
    };

    // --- HELLO handshake (no DB lock needed) ---
    let our_nonce = generate_nonce();
    let local_caps = PeerCapabilities::default();

    let hello = HelloMessage {
        site_id: site_id.clone(),
        protocol_version: crate::protocol::PROTOCOL_VERSION,
        supported_tables: local_caps.supported_tables.iter().cloned().collect(),
        supported_features: local_caps.supported_features.iter().cloned().collect(),
        schema_version: local_caps.schema_version,
        nonce: our_nonce.clone(),
    };

    let hello_payload = serde_json::to_vec(&hello)?;
    let hello_frame = WireFrame::new(MessageType::Hello, hello_payload);
    write_frame(&mut stream, hello_frame, hmac_key).await?;

    // Read HELLO_ACK (no DB lock needed)
    let ack_frame = read_frame(&mut stream, max_payload, hmac_key).await?;
    let hello_ack: HelloAckMessage = serde_json::from_slice(&ack_frame.payload)?;

    // Verify nonce echo
    if hello_ack.peer_nonce != our_nonce {
        return Err(format!(
            "nonce mismatch: expected {}, got {}",
            our_nonce, hello_ack.peer_nonce
        )
        .into());
    }
    debug!(
        "HELLO handshake complete with peer site_id={}",
        hello_ack.site_id
    );

    // Brief lock: prepare SYNC_REQUEST data
    let (last_seen, db_version, changes, encoded) = {
        let db = db.lock().await;
        let peer_site_id = &hello_ack.site_id;
        let last_seen = db.get_peer_version(peer_site_id);
        let db_version = db
            .conn()
            .query_row("SELECT crsql_db_version()", [], |row| row.get::<_, i64>(0))
            .unwrap_or(0);
        let all_changes = db.get_changes_since(last_seen).unwrap_or_default();
        let (changes, _has_more) = serde_wire::limit_changes_by_size(&all_changes, max_payload);
        let encoded = serde_wire::encode_changes(&changes);
        (last_seen, db_version, changes, encoded)
    };

    let request = SyncRequest {
        site_id,
        db_version,
        changes: encoded,
        last_seen_version: last_seen,
    };

    let req_payload = serde_json::to_vec(&request)?;
    let req_frame = WireFrame::new(MessageType::SyncRequest, req_payload);
    write_frame(&mut stream, req_frame, hmac_key).await?;

    // Read SYNC_RESPONSE (no DB lock needed)
    let resp_frame = read_frame(&mut stream, max_payload, hmac_key).await?;
    let response: SyncResponse = serde_json::from_slice(&resp_frame.payload)?;

    // Brief lock: apply changes and update peer tracking
    let incoming = serde_wire::decode_changes(&response.changes);
    {
        let db = db.lock().await;
        if !incoming.is_empty() {
            match db.apply_changes(&incoming) {
                Ok(n) => debug!("Applied {n} changes from peer"),
                Err(e) => warn!("Failed to apply response changes: {e}"),
            }
        }
        db.update_peer_version(&hello_ack.site_id, response.current_version, peer_addr);
    }

    info!(
        "Sync complete with {}: sent={}, received={} (last_seen: {} -> {})",
        peer_addr,
        changes.len(),
        incoming.len(),
        last_seen,
        response.current_version
    );

    Ok(())
}

/// Write the daemon PID file.
fn write_pid_file() -> std::io::Result<()> {
    std::fs::write(pid_file_path(), std::process::id().to_string())
}

/// Check if a daemon is already running.
pub fn check_pid_file() -> Option<u32> {
    let content = std::fs::read_to_string(pid_file_path()).ok()?;
    let pid: u32 = content.trim().parse().ok()?;

    // Check if process is actually running
    #[cfg(unix)]
    {
        use std::process::Command;
        if Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Some(pid);
        }
    }

    #[cfg(windows)]
    {
        use std::process::Command;
        // On Windows, use tasklist to check if PID is running
        if let Ok(output) = Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            if text.contains(&pid.to_string()) {
                return Some(pid);
            }
        }
    }

    None
}

/// Remove the PID file.
pub fn remove_pid_file() {
    let _ = std::fs::remove_file(pid_file_path());
}

/// Extract the IP portion from an address string (strips port if present).
fn extract_ip(addr: &str) -> &str {
    // Handle IPv6 in brackets: [::1]:5480 -> ::1
    if addr.starts_with('[') {
        return addr.find(']').map(|i| &addr[1..i]).unwrap_or(addr);
    }
    // Bare IPv6 (multiple colons, no port): ::1 or fe80::1
    if addr.matches(':').count() > 1 {
        return addr;
    }
    // IPv4 with optional port: 100.64.1.1:5480 -> 100.64.1.1
    if let Some(colon) = addr.rfind(':') {
        &addr[..colon]
    } else {
        addr
    }
}

/// Check if an address is a valid Tailscale CGNAT IP.
pub fn is_tailscale_ip(addr: &str) -> bool {
    extract_ip(addr).starts_with("100.")
}

/// Compute the effective allowlist: explicit allowed_ips if non-empty,
/// otherwise fall back to the configured peers list.
/// Returns empty Vec only if both are empty (which means reject all).
pub fn effective_allowed_ips(allowed_ips: &[String], peers: &[String]) -> Vec<String> {
    if !allowed_ips.is_empty() {
        return allowed_ips.to_vec();
    }
    // Use peers as implicit allowlist (strip port suffixes)
    peers.iter().map(|p| extract_ip(p).to_string()).collect()
}

/// Check if a connecting address is allowed.
///
/// Belt-and-suspenders:
/// 1. Must be a Tailscale IP (100.x.x.x) OR localhost
/// 2. Must be in the effective allowlist (allowed_ips, or peers as fallback)
pub fn is_ip_allowed(addr: &str, allowed: &[String]) -> bool {
    let ip = extract_ip(addr);

    // Always allow localhost (for local testing / health checks)
    if ip == "127.0.0.1" || ip == "::1" {
        return true;
    }

    // Layer 1: Must be a Tailscale IP
    if !ip.starts_with("100.") {
        return false;
    }

    // Layer 2: Must be in the allowlist
    if allowed.is_empty() {
        // No peers configured = reject everything (fail-closed)
        return false;
    }

    allowed.iter().any(|a| extract_ip(a) == ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pid_file_lock() {
        let _ = std::fs::remove_file(pid_file_path());
        assert!(check_pid_file().is_none());

        write_pid_file().unwrap();
        let pid = check_pid_file();
        assert!(pid.is_some());
        assert_eq!(pid.unwrap(), std::process::id());

        remove_pid_file();
        assert!(check_pid_file().is_none());
    }

    #[test]
    fn test_is_tailscale_ip() {
        assert!(is_tailscale_ip("100.64.1.1"));
        assert!(is_tailscale_ip("100.64.1.1:5480"));
        assert!(!is_tailscale_ip("192.168.1.1"));
        assert!(!is_tailscale_ip("10.0.0.1:5480"));
        assert!(!is_tailscale_ip("0.0.0.0"));
        assert!(!is_tailscale_ip("127.0.0.1"));
        assert!(!is_tailscale_ip("8.8.8.8:5480"));
    }

    #[test]
    fn test_reject_non_tailscale_ip() {
        let allowed = vec!["100.64.1.1".to_string()];
        assert!(!is_ip_allowed("192.168.1.1", &allowed));
        assert!(!is_ip_allowed("10.0.0.1:5480", &allowed));
        assert!(!is_ip_allowed("172.16.0.1", &allowed));
        assert!(!is_ip_allowed("8.8.8.8:5480", &allowed));
        assert!(!is_ip_allowed("0.0.0.0", &allowed));
    }

    #[test]
    fn test_allowed_ips_enforcement() {
        let allowed = vec!["100.64.1.1".to_string(), "100.64.1.2".to_string()];
        assert!(is_ip_allowed("100.64.1.1", &allowed));
        assert!(is_ip_allowed("100.64.1.2", &allowed));
        assert!(!is_ip_allowed("100.64.1.4", &allowed)); // not in list
        assert!(!is_ip_allowed("192.168.1.1", &allowed));
    }

    #[test]
    fn test_allowed_ips_empty_rejects_all() {
        let allowed: Vec<String> = vec![];
        // Empty allowlist = fail-closed (reject non-localhost)
        assert!(!is_ip_allowed("100.64.1.1", &allowed));
        assert!(!is_ip_allowed("192.168.1.1", &allowed));
    }

    #[test]
    fn test_localhost_always_allowed() {
        let allowed: Vec<String> = vec![];
        assert!(is_ip_allowed("127.0.0.1", &allowed));
        assert!(is_ip_allowed("::1", &allowed));

        let allowed = vec!["100.64.1.1".to_string()];
        assert!(is_ip_allowed("127.0.0.1", &allowed));
    }

    #[test]
    fn test_allowed_ips_with_port() {
        let allowed = vec!["100.64.1.1".to_string()];
        assert!(is_ip_allowed("100.64.1.1:5480", &allowed));
        assert!(!is_ip_allowed("100.64.1.5:5480", &allowed));
    }

    #[test]
    fn test_effective_allowed_ips_uses_peers_as_fallback() {
        // When allowed_ips is empty, peers become the allowlist
        let allowed_ips: Vec<String> = vec![];
        let peers = vec!["100.64.1.2".to_string(), "100.64.1.3".to_string()];
        let effective = effective_allowed_ips(&allowed_ips, &peers);
        assert_eq!(effective, vec!["100.64.1.2", "100.64.1.3"]);
    }

    #[test]
    fn test_effective_allowed_ips_prefers_explicit() {
        // When allowed_ips is set, it takes precedence over peers
        let allowed_ips = vec!["100.64.1.1".to_string()];
        let peers = vec!["100.64.1.2".to_string()];
        let effective = effective_allowed_ips(&allowed_ips, &peers);
        assert_eq!(effective, vec!["100.64.1.1"]);
    }

    #[test]
    fn test_effective_allowed_ips_strips_port_from_peers() {
        let allowed_ips: Vec<String> = vec![];
        let peers = vec!["100.64.1.2:5480".to_string()];
        let effective = effective_allowed_ips(&allowed_ips, &peers);
        assert_eq!(effective, vec!["100.64.1.2"]);
    }

    #[test]
    fn test_default_bind_is_not_all_interfaces() {
        let cfg = DaemonConfig::default();
        assert_ne!(
            cfg.bind_address, "0.0.0.0",
            "Default bind address must not be 0.0.0.0"
        );
    }

    #[test]
    fn test_generate_nonce_format() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 32); // 16 bytes = 32 hex chars
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_nonce_unique() {
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_hmac_key_derived_from_passphrase() {
        let key = crypto::derive_sync_hmac_key("test-passphrase");
        assert_eq!(key.len(), 32);
        // Deterministic
        let key2 = crypto::derive_sync_hmac_key("test-passphrase");
        assert_eq!(key, key2);
    }

    #[test]
    fn test_cert_persistence_across_calls() {
        let tmp = tempfile::TempDir::new().unwrap();
        let tls_dir = tmp.path().join(".memxp").join("tls");
        std::fs::create_dir_all(&tls_dir).unwrap();

        let cert_path = tls_dir.join("daemon-cert.der");
        let key_path = tls_dir.join("daemon-key.der");

        // First call generates
        let (certs1, _key1) = load_or_generate_cert_in(&tls_dir).unwrap();
        assert!(cert_path.exists());
        assert!(key_path.exists());

        // Second call reuses (same cert bytes)
        let (certs2, _key2) = load_or_generate_cert_in(&tls_dir).unwrap();
        assert_eq!(certs1[0].as_ref(), certs2[0].as_ref());
    }
}
