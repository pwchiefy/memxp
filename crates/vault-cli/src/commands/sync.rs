//! `memxp sync [<peer>]` — manual one-shot sync.
//!
//! Connects to a peer's daemon via TLS, performs HELLO handshake,
//! exchanges changes, and applies received changes locally.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct};
use tokio_rustls::TlsConnector;

use vault_core::crypto;
use vault_sync::protocol::{
    MessageType, WireFrame, CONNECTION_TIMEOUT_SECS, HEADER_SIZE_V2, HMAC_SIZE, MAX_PAYLOAD_SIZE,
    READ_TIMEOUT_SECS,
};
use vault_sync::serde_wire::{self, HelloAckMessage, HelloMessage, SyncRequest, SyncResponse};

use super::init::open_db;

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
        anyhow::bail!("trusted peer certificate fingerprint cannot be empty");
    }
    if cleaned.len() != 64 {
        anyhow::bail!(
            "trusted peer certificate fingerprint must be 32-byte SHA-256 hex (64 chars)"
        );
    }
    for i in (0..cleaned.len()).step_by(2) {
        u8::from_str_radix(&cleaned[i..i + 2], 16).map_err(|_| {
            anyhow::anyhow!("trusted peer certificate fingerprint is not valid hex")
        })?;
    }
    Ok(cleaned.to_ascii_lowercase())
}

/// Certificate verifier for pinned SHA-256 peer certificate fingerprint.
#[derive(Debug)]
struct FingerprintVerifier {
    expected_fingerprint: String,
}

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        let actual = certificate_fingerprint(end_entity);
        if actual != self.expected_fingerprint {
            return Err(tokio_rustls::rustls::Error::General(format!(
                "peer certificate fingerprint mismatch: expected {}, got {}",
                self.expected_fingerprint, actual
            )));
        }
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Development-only verifier that skips TLS certificate validation.
#[derive(Debug)]
struct NoVerifier;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn build_tls_client_config(
    insecure_skip_tls_verify: bool,
    peer_cert_fingerprint: Option<&str>,
) -> anyhow::Result<Arc<ClientConfig>> {
    if insecure_skip_tls_verify {
        eprintln!(
            "WARNING: TLS certificate verification disabled for this sync session. This is development-only."
        );
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        return Ok(Arc::new(config));
    }

    let Some(raw_fingerprint) = peer_cert_fingerprint else {
        anyhow::bail!(
            "TLS certificate verification is strict by default. Use \
             --peer-cert-fingerprint (SHA-256 hex) or \
             --insecure-skip-tls-verify."
        );
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

/// Read a single authenticated frame from a stream.
async fn read_frame(
    stream: &mut (impl AsyncReadExt + Unpin),
    max_payload: usize,
    hmac_key: &[u8; 32],
) -> anyhow::Result<WireFrame> {
    let timeout = tokio::time::Duration::from_secs(READ_TIMEOUT_SECS);

    let mut header = vec![0u8; HEADER_SIZE_V2];
    tokio::time::timeout(timeout, stream.read_exact(&mut header))
        .await
        .map_err(|_| anyhow::anyhow!("timeout reading frame header"))??;

    if &header[..9] != b"VAULT_P2P" {
        anyhow::bail!("invalid magic: {:?}", &header[..9]);
    }
    let version = header[9];
    if version != 0x03 {
        anyhow::bail!("unsupported protocol version: {version}");
    }
    let payload_len = u32::from_be_bytes([header[10], header[11], header[12], header[13]]) as usize;
    if payload_len > max_payload {
        anyhow::bail!("payload too large: {payload_len} > {max_payload}");
    }

    let remaining = payload_len + HMAC_SIZE;
    let mut rest = vec![0u8; remaining];
    tokio::time::timeout(timeout, stream.read_exact(&mut rest))
        .await
        .map_err(|_| anyhow::anyhow!("timeout reading frame payload"))??;

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
) -> anyhow::Result<()> {
    let timeout = tokio::time::Duration::from_secs(READ_TIMEOUT_SECS);
    let packed = frame.pack_authenticated(hmac_key)?;
    tokio::time::timeout(timeout, stream.write_all(&packed))
        .await
        .map_err(|_| anyhow::anyhow!("timeout writing frame"))??;
    stream.flush().await?;
    Ok(())
}

/// Generate a random 16-byte nonce, hex-encoded.
fn generate_nonce() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    crypto::hex::encode(&bytes)
}

/// Perform a full sync session with a single peer.
async fn sync_with_peer(
    peer_addr: &str,
    db: &vault_core::db::CrSqliteDatabase,
    passphrase: &str,
    insecure_skip_tls_verify: bool,
    peer_cert_fingerprint: Option<&str>,
) -> anyhow::Result<(usize, usize)> {
    let hmac_key = crypto::derive_sync_hmac_key(passphrase);
    let max_payload = MAX_PAYLOAD_SIZE;
    let conn_timeout = tokio::time::Duration::from_secs(CONNECTION_TIMEOUT_SECS);

    // TCP connect
    let tcp_stream = tokio::time::timeout(conn_timeout, tokio::net::TcpStream::connect(peer_addr))
        .await
        .map_err(|_| anyhow::anyhow!("TCP connection timeout"))??;

    eprintln!("  TCP connected to {peer_addr}");

    // TLS handshake
    let tls_connector = TlsConnector::from(build_tls_client_config(
        insecure_skip_tls_verify,
        peer_cert_fingerprint,
    )?);
    let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from("memxp.local")
        .expect("valid server name");
    let mut stream = tls_connector.connect(server_name, tcp_stream).await?;

    eprintln!("  TLS handshake complete");

    // Get our site ID and version
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

    // --- HELLO handshake ---
    let our_nonce = generate_nonce();
    let hello = HelloMessage {
        site_id: site_id.clone(),
        protocol_version: vault_sync::protocol::PROTOCOL_VERSION,
        supported_tables: vec!["vault_entries".into()],
        supported_features: vec![],
        schema_version: 5,
        nonce: our_nonce.clone(),
    };

    let hello_payload = serde_json::to_vec(&hello)?;
    let hello_frame = WireFrame::new(MessageType::Hello, hello_payload);
    write_frame(&mut stream, hello_frame, &hmac_key).await?;
    eprintln!("  HELLO sent (site_id={site_id})");

    // Read HELLO_ACK
    let ack_frame = read_frame(&mut stream, max_payload, &hmac_key).await?;
    let hello_ack: HelloAckMessage = serde_json::from_slice(&ack_frame.payload)?;

    if hello_ack.peer_nonce != our_nonce {
        anyhow::bail!(
            "nonce mismatch: expected {}, got {}",
            our_nonce,
            hello_ack.peer_nonce
        );
    }
    eprintln!(
        "  HELLO_ACK received (peer site_id={}, db_version={})",
        hello_ack.site_id, hello_ack.db_version
    );

    // --- SYNC_REQUEST (incremental) ---
    let peer_site_id = &hello_ack.site_id;
    let last_seen = db.get_peer_version(peer_site_id);

    let all_changes = db.get_changes_since(last_seen).unwrap_or_default();
    let (changes, has_more) = serde_wire::limit_changes_by_size(&all_changes, max_payload);
    let encoded = serde_wire::encode_changes(&changes);

    let request = SyncRequest {
        site_id,
        db_version,
        changes: encoded,
        last_seen_version: last_seen,
    };

    let req_payload = serde_json::to_vec(&request)?;
    let req_frame = WireFrame::new(MessageType::SyncRequest, req_payload);
    write_frame(&mut stream, req_frame, &hmac_key).await?;
    eprintln!(
        "  SYNC_REQUEST sent ({} changes, last_seen={}, has_more={})",
        changes.len(),
        last_seen,
        has_more
    );

    // Read SYNC_RESPONSE
    let resp_frame = read_frame(&mut stream, max_payload, &hmac_key).await?;
    let response: SyncResponse = serde_json::from_slice(&resp_frame.payload)?;

    eprintln!(
        "  SYNC_RESPONSE received ({} changes, current_version={})",
        response.changes.len(),
        response.current_version
    );

    // Apply response changes
    let incoming = serde_wire::decode_changes(&response.changes);
    let received_count = incoming.len();
    if !incoming.is_empty() {
        match db.apply_changes(&incoming) {
            Ok(n) => eprintln!("  Applied {n} changes from peer"),
            Err(e) => eprintln!("  WARNING: Failed to apply some changes: {e}"),
        }
    }

    // Update peer version tracking
    db.update_peer_version(peer_site_id, response.current_version, peer_addr);

    Ok((changes.len(), received_count))
}

/// Run a one-shot sync with a specific peer or all configured peers.
pub async fn run(
    peer: Option<&str>,
    insecure_skip_tls_verify: bool,
    peer_cert_fingerprint: Option<&str>,
) -> anyhow::Result<()> {
    let db = open_db()?;
    let machine_id = vault_core::config::get_local_machine_id();
    let passphrase = super::init::db_passphrase()?;

    let site_id = db
        .conn()
        .query_row("SELECT hex(crsql_site_id())", [], |row| {
            row.get::<_, String>(0)
        })
        .unwrap_or_else(|_| "unknown".to_string());

    let version = db.db_version()?;

    println!("Local site: {site_id} (machine: {machine_id})");
    println!("DB version: {version}");

    if let Some(addr) = peer {
        let bind_addr = format!("{addr}:{}", vault_core::models::DEFAULT_SYNC_PORT);
        println!("Syncing with {addr}...");

        match sync_with_peer(
            &bind_addr,
            &db,
            &passphrase,
            insecure_skip_tls_verify,
            peer_cert_fingerprint,
        )
        .await
        {
            Ok((sent, received)) => {
                println!("Sync complete: sent={sent}, received={received}");
            }
            Err(e) => {
                anyhow::bail!("Sync with {addr} failed: {e}");
            }
        }
    } else {
        let cfg = vault_core::config::VaultConfig::load(&vault_core::config::config_path());
        if cfg.sync.peers.is_empty() {
            println!("No peers configured. Add peers in config or specify: memxp sync <peer>");
            return Ok(());
        }
        for addr in &cfg.sync.peers {
            let bind_addr = format!("{addr}:{}", vault_core::models::DEFAULT_SYNC_PORT);
            println!("Syncing with {addr}...");
            match sync_with_peer(
                &bind_addr,
                &db,
                &passphrase,
                insecure_skip_tls_verify,
                peer_cert_fingerprint,
            )
            .await
            {
                Ok((sent, received)) => {
                    println!("  Complete: sent={sent}, received={received}");
                }
                Err(e) => {
                    println!("  Failed: {e}");
                }
            }
        }
    }

    let new_version = db.db_version()?;
    if new_version != version {
        println!("DB version: {version} -> {new_version}");
    }

    Ok(())
}
