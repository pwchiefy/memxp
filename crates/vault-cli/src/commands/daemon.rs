//! Sync daemon commands: start, stop, status.

use vault_sync::daemon::{check_pid_file, remove_pid_file, DaemonConfig, SyncDaemon};

use super::init::{db_passphrase, extension_path};

/// `memxp daemon start`
pub async fn start(
    port: Option<u16>,
    interval: Option<u32>,
    insecure_skip_tls_verify: bool,
    peer_cert_fingerprint: Option<String>,
) -> anyhow::Result<()> {
    // Check if already running
    if let Some(pid) = check_pid_file() {
        anyhow::bail!("Daemon already running (PID {pid}). Use `memxp daemon stop` first.");
    }

    let cfg = vault_core::config::VaultConfig::load(&vault_core::config::config_path());
    let passphrase = db_passphrase()?;
    let ext = extension_path();

    // Determine bind address: explicit config > Tailscale IP > 127.0.0.1
    let bind_address = cfg.sync.bind_address.unwrap_or_else(|| {
        let ts_ip = vault_core::config::get_local_machine_id();
        if ts_ip.starts_with("100.") {
            ts_ip
        } else {
            "127.0.0.1".to_string()
        }
    });

    let daemon_config = DaemonConfig {
        db_path: vault_core::config::db_path(),
        passphrase,
        extension_path: ext,
        bind_address,
        port: port.unwrap_or(cfg.sync.port),
        peers: cfg.sync.peers.clone(),
        allowed_ips: cfg.sync.allowed_ips.clone(),
        insecure_skip_tls_verify,
        peer_cert_fingerprint,
        sync_interval_secs: interval.unwrap_or(cfg.sync.interval_seconds),
        max_payload_bytes: cfg.sync.max_payload_bytes,
    };

    println!(
        "Starting sync daemon on {}:{}...",
        daemon_config.bind_address, daemon_config.port
    );
    println!(
        "Sync interval: {}s, peers: {}",
        daemon_config.sync_interval_secs,
        if daemon_config.peers.is_empty() {
            "none".to_string()
        } else {
            daemon_config.peers.join(", ")
        }
    );

    let db = vault_core::db::CrSqliteDatabase::open(
        &daemon_config.db_path,
        &daemon_config.passphrase,
        daemon_config.extension_path.as_deref(),
    )?;

    let daemon = SyncDaemon::new(daemon_config, db);
    daemon.run().await.map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(())
}

/// `memxp daemon stop`
pub fn stop() -> anyhow::Result<()> {
    if let Some(pid) = check_pid_file() {
        // Send SIGTERM
        #[cfg(unix)]
        {
            use std::process::Command;
            let status = Command::new("kill").arg(pid.to_string()).status()?;
            if status.success() {
                println!("Sent SIGTERM to daemon (PID {pid}).");
            } else {
                println!("Failed to signal daemon (PID {pid}). It may have already exited.");
            }
        }
        #[cfg(windows)]
        {
            use std::process::Command;
            let status = Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/F"])
                .status()?;
            if status.success() {
                println!("Terminated daemon (PID {pid}).");
            } else {
                println!("Failed to terminate daemon (PID {pid}). It may have already exited.");
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            println!("Cannot signal daemon on this platform. PID: {pid}");
        }
        remove_pid_file();
        println!("Removed PID file.");
    } else {
        println!("No daemon running.");
    }
    Ok(())
}

/// `memxp daemon status`
pub fn daemon_status() -> anyhow::Result<()> {
    if let Some(pid) = check_pid_file() {
        println!("Daemon running (PID {pid}).");
    } else {
        println!("Daemon not running.");
    }
    Ok(())
}
