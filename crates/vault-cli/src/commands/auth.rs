//! CLI auth/operator commands.

use chrono::Utc;
use vault_core::operator_session;

fn lock_file_path() -> std::path::PathBuf {
    vault_core::config::lock_file_path()
}

pub fn operator_enable(ttl_secs: i64, json: bool) -> anyhow::Result<()> {
    let candidate = vault_core::auth::resolve_passphrase_keychain_first()?;
    let passphrase = candidate.ok_or_else(|| {
        anyhow::anyhow!("No passphrase source available (set VAULT_PASSPHRASE or keychain entry)")
    })?;
    if !vault_core::auth::validate_passphrase(&passphrase)? {
        anyhow::bail!("Invalid passphrase");
    }
    let session = operator_session::enable_operator_session(ttl_secs)?;
    let out = serde_json::json!({
        "operator_active": true,
        "operator_expires_at": chrono::DateTime::from_timestamp(session.expires_at_epoch, 0).map(|dt| dt.to_rfc3339()),
        "message": "Operator mode enabled.",
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!(
            "Operator mode enabled until {}",
            out["operator_expires_at"].as_str().unwrap_or("-")
        );
    }
    Ok(())
}

pub fn operator_disable(json: bool) -> anyhow::Result<()> {
    operator_session::disable_operator_session()?;
    let out = serde_json::json!({
        "operator_active": false,
        "message": "Operator mode disabled.",
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("Operator mode disabled.");
    }
    Ok(())
}

pub fn lock(json: bool) -> anyhow::Result<()> {
    vault_core::config::ensure_directories()?;
    let out = serde_json::json!({
        "status": "locked",
        "locked_at": Utc::now().to_rfc3339(),
    });
    std::fs::write(lock_file_path(), serde_json::to_string_pretty(&out)?)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("Vault locked.");
    }
    Ok(())
}

pub fn unlock(password: Option<&str>, json: bool) -> anyhow::Result<()> {
    let candidate = if let Some(p) = password {
        Some(p.to_string())
    } else {
        vault_core::auth::resolve_passphrase_keychain_first()?
    };
    let passphrase = candidate.ok_or_else(|| {
        anyhow::anyhow!("No passphrase source available (provide --password or set keychain/env)")
    })?;
    if !vault_core::auth::validate_passphrase(&passphrase)? {
        anyhow::bail!("Invalid passphrase");
    }
    let _ = std::fs::remove_file(lock_file_path());
    let out = serde_json::json!({
        "status": "unlocked",
        "unlocked_at": Utc::now().to_rfc3339(),
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("Vault unlocked.");
    }
    Ok(())
}

pub fn auth_status(json: bool) -> anyhow::Result<()> {
    let locked = lock_file_path().exists();
    let operator_active = operator_session::is_operator_session_active();
    let out = serde_json::json!({
        "authenticated": !locked,
        "locked": locked,
        "operator_active": operator_active,
        "operator_expires_at": operator_session::operator_session_expires_at(),
        "method": "cli_local",
    });
    if json {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else if locked {
        println!("Vault is locked.");
    } else if operator_active {
        println!(
            "Vault unlocked. Operator active until {}.",
            out["operator_expires_at"].as_str().unwrap_or("-")
        );
    } else {
        println!("Vault unlocked. Routine mode active.");
    }
    Ok(())
}
