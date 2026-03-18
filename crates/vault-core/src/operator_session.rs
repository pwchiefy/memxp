//! Shared operator mode session state persisted to disk.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Default operator session lifetime in seconds.
pub const DEFAULT_OPERATOR_TTL_SECS: i64 = 15 * 60;
/// Max operator session lifetime in seconds.
pub const MAX_OPERATOR_TTL_SECS: i64 = 4 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorSession {
    pub expires_at_epoch: i64,
    pub machine_id: String,
    pub pid: u32,
    pub created_at: String,
}

/// Path to shared operator session file.
pub fn operator_session_path() -> PathBuf {
    crate::config::vault_base_dir().join("operator.session")
}

#[cfg(unix)]
fn secure_file(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn secure_file(_path: &std::path::Path) {}

fn now_epoch() -> i64 {
    Utc::now().timestamp()
}

/// Enable operator session and write/update session file.
pub fn enable_operator_session(ttl_secs: i64) -> std::io::Result<OperatorSession> {
    crate::config::ensure_directories()?;
    let ttl = ttl_secs.clamp(1, MAX_OPERATOR_TTL_SECS);
    let session = OperatorSession {
        expires_at_epoch: now_epoch() + ttl,
        machine_id: crate::config::get_local_machine_id(),
        pid: std::process::id(),
        created_at: Utc::now().to_rfc3339(),
    };
    let path = operator_session_path();
    let body = serde_json::to_string_pretty(&session).map_err(std::io::Error::other)?;
    std::fs::write(&path, body)?;
    secure_file(&path);
    Ok(session)
}

/// Disable operator session (best-effort remove).
pub fn disable_operator_session() -> std::io::Result<()> {
    let path = operator_session_path();
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Load operator session from disk.
pub fn load_operator_session() -> std::io::Result<Option<OperatorSession>> {
    let path = operator_session_path();
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path)?;
    match serde_json::from_str::<OperatorSession>(&raw) {
        Ok(session) => Ok(Some(session)),
        Err(_) => Ok(None),
    }
}

/// Check active operator session and clean up expired file.
pub fn is_operator_session_active() -> bool {
    match load_operator_session() {
        Ok(Some(session)) => {
            if session.expires_at_epoch > now_epoch() {
                true
            } else {
                let _ = disable_operator_session();
                false
            }
        }
        _ => false,
    }
}

/// Return RFC3339 expiration timestamp if a session is active.
pub fn operator_session_expires_at() -> Option<String> {
    let session = load_operator_session().ok().flatten()?;
    if session.expires_at_epoch <= now_epoch() {
        return None;
    }
    chrono::DateTime::from_timestamp(session.expires_at_epoch, 0).map(|dt| dt.to_rfc3339())
}
