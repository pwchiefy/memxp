//! File-based challenge/confirmation protocol for out-of-band auth approvals.

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

const DEFAULT_CHALLENGE_TTL_SECS: i64 = 60;

#[derive(Debug, Error)]
pub enum ChallengeError {
    #[error("challenge not found: {0}")]
    NotFound(String),
    #[error("challenge expired: {0}")]
    Expired(String),
    #[error("challenge action mismatch")]
    ActionMismatch,
    #[error("challenge session mismatch")]
    SessionMismatch,
    #[error("challenge owner mismatch")]
    OwnerMismatch,
    #[error("challenge already consumed")]
    Consumed,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengePayload {
    pub challenge_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub action: String,
    pub requesting_tool: String,
    pub requesting_pid: u32,
    pub session_nonce: String,
    pub uid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfirmationPayload {
    challenge_id: String,
    action: String,
    confirmed_at: String,
    confirmer_pid: u32,
    session_nonce: String,
    uid: u32,
}

#[derive(Debug, Clone)]
pub struct ChallengeStore {
    dir: PathBuf,
}

impl Default for ChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self {
            dir: crate::config::vault_base_dir().join("challenges"),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn pending_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.pending"))
    }

    fn confirmed_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.confirmed"))
    }

    fn consumed_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.consumed"))
    }

    fn now() -> chrono::DateTime<Utc> {
        Utc::now()
    }

    pub fn ensure_dir(&self) -> Result<(), ChallengeError> {
        if let Some(parent) = self.dir.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::create_dir_all(&self.dir)?;
        secure_dir(&self.dir)?;
        Ok(())
    }

    /// Create a new one-time challenge file.
    pub fn create(
        &self,
        action: &str,
        requesting_tool: &str,
        requesting_pid: u32,
        session_nonce: &str,
        ttl_secs: Option<i64>,
    ) -> Result<ChallengePayload, ChallengeError> {
        self.ensure_dir()?;
        let _ = self.gc_expired();

        let id = format!("confirm-{}", Uuid::new_v4().simple());
        let created = Self::now();
        let expires = created + Duration::seconds(ttl_secs.unwrap_or(DEFAULT_CHALLENGE_TTL_SECS));
        let payload = ChallengePayload {
            challenge_id: id.clone(),
            created_at: created.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
            action: action.to_string(),
            requesting_tool: requesting_tool.to_string(),
            requesting_pid,
            session_nonce: session_nonce.to_string(),
            uid: current_uid(),
        };

        let path = self.pending_path(&id);
        write_json_secure(&path, &payload)?;
        Ok(payload)
    }

    /// Confirm a challenge out-of-band.
    pub fn confirm(
        &self,
        challenge_id: &str,
        action: &str,
        session_nonce: Option<&str>,
    ) -> Result<ChallengePayload, ChallengeError> {
        self.ensure_dir()?;
        let pending_path = self.pending_path(challenge_id);
        if !pending_path.exists() {
            return Err(ChallengeError::NotFound(challenge_id.to_string()));
        }
        let pending: ChallengePayload = read_json_secure(&pending_path)?;
        verify_owner(&pending_path, pending.uid)?;

        if pending.action != action {
            return Err(ChallengeError::ActionMismatch);
        }
        if let Some(expected) = session_nonce {
            if pending.session_nonce != expected {
                return Err(ChallengeError::SessionMismatch);
            }
        }
        if pending.uid != current_uid() {
            return Err(ChallengeError::OwnerMismatch);
        }
        if is_expired(&pending.expires_at)? {
            return Err(ChallengeError::Expired(challenge_id.to_string()));
        }
        if self.consumed_path(challenge_id).exists() {
            return Err(ChallengeError::Consumed);
        }

        let confirmed = ConfirmationPayload {
            challenge_id: challenge_id.to_string(),
            action: action.to_string(),
            confirmed_at: Self::now().to_rfc3339(),
            confirmer_pid: std::process::id(),
            session_nonce: pending.session_nonce.clone(),
            uid: pending.uid,
        };

        let confirmed_path = self.confirmed_path(challenge_id);
        if confirmed_path.exists() {
            return Ok(pending);
        }
        write_json_secure(&confirmed_path, &confirmed)?;
        Ok(pending)
    }

    /// Consume confirmed challenge exactly once.
    pub fn consume(
        &self,
        challenge_id: &str,
        action: &str,
        session_nonce: &str,
    ) -> Result<ChallengePayload, ChallengeError> {
        self.ensure_dir()?;
        let _ = self.gc_expired();

        let pending_path = self.pending_path(challenge_id);
        if !pending_path.exists() {
            if self.consumed_path(challenge_id).exists() {
                return Err(ChallengeError::Consumed);
            }
            return Err(ChallengeError::NotFound(challenge_id.to_string()));
        }
        let pending: ChallengePayload = read_json_secure(&pending_path)?;
        verify_owner(&pending_path, pending.uid)?;

        let confirmed_path = self.confirmed_path(challenge_id);
        if !confirmed_path.exists() {
            return Err(ChallengeError::NotFound(format!(
                "confirmation for {challenge_id}"
            )));
        }
        let confirmed: ConfirmationPayload = read_json_secure(&confirmed_path)?;
        verify_owner(&confirmed_path, pending.uid)?;

        if pending.action != action || confirmed.action != action {
            return Err(ChallengeError::ActionMismatch);
        }
        if pending.session_nonce != session_nonce || confirmed.session_nonce != session_nonce {
            return Err(ChallengeError::SessionMismatch);
        }
        if pending.uid != current_uid() || confirmed.uid != current_uid() {
            return Err(ChallengeError::OwnerMismatch);
        }
        if is_expired(&pending.expires_at)? {
            return Err(ChallengeError::Expired(challenge_id.to_string()));
        }

        std::fs::rename(&pending_path, self.consumed_path(challenge_id))?;
        secure_file(&self.consumed_path(challenge_id))?;
        let _ = std::fs::remove_file(&confirmed_path);
        Ok(pending)
    }

    /// List all non-expired pending challenges.
    pub fn list_pending(&self) -> Result<Vec<ChallengePayload>, ChallengeError> {
        self.ensure_dir()?;
        let mut pending = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            if ext != "pending" {
                continue;
            }
            if let Ok(payload) = read_json_secure::<ChallengePayload>(&path) {
                if !is_expired(&payload.expires_at).unwrap_or(true) {
                    pending.push(payload);
                }
            }
        }
        pending.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(pending)
    }

    /// Remove stale pending/confirmed/consumed challenge files.
    pub fn gc_expired(&self) -> Result<usize, ChallengeError> {
        self.ensure_dir()?;
        let mut removed = 0usize;
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            if !matches!(ext, "pending" | "confirmed" | "consumed") {
                continue;
            }

            let expired = match ext {
                "pending" => read_json_secure::<ChallengePayload>(&path)
                    .ok()
                    .and_then(|p| is_expired(&p.expires_at).ok())
                    .unwrap_or(true),
                "confirmed" => {
                    // Confirmation files are short-lived artifacts.
                    file_older_than(&path, 120).unwrap_or(true)
                }
                "consumed" => file_older_than(&path, 300).unwrap_or(true),
                _ => false,
            };

            if expired && std::fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

fn parse_rfc3339(ts: &str) -> Result<chrono::DateTime<Utc>, ChallengeError> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| {
            ChallengeError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid timestamp: {e}"),
            ))
        })
}

fn is_expired(expires_at: &str) -> Result<bool, ChallengeError> {
    let expires = parse_rfc3339(expires_at)?;
    Ok(expires <= ChallengeStore::now())
}

fn file_older_than(path: &Path, seconds: u64) -> Result<bool, ChallengeError> {
    let meta = std::fs::metadata(path)?;
    let modified = meta.modified()?;
    let age = std::time::SystemTime::now()
        .duration_since(modified)
        .unwrap_or_default();
    Ok(age.as_secs() > seconds)
}

fn write_json_secure<T: Serialize>(path: &Path, value: &T) -> Result<(), ChallengeError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)?;
    use std::io::Write;
    file.write_all(&bytes)?;
    file.flush()?;
    secure_file(path)?;
    Ok(())
}

fn read_json_secure<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, ChallengeError> {
    let raw = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str::<T>(&raw)?)
}

#[cfg(unix)]
fn secure_dir(path: &Path) -> Result<(), ChallengeError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(windows)]
fn secure_dir(path: &Path) -> Result<(), ChallengeError> {
    // Use icacls to restrict directory access to current user
    let path_str = path.to_string_lossy();
    let user = windows_username();
    let _ = std::process::Command::new("icacls")
        .args([
            &*path_str,
            "/inheritance:r",
            "/grant:r",
            &format!("{user}:(OI)(CI)F"),
            "/T",
        ])
        .output();
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn secure_dir(_path: &Path) -> Result<(), ChallengeError> {
    Ok(())
}

#[cfg(unix)]
fn secure_file(path: &Path) -> Result<(), ChallengeError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(windows)]
fn secure_file(path: &Path) -> Result<(), ChallengeError> {
    // Use icacls to restrict file access to current user
    let path_str = path.to_string_lossy();
    let user = windows_username();
    let _ = std::process::Command::new("icacls")
        .args([
            &*path_str,
            "/inheritance:r",
            "/grant:r",
            &format!("{user}:F"),
        ])
        .output();
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn secure_file(_path: &Path) -> Result<(), ChallengeError> {
    Ok(())
}

/// Get the current Windows username for ACL operations.
#[cfg(windows)]
fn windows_username() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "BUILTIN\\Users".to_string())
}

#[cfg(unix)]
fn verify_owner(path: &Path, expected_uid: u32) -> Result<(), ChallengeError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = std::fs::metadata(path)?;
    if meta.uid() != expected_uid {
        return Err(ChallengeError::OwnerMismatch);
    }
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(ChallengeError::OwnerMismatch);
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_owner(_path: &Path, _expected_uid: u32) -> Result<(), ChallengeError> {
    Ok(())
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // SAFETY: libc::geteuid is thread-safe and has no preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store() -> ChallengeStore {
        let mut dir = std::env::temp_dir();
        dir.push(format!("memxp-challenge-test-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        ChallengeStore { dir }
    }

    #[test]
    fn test_list_pending() {
        let store = tmp_store();
        // Create two challenges
        let p1 = store
            .create("operator_mode", "vault_operator_mode", 1234, "n1", Some(60))
            .unwrap();
        let p2 = store
            .create("unlock", "vault_unlock", 1234, "n2", Some(60))
            .unwrap();

        let pending = store.list_pending().unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].challenge_id, p1.challenge_id);
        assert_eq!(pending[1].challenge_id, p2.challenge_id);

        // Confirm one — it should still appear in pending (confirm doesn't remove pending file)
        store
            .confirm(&p1.challenge_id, "operator_mode", Some("n1"))
            .unwrap();
        let pending = store.list_pending().unwrap();
        assert_eq!(pending.len(), 2);

        // Consume it — pending file renamed to consumed, should disappear
        store
            .consume(&p1.challenge_id, "operator_mode", "n1")
            .unwrap();
        let pending = store.list_pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].challenge_id, p2.challenge_id);
    }

    #[test]
    fn test_list_pending_empty() {
        let store = tmp_store();
        let pending = store.list_pending().unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn test_challenge_create_confirm_consume() {
        let store = tmp_store();
        let p = store
            .create(
                "operator_mode",
                "vault_operator_mode",
                1234,
                "nonce-1",
                Some(60),
            )
            .unwrap();
        store
            .confirm(&p.challenge_id, "operator_mode", Some("nonce-1"))
            .unwrap();
        let consumed = store
            .consume(&p.challenge_id, "operator_mode", "nonce-1")
            .unwrap();
        assert_eq!(consumed.challenge_id, p.challenge_id);
    }
}
