//! Authentication state and session management.

pub mod password;
pub mod totp;

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Instant;

/// Session idle timeout (30 minutes).
const IDLE_TIMEOUT_SECS: u64 = 30 * 60;
/// Session max lifetime (24 hours).
const MAX_LIFETIME_SECS: u64 = 24 * 60 * 60;

/// Maximum failed auth attempts before rate limiting kicks in.
const MAX_FAILED_ATTEMPTS: usize = 10;
/// Rate limit window in seconds (5 minutes).
const RATE_LIMIT_WINDOW_SECS: u64 = 300;

/// Authentication state, shared across the web server.
#[derive(Clone)]
pub struct AuthState {
    inner: Arc<RwLock<AuthStateInner>>,
}

struct AuthStateInner {
    /// Whether any auth method has been configured.
    configured: bool,
    /// Password hash (Argon2id).
    password_hash: Option<String>,
    /// TOTP secret (base32 encoded).
    totp_secret: Option<String>,
    /// Active sessions: session_id -> Session.
    sessions: HashMap<String, Session>,
    /// Timestamps of recent failed auth attempts (for rate limiting).
    failed_attempts: Vec<Instant>,
}

struct Session {
    #[allow(dead_code)] // Stored for future audit logging
    method: String,
    created_at: Instant,
    last_activity: Instant,
}

impl AuthState {
    /// Create new auth state.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(AuthStateInner {
                configured: false,
                password_hash: None,
                totp_secret: None,
                sessions: HashMap::new(),
                failed_attempts: Vec::new(),
            })),
        }
    }

    /// Acquire read lock, recovering from poison if a prior thread panicked.
    fn read(&self) -> RwLockReadGuard<'_, AuthStateInner> {
        self.inner.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Acquire write lock, recovering from poison if a prior thread panicked.
    fn write(&self) -> RwLockWriteGuard<'_, AuthStateInner> {
        self.inner.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Check if auth has been configured (password or TOTP set up).
    pub fn is_configured(&self) -> bool {
        let inner = self.read();
        inner.configured
    }

    /// Check if a session is valid and active.
    pub fn validate_session(&self, session_id: &str) -> bool {
        let mut inner = self.write();
        if let Some(session) = inner.sessions.get_mut(session_id) {
            let now = Instant::now();
            let idle = now.duration_since(session.last_activity).as_secs();
            let lifetime = now.duration_since(session.created_at).as_secs();

            if idle > IDLE_TIMEOUT_SECS || lifetime > MAX_LIFETIME_SECS {
                inner.sessions.remove(session_id);
                return false;
            }

            session.last_activity = now;
            true
        } else {
            false
        }
    }

    /// Create a new session, returning the session ID.
    pub fn create_session(&self, method: &str) -> String {
        let session_id = uuid::Uuid::new_v4().to_string();
        let session = Session {
            method: method.to_string(),
            created_at: Instant::now(),
            last_activity: Instant::now(),
        };
        let mut inner = self.write();
        inner.sessions.insert(session_id.clone(), session);
        session_id
    }

    /// Invalidate all sessions (lock).
    pub fn lock(&self) {
        let mut inner = self.write();
        inner.sessions.clear();
    }

    /// Get auth status info.
    pub fn status(&self) -> serde_json::Value {
        let inner = self.read();
        let active_sessions = inner.sessions.len();
        serde_json::json!({
            "configured": inner.configured,
            "has_password": inner.password_hash.is_some(),
            "has_totp": inner.totp_secret.is_some(),
            "active_sessions": active_sessions,
        })
    }

    /// Register a password (Argon2id hash).
    pub fn set_password_hash(&self, hash: &str) {
        let mut inner = self.write();
        inner.password_hash = Some(hash.to_string());
        inner.configured = true;
    }

    /// Get the stored password hash.
    pub fn password_hash(&self) -> Option<String> {
        let inner = self.read();
        inner.password_hash.clone()
    }

    /// Set TOTP secret.
    pub fn set_totp_secret(&self, secret: &str) {
        let mut inner = self.write();
        inner.totp_secret = Some(secret.to_string());
        inner.configured = true;
    }

    /// Get stored TOTP secret.
    pub fn totp_secret(&self) -> Option<String> {
        let inner = self.read();
        inner.totp_secret.clone()
    }

    /// Record a failed auth attempt. Prunes entries older than the rate limit window.
    pub fn record_failure(&self) {
        let mut inner = self.write();
        let now = Instant::now();
        let window = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
        inner
            .failed_attempts
            .retain(|t| now.duration_since(*t) < window);
        inner.failed_attempts.push(now);
    }

    /// Check if the auth endpoint is rate limited (too many failed attempts).
    pub fn is_rate_limited(&self) -> bool {
        let mut inner = self.write();
        let now = Instant::now();
        let window = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
        inner
            .failed_attempts
            .retain(|t| now.duration_since(*t) < window);
        inner.failed_attempts.len() >= MAX_FAILED_ATTEMPTS
    }
}

impl Default for AuthState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_below_threshold_not_limited() {
        let auth = AuthState::new();
        for _ in 0..MAX_FAILED_ATTEMPTS - 1 {
            auth.record_failure();
        }
        assert!(!auth.is_rate_limited());
    }

    #[test]
    fn test_rate_limit_at_threshold_limited() {
        let auth = AuthState::new();
        for _ in 0..MAX_FAILED_ATTEMPTS {
            auth.record_failure();
        }
        assert!(auth.is_rate_limited());
    }

    #[test]
    fn test_rate_limit_fresh_state_not_limited() {
        let auth = AuthState::new();
        assert!(!auth.is_rate_limited());
    }

    #[test]
    fn test_rate_limit_pruning_works() {
        let auth = AuthState::new();
        // Manually inject old timestamps
        {
            let mut inner = auth.inner.write().unwrap();
            let past = Instant::now() - std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS + 1);
            for _ in 0..MAX_FAILED_ATTEMPTS + 5 {
                inner.failed_attempts.push(past);
            }
        }
        // All are expired, so should not be rate limited
        assert!(!auth.is_rate_limited());
    }
}
