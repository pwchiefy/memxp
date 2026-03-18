//! Shared passphrase resolution and validation helpers.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("no passphrase configured (set VAULT_PASSPHRASE or store db-passphrase in keychain)")]
    NotConfigured,
    #[error("keyring error: {0}")]
    Keyring(String),
}

fn from_env() -> Option<String> {
    std::env::var("VAULT_PASSPHRASE")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn from_keyring() -> Result<Option<String>, AuthError> {
    crate::keyring_backend::get_from_keyring("db-passphrase")
        .map_err(|e| AuthError::Keyring(e.to_string()))
        .map(|v| v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()))
}

/// Resolve passphrase with environment priority (legacy behavior).
pub fn resolve_passphrase_env_first() -> Result<Option<String>, AuthError> {
    if let Some(env) = from_env() {
        return Ok(Some(env));
    }
    from_keyring()
}

/// Resolve passphrase with keychain priority (interactive prompt-friendly behavior).
pub fn resolve_passphrase_keychain_first() -> Result<Option<String>, AuthError> {
    if let Some(keychain) = from_keyring()? {
        return Ok(Some(keychain));
    }
    Ok(from_env())
}

/// Resolve configured passphrase or return a configuration error.
pub fn configured_passphrase() -> Result<String, AuthError> {
    resolve_passphrase_env_first()?.ok_or(AuthError::NotConfigured)
}

/// Constant-time string equality for secret comparisons.
pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Validate a provided passphrase against configured expected passphrase.
pub fn validate_passphrase(candidate: &str) -> Result<bool, AuthError> {
    let expected = configured_passphrase()?;
    Ok(constant_time_eq_str(candidate, &expected))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_str() {
        assert!(constant_time_eq_str("abc", "abc"));
        assert!(!constant_time_eq_str("abc", "abd"));
        assert!(!constant_time_eq_str("abc", "ab"));
    }
}
