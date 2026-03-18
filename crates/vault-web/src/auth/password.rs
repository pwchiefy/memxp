//! Password authentication (Argon2id).

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;

use super::AuthState;

/// Hash a password using Argon2id.
pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Failed to hash password: {e}"))?;
    Ok(hash.to_string())
}

/// Verify a password against a hash.
pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Register a new password.
pub fn register(auth: &AuthState, password: &str) -> Result<(), String> {
    if auth.is_configured() {
        return Err("Auth already configured. Use login instead.".to_string());
    }
    let hash = hash_password(password)?;
    auth.set_password_hash(&hash);
    Ok(())
}

/// Login with password. Returns session ID on success.
pub fn login(auth: &AuthState, password: &str) -> Result<String, String> {
    let hash = auth
        .password_hash()
        .ok_or_else(|| "No password configured".to_string())?;

    if verify_password(password, &hash) {
        Ok(auth.create_session("password"))
    } else {
        Err("Invalid password".to_string())
    }
}
