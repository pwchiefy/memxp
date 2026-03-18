//! TOTP (Time-based One-Time Password) authentication.

use totp_rs::{Algorithm, Secret, TOTP};

use super::AuthState;

/// Generate a new TOTP secret and return it with the otpauth URI.
pub fn setup(issuer: &str, account: &str) -> Result<(String, String), String> {
    let secret = Secret::generate_secret();
    let secret_base32 = secret.to_encoded().to_string();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret
            .to_bytes()
            .map_err(|e| format!("Invalid secret: {e}"))?,
        Some(issuer.to_string()),
        account.to_string(),
    )
    .map_err(|e| format!("Failed to create TOTP: {e}"))?;

    let uri = totp.get_url();
    Ok((secret_base32, uri))
}

/// Verify a TOTP code against a stored secret.
pub fn verify(secret_base32: &str, code: &str) -> Result<bool, String> {
    let secret = Secret::Encoded(secret_base32.to_string());
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret
            .to_bytes()
            .map_err(|e| format!("Invalid secret: {e}"))?,
        None,
        String::new(),
    )
    .map_err(|e| format!("Failed to create TOTP: {e}"))?;

    let token = totp
        .generate_current()
        .map_err(|e| format!("TOTP generation error: {e}"))?;

    Ok(token == code)
}

/// Register TOTP and return the secret + URI.
pub fn register(auth: &AuthState, issuer: &str, account: &str) -> Result<(String, String), String> {
    let (secret, uri) = setup(issuer, account)?;
    auth.set_totp_secret(&secret);
    Ok((secret, uri))
}

/// Login with TOTP code. Returns session ID on success.
pub fn login(auth: &AuthState, code: &str) -> Result<String, String> {
    let secret = auth
        .totp_secret()
        .ok_or_else(|| "No TOTP configured".to_string())?;

    if verify(&secret, code)? {
        Ok(auth.create_session("totp"))
    } else {
        Err("Invalid TOTP code".to_string())
    }
}
