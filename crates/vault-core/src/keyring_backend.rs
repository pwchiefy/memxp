//! Cross-platform keyring integration using the `keyring` crate.
//!
//! Provides secure storage for individual credential values in the
//! OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service).

use thiserror::Error;

const SERVICE_NAME: &str = "com.memxp.credentials";
const LEGACY_SERVICE_NAME: &str = "com.vaultp2p.credentials";

#[derive(Debug, Error)]
pub enum KeyringError {
    #[error("keyring error: {0}")]
    Backend(String),
    #[error("entry not found: {0}")]
    NotFound(String),
}

/// Store a value in the system keyring (always writes to new service name).
pub fn set_in_keyring(path: &str, value: &str) -> Result<(), KeyringError> {
    let entry = keyring::Entry::new(SERVICE_NAME, path)
        .map_err(|e| KeyringError::Backend(e.to_string()))?;
    entry
        .set_password(value)
        .map_err(|e| KeyringError::Backend(e.to_string()))
}

/// Get a value from the system keyring.
///
/// Tries the new service name first, then falls back to the legacy name
/// for existing installations that haven't migrated.
pub fn get_from_keyring(path: &str) -> Result<Option<String>, KeyringError> {
    // Try new service name first
    let entry = keyring::Entry::new(SERVICE_NAME, path)
        .map_err(|e| KeyringError::Backend(e.to_string()))?;
    match entry.get_password() {
        Ok(value) => return Ok(Some(value)),
        Err(keyring::Error::NoEntry) => {}
        Err(e) => return Err(KeyringError::Backend(e.to_string())),
    }

    // Fall back to legacy service name
    let legacy = keyring::Entry::new(LEGACY_SERVICE_NAME, path)
        .map_err(|e| KeyringError::Backend(e.to_string()))?;
    match legacy.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(KeyringError::Backend(e.to_string())),
    }
}

/// Delete a value from the system keyring.
pub fn delete_from_keyring(path: &str) -> Result<bool, KeyringError> {
    let entry = keyring::Entry::new(SERVICE_NAME, path)
        .map_err(|e| KeyringError::Backend(e.to_string()))?;
    match entry.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(KeyringError::Backend(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Keyring tests require actual OS keychain access.
    // Skip on Linux CI where no Secret Service is available.
    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore)]
    fn test_keyring_roundtrip() {
        let test_path = "vault-core-test/keyring-roundtrip";
        let test_value = "test-secret-value-12345";

        // Clean up from previous test runs
        let _ = delete_from_keyring(test_path);

        // Set
        match set_in_keyring(test_path, test_value) {
            Ok(()) => {}
            Err(KeyringError::Backend(msg))
                if msg.contains("platform") || msg.contains("not supported") =>
            {
                // Skip test on platforms without keyring support (CI)
                return;
            }
            Err(e) => panic!("Unexpected keyring error: {e}"),
        }

        // Get
        let got = get_from_keyring(test_path).unwrap();
        assert_eq!(got, Some(test_value.to_string()));

        // Delete
        let deleted = delete_from_keyring(test_path).unwrap();
        assert!(deleted);

        // Verify gone
        let after = get_from_keyring(test_path).unwrap();
        assert_eq!(after, None);
    }
}
