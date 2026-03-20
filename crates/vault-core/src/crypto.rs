//! Cryptographic primitives for vault-core.
//!
//! - SHA-256 hash truncation for conflict detection (`value_hash`)
//! - SHA-256 HMAC key derivation for P2P sync authentication (`derive_sync_hmac_key`)
//! - Hex encoding/decoding for wire protocol and nonce generation
//!
//! Note: SQLCipher uses its own internal KDF (PBKDF2-HMAC-SHA512, 256K iterations)
//! when receiving a passphrase via `PRAGMA key`. There is no application-level
//! encryption beyond SQLCipher's page-level encryption.

use sha2::{Digest, Sha256};

/// Size of the encryption key in bytes (256-bit).
pub const KEY_SIZE: usize = 32;

/// Compute SHA-256 hash of a value, returning first 8 hex chars.
///
/// Used for conflict detection without exposing actual values.
pub fn value_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..4])
}

/// Derive a deterministic 32-byte HMAC key from the vault passphrase.
///
/// Uses SHA-256 with a domain separator. All peers sharing the same passphrase
/// derive the same HMAC key — no salt exchange needed.
///
/// This is intentionally fast (SHA-256, not Argon2) because it runs per-frame
/// and the passphrase is already validated by SQLCipher (PBKDF2) during vault open.
pub fn derive_sync_hmac_key(passphrase: &str) -> [u8; KEY_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(b"vaultp2p-sync-hmac-v1:");
    hasher.update(passphrase.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&result);
    key
}

/// Simple hex encoding module (no external dependency).
pub mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if !s.len().is_multiple_of(2) {
            return Err("odd length hex string".into());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("invalid hex at {i}: {e}"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_hash() {
        let hash1 = value_hash("hello world");
        let hash2 = value_hash("hello world");
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 8); // 4 bytes = 8 hex chars

        let hash3 = value_hash("different value");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_derive_sync_hmac_key_deterministic() {
        let key1 = derive_sync_hmac_key("my-vault-passphrase");
        let key2 = derive_sync_hmac_key("my-vault-passphrase");
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), KEY_SIZE);
    }

    #[test]
    fn test_derive_sync_hmac_key_different_passphrases() {
        let key1 = derive_sync_hmac_key("passphrase-one");
        let key2 = derive_sync_hmac_key("passphrase-two");
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_hex_roundtrip() {
        let bytes = vec![0xAB, 0xCD, 0xEF, 0x01];
        let encoded = hex::encode(&bytes);
        assert_eq!(encoded, "abcdef01");
        let decoded = hex::decode(&encoded).unwrap();
        assert_eq!(decoded, bytes);
    }
}
