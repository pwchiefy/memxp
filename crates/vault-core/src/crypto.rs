//! Cryptographic primitives for vault-core.
//!
//! - XChaCha20-Poly1305 for value-level encryption (available, not yet used in default storage path)
//! - Argon2id for key derivation from passphrases (available, not yet used in default storage path)
//! - SHA-256 HMAC key derivation for P2P sync authentication
//!
//! Note: SQLCipher uses its own internal KDF (PBKDF2-HMAC-SHA512, 256K iterations)
//! when receiving a passphrase via `PRAGMA key`. The Argon2id `derive_key` function
//! here is available for future use (e.g., per-value encryption) but is not currently
//! part of the database encryption path.

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// Size of the encryption key in bytes (256-bit).
pub const KEY_SIZE: usize = 32;

/// Size of the XChaCha20 nonce in bytes.
pub const NONCE_SIZE: usize = 24;

/// Argon2id parameters for key derivation.
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3; // 3 iterations
const ARGON2_P_COST: u32 = 1; // 1 thread
const ARGON2_SALT_SIZE: usize = 16;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("key derivation failed: {0}")]
    KeyDerivationFailed(String),
    #[error("invalid data: {0}")]
    InvalidData(String),
}

/// Encrypt a value using XChaCha20-Poly1305.
///
/// Returns the nonce prepended to the ciphertext: `nonce (24B) || ciphertext`.
pub fn encrypt_value(key: &[u8; KEY_SIZE], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt a value encrypted with `encrypt_value`.
///
/// Expects input format: `nonce (24B) || ciphertext`.
pub fn decrypt_value(key: &[u8; KEY_SIZE], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < NONCE_SIZE + 16 {
        // At minimum: nonce + poly1305 tag
        return Err(CryptoError::InvalidData(
            "data too short for nonce + tag".into(),
        ));
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
    let nonce = XNonce::from_slice(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(key.into());

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

/// Derive an encryption key from a passphrase using Argon2id.
///
/// Returns `(key, salt)`. If `salt` is provided, uses that salt (deterministic).
/// The key is wrapped in `Zeroizing` to ensure it is zeroed on drop.
pub fn derive_key(
    passphrase: &str,
    salt: Option<&[u8]>,
) -> Result<(Zeroizing<[u8; KEY_SIZE]>, Vec<u8>), CryptoError> {
    let salt_bytes = if let Some(s) = salt {
        s.to_vec()
    } else {
        let mut s = vec![0u8; ARGON2_SALT_SIZE];
        OsRng.fill_bytes(&mut s);
        s
    };

    let params = argon2::Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(KEY_SIZE))
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt_bytes, key.as_mut())
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok((key, salt_bytes))
}

/// Generate a random encryption key.
pub fn generate_key() -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    OsRng.fill_bytes(&mut key);
    key
}

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
/// and the passphrase is already validated via Argon2 during vault open.
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
    fn test_value_level_encrypt_decrypt() {
        let key = generate_key();
        let plaintext = b"super-secret-api-key-12345";

        let encrypted1 = encrypt_value(&key, plaintext).unwrap();
        let encrypted2 = encrypt_value(&key, plaintext).unwrap();

        // Different nonces → different ciphertext
        assert_ne!(encrypted1, encrypted2);

        // Both decrypt to same plaintext
        let decrypted1 = decrypt_value(&key, &encrypted1).unwrap();
        let decrypted2 = decrypt_value(&key, &encrypted2).unwrap();
        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = generate_key();
        let key2 = generate_key();
        let encrypted = encrypt_value(&key1, b"secret").unwrap();
        assert!(decrypt_value(&key2, &encrypted).is_err());
    }

    #[test]
    fn test_decrypt_short_data_fails() {
        let key = generate_key();
        assert!(decrypt_value(&key, &[0u8; 10]).is_err());
    }

    #[test]
    fn test_argon2_key_derivation() {
        let passphrase = "my-secure-passphrase";
        let (key1, salt) = derive_key(passphrase, None).unwrap();

        // Same passphrase + salt → same key (deterministic)
        let (key2, _) = derive_key(passphrase, Some(&salt)).unwrap();
        assert_eq!(key1, key2);

        // Different passphrase → different key
        let (key3, _) = derive_key("different-passphrase", Some(&salt)).unwrap();
        assert_ne!(key1, key3);
    }

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
