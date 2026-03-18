//! Wire protocol: binary frame packing/unpacking.
//!
//! Frame format (v3):
//! ```text
//! MAGIC(9) | VERSION=0x03(1) | LENGTH(4 BE) | TYPE(16 null-padded) | PAYLOAD(variable) | HMAC(32)
//! ```
//! Total header = 30 bytes. HMAC is appended after payload.
//! HMAC-SHA256 is computed over MAGIC..PAYLOAD (everything before HMAC).

use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Magic bytes: ASCII "VAULT_P2P"
pub const MAGIC: &[u8; 9] = b"VAULT_P2P";

/// Current protocol version.
pub const PROTOCOL_VERSION: u8 = 0x03;

/// Header size for v3/v2 protocol (9 + 1 + 4 + 16 = 30).
pub const HEADER_SIZE_V2: usize = 30;

/// Header size for v1 protocol (9 + 1 + 2 + 16 = 28).
pub const HEADER_SIZE_V1: usize = 28;

/// HMAC-SHA256 tag size in bytes.
pub const HMAC_SIZE: usize = 32;

/// Maximum payload size (10 MB).
pub const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024;

/// Maximum changes per sync batch.
pub const MAX_CHANGES_PER_SYNC: usize = 50_000;

/// Connection timeout in seconds.
pub const CONNECTION_TIMEOUT_SECS: u64 = 5;

/// Read timeout in seconds.
pub const READ_TIMEOUT_SECS: u64 = 30;

/// Message type field is 16 bytes, null-padded.
const TYPE_FIELD_SIZE: usize = 16;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("invalid magic bytes")]
    InvalidMagic,
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u8),
    #[error("payload too large: {size} bytes (max {max})")]
    PayloadTooLarge { size: usize, max: usize },
    #[error("unknown message type: {0}")]
    UnknownMessageType(String),
    #[error("invalid frame: {0}")]
    InvalidFrame(String),
    #[error("HMAC verification failed")]
    HmacVerificationFailed,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Protocol message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    SyncRequest,
    SyncResponse,
    SyncTrigger,
    TriggerAck,
    Hello,
    HelloAck,
    Error,
}

impl MessageType {
    /// Convert to the 16-byte null-padded type field.
    pub fn as_bytes(&self) -> [u8; TYPE_FIELD_SIZE] {
        let s = match self {
            Self::SyncRequest => "SYNC_REQUEST",
            Self::SyncResponse => "SYNC_RESPONSE",
            Self::SyncTrigger => "SYNC_TRIGGER",
            Self::TriggerAck => "TRIGGER_ACK",
            Self::Hello => "HELLO",
            Self::HelloAck => "HELLO_ACK",
            Self::Error => "ERROR",
        };
        let mut buf = [0u8; TYPE_FIELD_SIZE];
        let bytes = s.as_bytes();
        buf[..bytes.len()].copy_from_slice(bytes);
        buf
    }

    /// Parse from the 16-byte type field.
    pub fn from_bytes(bytes: &[u8; TYPE_FIELD_SIZE]) -> Result<Self, ProtocolError> {
        // Find the first null byte to get the actual string
        let end = bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(TYPE_FIELD_SIZE);
        let s = std::str::from_utf8(&bytes[..end])
            .map_err(|_| ProtocolError::UnknownMessageType("invalid UTF-8".into()))?;

        match s {
            "SYNC_REQUEST" => Ok(Self::SyncRequest),
            "SYNC_RESPONSE" => Ok(Self::SyncResponse),
            "SYNC_TRIGGER" => Ok(Self::SyncTrigger),
            "TRIGGER_ACK" => Ok(Self::TriggerAck),
            "HELLO" => Ok(Self::Hello),
            "HELLO_ACK" => Ok(Self::HelloAck),
            "ERROR" => Ok(Self::Error),
            _ => Err(ProtocolError::UnknownMessageType(s.to_string())),
        }
    }
}

/// A parsed wire frame.
#[derive(Debug, Clone)]
pub struct WireFrame {
    pub version: u8,
    pub msg_type: MessageType,
    pub payload: Vec<u8>,
}

impl WireFrame {
    /// Create a new frame.
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            msg_type,
            payload,
        }
    }

    /// Pack a frame into bytes for sending (without HMAC).
    pub fn pack(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.payload.len() > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge {
                size: self.payload.len(),
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let mut buf = Vec::with_capacity(HEADER_SIZE_V2 + self.payload.len());

        // MAGIC (9 bytes)
        buf.extend_from_slice(MAGIC);
        // VERSION (1 byte)
        buf.push(self.version);
        // LENGTH (4 bytes, big-endian)
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        // TYPE (16 bytes, null-padded)
        buf.extend_from_slice(&self.msg_type.as_bytes());
        // PAYLOAD
        buf.extend_from_slice(&self.payload);

        Ok(buf)
    }

    /// Pack a frame with HMAC-SHA256 appended.
    ///
    /// Format: `pack() || HMAC-SHA256(pack(), key)`
    pub fn pack_authenticated(&self, hmac_key: &[u8; 32]) -> Result<Vec<u8>, ProtocolError> {
        let mut buf = self.pack()?;

        let mut mac = HmacSha256::new_from_slice(hmac_key).expect("HMAC accepts any key size");
        mac.update(&buf);
        let tag = mac.finalize().into_bytes();
        buf.extend_from_slice(&tag);

        Ok(buf)
    }

    /// Unpack a frame from bytes (no HMAC verification).
    pub fn unpack(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < HEADER_SIZE_V1 {
            return Err(ProtocolError::InvalidFrame(format!(
                "too short: {} bytes (min {})",
                data.len(),
                HEADER_SIZE_V1
            )));
        }

        // Check magic
        if &data[..9] != MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }

        let version = data[9];

        let (payload_len, type_start) = match version {
            0x01 | 0x02 => {
                return Err(ProtocolError::UnsupportedVersion(version));
            }
            0x03 => {
                // V3: 4-byte length (same header layout as v2)
                if data.len() < HEADER_SIZE_V2 {
                    return Err(ProtocolError::InvalidFrame(format!(
                        "too short for v3: {} bytes (need {})",
                        data.len(),
                        HEADER_SIZE_V2
                    )));
                }
                let len = u32::from_be_bytes([data[10], data[11], data[12], data[13]]) as usize;
                (len, 14)
            }
            _ => return Err(ProtocolError::UnsupportedVersion(version)),
        };

        if payload_len > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge {
                size: payload_len,
                max: MAX_PAYLOAD_SIZE,
            });
        }

        // Parse type field (16 bytes)
        let type_end = type_start + TYPE_FIELD_SIZE;
        if data.len() < type_end {
            return Err(ProtocolError::InvalidFrame("truncated type field".into()));
        }
        let mut type_bytes = [0u8; TYPE_FIELD_SIZE];
        type_bytes.copy_from_slice(&data[type_start..type_end]);
        let msg_type = MessageType::from_bytes(&type_bytes)?;

        // Extract payload
        let payload_start = type_end;
        let payload_end = payload_start + payload_len;
        if data.len() < payload_end {
            return Err(ProtocolError::InvalidFrame(format!(
                "truncated payload: have {} bytes, need {}",
                data.len() - payload_start,
                payload_len
            )));
        }
        let payload = data[payload_start..payload_end].to_vec();

        Ok(Self {
            version,
            msg_type,
            payload,
        })
    }

    /// Unpack a frame from bytes and verify HMAC-SHA256.
    ///
    /// Expected format: `MAGIC..PAYLOAD || HMAC(32)`
    /// HMAC is verified over all bytes before the trailing 32-byte tag.
    pub fn unpack_authenticated(data: &[u8], hmac_key: &[u8; 32]) -> Result<Self, ProtocolError> {
        if data.len() < HEADER_SIZE_V2 + HMAC_SIZE {
            return Err(ProtocolError::InvalidFrame(format!(
                "too short for authenticated frame: {} bytes",
                data.len()
            )));
        }

        let (message, tag_bytes) = data.split_at(data.len() - HMAC_SIZE);

        // Verify HMAC (constant-time comparison via hmac crate)
        let mut mac = HmacSha256::new_from_slice(hmac_key).expect("HMAC accepts any key size");
        mac.update(message);
        mac.verify_slice(tag_bytes)
            .map_err(|_| ProtocolError::HmacVerificationFailed)?;

        // HMAC valid — unpack the message portion
        Self::unpack(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_unpack_header_v3() {
        let payload = b"{\"site_id\":\"abcd1234\"}".to_vec();
        let frame = WireFrame::new(MessageType::SyncRequest, payload.clone());
        let packed = frame.pack().unwrap();

        // Check header
        assert_eq!(&packed[..9], MAGIC);
        assert_eq!(packed[9], 0x03);
        let len = u32::from_be_bytes([packed[10], packed[11], packed[12], packed[13]]);
        assert_eq!(len as usize, payload.len());
        // Type should start with SYNC_REQUEST
        assert_eq!(&packed[14..26], b"SYNC_REQUEST");

        // Unpack
        let unpacked = WireFrame::unpack(&packed).unwrap();
        assert_eq!(unpacked.version, PROTOCOL_VERSION);
        assert_eq!(unpacked.msg_type, MessageType::SyncRequest);
        assert_eq!(unpacked.payload, payload);
    }

    #[test]
    fn test_unpack_v1_header() {
        // Manually construct a v1 frame — should be rejected
        let payload = b"{}".to_vec();
        let mut data = Vec::new();
        data.extend_from_slice(MAGIC);
        data.push(0x01); // v1
        data.extend_from_slice(&(payload.len() as u16).to_be_bytes()); // 2-byte length
        let mut type_field = [0u8; 16];
        type_field[..5].copy_from_slice(b"HELLO");
        data.extend_from_slice(&type_field);
        data.extend_from_slice(&payload);

        assert!(matches!(
            WireFrame::unpack(&data),
            Err(ProtocolError::UnsupportedVersion(0x01))
        ));
    }

    #[test]
    fn test_unpack_v2_header_rejected() {
        // Construct a v2 frame — should be rejected in v3
        let payload = b"{}".to_vec();
        let mut data = Vec::new();
        data.extend_from_slice(MAGIC);
        data.push(0x02); // v2
        data.extend_from_slice(&(payload.len() as u32).to_be_bytes()); // 4-byte length
        let mut type_field = [0u8; 16];
        type_field[..5].copy_from_slice(b"HELLO");
        data.extend_from_slice(&type_field);
        data.extend_from_slice(&payload);

        assert!(matches!(
            WireFrame::unpack(&data),
            Err(ProtocolError::UnsupportedVersion(0x02))
        ));
    }

    #[test]
    fn test_pack_unpack_authenticated() {
        let hmac_key = [0x42u8; 32];
        let payload = b"{\"site_id\":\"test\"}".to_vec();
        let frame = WireFrame::new(MessageType::Hello, payload.clone());

        let packed = frame.pack_authenticated(&hmac_key).unwrap();

        // Should be pack() + 32 bytes HMAC
        let plain_packed = frame.pack().unwrap();
        assert_eq!(packed.len(), plain_packed.len() + HMAC_SIZE);

        // Unpack with correct key
        let unpacked = WireFrame::unpack_authenticated(&packed, &hmac_key).unwrap();
        assert_eq!(unpacked.msg_type, MessageType::Hello);
        assert_eq!(unpacked.payload, payload);
    }

    #[test]
    fn test_authenticated_frame_wrong_key_rejected() {
        let key1 = [0x42u8; 32];
        let key2 = [0x99u8; 32];
        let frame = WireFrame::new(MessageType::Hello, b"{}".to_vec());

        let packed = frame.pack_authenticated(&key1).unwrap();

        assert!(matches!(
            WireFrame::unpack_authenticated(&packed, &key2),
            Err(ProtocolError::HmacVerificationFailed)
        ));
    }

    #[test]
    fn test_authenticated_frame_tampered_payload_rejected() {
        let hmac_key = [0x42u8; 32];
        let frame = WireFrame::new(MessageType::Hello, b"{\"data\":\"test\"}".to_vec());

        let mut packed = frame.pack_authenticated(&hmac_key).unwrap();

        // Tamper with a payload byte (flip bit in the payload area)
        let tamper_idx = HEADER_SIZE_V2 + 2;
        packed[tamper_idx] ^= 0xFF;

        assert!(matches!(
            WireFrame::unpack_authenticated(&packed, &hmac_key),
            Err(ProtocolError::HmacVerificationFailed)
        ));
    }

    #[test]
    fn test_authenticated_frame_truncated_rejected() {
        let hmac_key = [0x42u8; 32];
        let frame = WireFrame::new(MessageType::Hello, b"{}".to_vec());

        let packed = frame.pack_authenticated(&hmac_key).unwrap();

        // Truncate the HMAC (remove last 16 bytes)
        let truncated = &packed[..packed.len() - 16];

        assert!(WireFrame::unpack_authenticated(truncated, &hmac_key).is_err());
    }

    #[test]
    fn test_message_type_roundtrip() {
        for msg_type in [
            MessageType::SyncRequest,
            MessageType::SyncResponse,
            MessageType::SyncTrigger,
            MessageType::TriggerAck,
            MessageType::Hello,
            MessageType::HelloAck,
            MessageType::Error,
        ] {
            let bytes = msg_type.as_bytes();
            let parsed = MessageType::from_bytes(&bytes).unwrap();
            assert_eq!(parsed, msg_type);
        }
    }

    #[test]
    fn test_invalid_magic() {
        let mut data = vec![0u8; HEADER_SIZE_V2 + 10];
        data[..9].copy_from_slice(b"NOT_VALID");
        assert!(matches!(
            WireFrame::unpack(&data),
            Err(ProtocolError::InvalidMagic)
        ));
    }

    #[test]
    fn test_payload_size_enforcement() {
        let too_big = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let frame = WireFrame::new(MessageType::SyncRequest, too_big);
        assert!(matches!(
            frame.pack(),
            Err(ProtocolError::PayloadTooLarge { .. })
        ));
    }
}
