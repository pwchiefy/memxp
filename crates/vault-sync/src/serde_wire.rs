//! Wire serialization for sync messages.
//!
//! Handles JSON encoding/decoding of sync payloads, including the
//! special `{"__bytes__": "hex"}` encoding for BLOBs (primary keys, site IDs).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use vault_core::crypto::hex;
use vault_core::models::SyncChange;

/// A sync request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    pub site_id: String,
    pub db_version: i64,
    #[serde(default)]
    pub changes: Vec<Value>,
    #[serde(default)]
    pub last_seen_version: i64,
}

/// A sync response payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    pub site_id: String,
    pub db_version: i64,
    #[serde(default)]
    pub changes: Vec<Value>,
    pub current_version: i64,
    #[serde(default)]
    pub has_more_changes: bool,
}

/// A sync trigger payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncTrigger {
    pub site_id: String,
    pub db_version: i64,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub timestamp: String,
}

/// A trigger acknowledgment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerAck {
    pub status: String,
    #[serde(default)]
    pub will_sync: bool,
}

/// A HELLO message for capability exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloMessage {
    pub site_id: String,
    pub protocol_version: u8,
    #[serde(default)]
    pub supported_tables: Vec<String>,
    #[serde(default)]
    pub supported_features: Vec<String>,
    #[serde(default)]
    pub schema_version: i32,
    /// Random 16-byte hex-encoded nonce for replay prevention.
    #[serde(default)]
    pub nonce: String,
}

/// A HELLO_ACK response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloAckMessage {
    pub site_id: String,
    pub protocol_version: u8,
    #[serde(default)]
    pub supported_tables: Vec<String>,
    #[serde(default)]
    pub supported_features: Vec<String>,
    #[serde(default)]
    pub schema_version: i32,
    /// Echoes the nonce from the corresponding HELLO message.
    #[serde(default)]
    pub peer_nonce: String,
    /// Server's current crsql_db_version(), used for peer version tracking.
    #[serde(default)]
    pub db_version: i64,
}

/// An error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMessage {
    pub code: String,
    pub message: String,
}

// =========================================================================
// BLOB Encoding/Decoding
// =========================================================================

/// Encode bytes as `{"__bytes__": "hex_string"}`.
pub fn encode_bytes(data: &[u8]) -> Value {
    Value::Object({
        let mut map = serde_json::Map::new();
        map.insert("__bytes__".to_string(), Value::String(hex::encode(data)));
        map
    })
}

/// Decode `{"__bytes__": "hex_string"}` back to bytes.
///
/// Returns `None` if the value is not a bytes-encoded object.
pub fn decode_bytes(value: &Value) -> Option<Vec<u8>> {
    if let Value::Object(map) = value {
        if let Some(Value::String(hex_str)) = map.get("__bytes__") {
            return hex::decode(hex_str).ok();
        }
    }
    None
}

/// Check if a JSON value is a bytes-encoded object.
pub fn is_bytes_encoded(value: &Value) -> bool {
    matches!(value, Value::Object(map) if map.contains_key("__bytes__"))
}

// =========================================================================
// Change Tuple Encoding/Decoding
// =========================================================================

/// Encode a SyncChange as a JSON array (9 elements).
///
/// ```json
/// ["table", {"__bytes__": "pk_hex"}, "cid", val, col_version, db_version, "site_id_hex", cl, seq]
/// ```
pub fn encode_change(change: &SyncChange) -> Value {
    let pk = encode_bytes(&change.pk);

    let site_id_val = match &change.site_id {
        Some(sid) => Value::String(hex::encode(sid)),
        None => Value::Null,
    };

    let val = match &change.val {
        Some(rusqlite::types::Value::Null) | None => Value::Null,
        Some(rusqlite::types::Value::Integer(i)) => Value::Number((*i).into()),
        Some(rusqlite::types::Value::Real(f)) => serde_json::Number::from_f64(*f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Some(rusqlite::types::Value::Text(s)) => Value::String(s.clone()),
        Some(rusqlite::types::Value::Blob(b)) => encode_bytes(b),
    };

    Value::Array(vec![
        Value::String(change.table.clone()),
        pk,
        Value::String(change.cid.clone()),
        val,
        Value::Number(change.col_version.into()),
        Value::Number(change.db_version.into()),
        site_id_val,
        Value::Number(change.cl.into()),
        Value::Number(change.seq.into()),
    ])
}

/// Decode a JSON array (9 elements) into a SyncChange.
pub fn decode_change(value: &Value) -> Option<SyncChange> {
    let arr = value.as_array()?;
    if arr.len() < 9 {
        return None;
    }

    let table = arr[0].as_str()?.to_string();

    // pk: can be {"__bytes__": "hex"} or plain string
    let pk = if let Some(bytes) = decode_bytes(&arr[1]) {
        bytes
    } else if let Some(s) = arr[1].as_str() {
        s.as_bytes().to_vec()
    } else {
        return None;
    };

    let cid = arr[2].as_str()?.to_string();

    // val: can be null, number, string, or bytes-encoded
    let val = match &arr[3] {
        Value::Null => None,
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(rusqlite::types::Value::Integer(i))
            } else {
                n.as_f64().map(rusqlite::types::Value::Real)
            }
        }
        Value::String(s) => Some(rusqlite::types::Value::Text(s.clone())),
        v if is_bytes_encoded(v) => decode_bytes(v).map(rusqlite::types::Value::Blob),
        _ => None,
    };

    let col_version = arr[4].as_i64()?;
    let db_version = arr[5].as_i64()?;

    // site_id: can be hex string or bytes-encoded
    let site_id = match &arr[6] {
        Value::String(s) => hex::decode(s).ok(),
        v if is_bytes_encoded(v) => decode_bytes(v),
        Value::Null => None,
        _ => None,
    };

    let cl = arr[7].as_i64()?;
    let seq = arr[8].as_i64()?;

    Some(SyncChange {
        table,
        pk,
        cid,
        val,
        col_version,
        db_version,
        site_id,
        cl,
        seq,
    })
}

/// Encode multiple changes as a JSON array.
pub fn encode_changes(changes: &[SyncChange]) -> Vec<Value> {
    changes.iter().map(encode_change).collect()
}

/// Decode multiple changes from a JSON array.
pub fn decode_changes(values: &[Value]) -> Vec<SyncChange> {
    values.iter().filter_map(decode_change).collect()
}

/// Limit changes to fit within a payload size budget.
///
/// Returns `(changes_to_send, has_more)`.
pub fn limit_changes_by_size(
    changes: &[SyncChange],
    max_payload_bytes: usize,
) -> (Vec<SyncChange>, bool) {
    if changes.is_empty() {
        return (Vec::new(), false);
    }

    let mut total_size = 100; // overhead for the wrapper JSON
    let mut result = Vec::new();

    for change in changes {
        // Estimate the JSON size of this change
        let encoded = encode_change(change);
        let size = serde_json::to_string(&encoded)
            .map(|s| s.len())
            .unwrap_or(200);

        if total_size + size > max_payload_bytes && !result.is_empty() {
            return (result, true);
        }

        total_size += size;
        result.push(change.clone());
    }

    (result, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_change_json_blobs() {
        let change = SyncChange {
            table: "vault_entries".to_string(),
            pk: vec![0xAB, 0xCD],
            cid: "value".to_string(),
            val: Some(rusqlite::types::Value::Text("secret".to_string())),
            col_version: 42,
            db_version: 335,
            site_id: Some(vec![0xF5, 0x2F, 0x35, 0xF6]),
            cl: 1,
            seq: 0,
        };

        let encoded = encode_change(&change);
        let arr = encoded.as_array().unwrap();

        // pk should be {"__bytes__": "abcd"}
        assert!(is_bytes_encoded(&arr[1]));
        let pk_bytes = decode_bytes(&arr[1]).unwrap();
        assert_eq!(pk_bytes, vec![0xAB, 0xCD]);

        // site_id should be hex string
        assert_eq!(arr[6].as_str().unwrap(), "f52f35f6");
    }

    #[test]
    fn test_decode_change_json_blobs() {
        let json = serde_json::json!([
            "vault_entries",
            {"__bytes__": "abcd"},
            "value",
            "sk-secret",
            42,
            335,
            "f52f35f6",
            1,
            0
        ]);

        let change = decode_change(&json).unwrap();
        assert_eq!(change.table, "vault_entries");
        assert_eq!(change.pk, vec![0xAB, 0xCD]);
        assert_eq!(change.cid, "value");
        assert_eq!(change.col_version, 42);
        assert_eq!(change.db_version, 335);
        assert_eq!(change.site_id, Some(vec![0xF5, 0x2F, 0x35, 0xF6]));
    }

    #[test]
    fn test_msgpack_roundtrip() {
        let req = SyncRequest {
            site_id: "f52f35f66eef4459".to_string(),
            db_version: 335,
            changes: vec![
                serde_json::json!(["vault_entries", {"__bytes__": "abcd"}, "value", "test", 1, 1, "aabb", 1, 0]),
            ],
            last_seen_version: 320,
        };

        // Encode as msgpack
        let packed = rmp_serde::to_vec(&req).unwrap();
        assert!(!packed.is_empty());

        // Decode from msgpack
        let unpacked: SyncRequest = rmp_serde::from_slice(&packed).unwrap();
        assert_eq!(unpacked.site_id, "f52f35f66eef4459");
        assert_eq!(unpacked.db_version, 335);
        assert_eq!(unpacked.changes.len(), 1);
    }

    #[test]
    fn test_payload_size_limiting() {
        // Create 100 changes
        let changes: Vec<SyncChange> = (0..100)
            .map(|i| SyncChange {
                table: "vault_entries".to_string(),
                pk: format!("api/key{i}").into_bytes(),
                cid: "value".to_string(),
                val: Some(rusqlite::types::Value::Text(format!("value-{i}"))),
                col_version: 1,
                db_version: i as i64,
                site_id: Some(vec![0xAA, 0xBB]),
                cl: 1,
                seq: 0,
            })
            .collect();

        // Limit to 1KB
        let (limited, has_more) = limit_changes_by_size(&changes, 1024);
        assert!(!limited.is_empty());
        assert!(limited.len() < 100);
        assert!(has_more);
    }

    #[test]
    fn test_hello_nonce_roundtrip() {
        let hello = HelloMessage {
            site_id: "abc123".to_string(),
            protocol_version: 3,
            supported_tables: vec!["vault_entries".into()],
            supported_features: vec![],
            schema_version: 5,
            nonce: "deadbeef01020304aabbccdd11223344".to_string(),
        };
        let json = serde_json::to_string(&hello).unwrap();
        let parsed: HelloMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.nonce, "deadbeef01020304aabbccdd11223344");
    }

    #[test]
    fn test_hello_ack_peer_nonce_echo() {
        let ack = HelloAckMessage {
            site_id: "abc123".to_string(),
            protocol_version: 3,
            supported_tables: vec![],
            supported_features: vec![],
            schema_version: 5,
            peer_nonce: "aabbccdd11223344deadbeef01020304".to_string(),
            db_version: 42,
        };
        let json = serde_json::to_string(&ack).unwrap();
        let parsed: HelloAckMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.peer_nonce, "aabbccdd11223344deadbeef01020304");
        assert_eq!(parsed.db_version, 42);
    }

    #[test]
    fn test_hello_empty_nonce_deserialization() {
        // Simulate a message without nonce field (backward compat via serde(default))
        let json = r#"{"site_id":"abc","protocol_version":3,"schema_version":5}"#;
        let hello: HelloMessage = serde_json::from_str(json).unwrap();
        assert_eq!(hello.nonce, "");

        let ack_json = r#"{"site_id":"abc","protocol_version":3,"schema_version":5}"#;
        let ack: HelloAckMessage = serde_json::from_str(ack_json).unwrap();
        assert_eq!(ack.peer_nonce, "");
    }

    #[test]
    fn test_error_payload() {
        let err = ErrorMessage {
            code: "SYNC_FAILED".to_string(),
            message: "Database locked".to_string(),
        };

        let json = serde_json::to_string(&err).unwrap();
        let parsed: ErrorMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.code, "SYNC_FAILED");
        assert_eq!(parsed.message, "Database locked");
    }

    #[test]
    fn test_change_roundtrip() {
        let change = SyncChange {
            table: "vault_entries".to_string(),
            pk: b"api/openai/key".to_vec(),
            cid: "value".to_string(),
            val: Some(rusqlite::types::Value::Text("sk-secret".to_string())),
            col_version: 42,
            db_version: 335,
            site_id: Some(vec![0xF5, 0x2F, 0x35, 0xF6, 0x6E, 0xEF, 0x44, 0x59]),
            cl: 1,
            seq: 0,
        };

        let encoded = encode_change(&change);
        let decoded = decode_change(&encoded).unwrap();

        assert_eq!(decoded.table, change.table);
        assert_eq!(decoded.pk, change.pk);
        assert_eq!(decoded.cid, change.cid);
        assert_eq!(decoded.col_version, change.col_version);
        assert_eq!(decoded.db_version, change.db_version);
        assert_eq!(decoded.site_id, change.site_id);
        assert_eq!(decoded.cl, change.cl);
        assert_eq!(decoded.seq, change.seq);
    }
}
