//! Wire compatibility tests for memxp sync protocol.
//!
//! Tests that Rust can encode/decode wire frames compatible with
//! the v3 protocol (HMAC-authenticated frames).

use serde_json::json;
use vault_sync::protocol::{
    MessageType, ProtocolError, WireFrame, HMAC_SIZE, MAGIC, PROTOCOL_VERSION,
};
use vault_sync::serde_wire::{
    decode_bytes, decode_change, decode_changes, encode_bytes, encode_change, encode_changes,
    is_bytes_encoded, ErrorMessage, HelloAckMessage, HelloMessage, SyncRequest, SyncResponse,
    SyncTrigger, TriggerAck,
};

use vault_core::models::SyncChange;
use vault_sync::capabilities::{
    filter_changes_for_peer, PeerCapabilities, ALL_CRR_TABLES, ALL_FEATURES,
};

// =========================================================================
// Fixture helpers — build synthetic frames matching the v3 wire format
// =========================================================================

/// Build a binary HELLO frame (v3).
fn v3_hello_fixture() -> Vec<u8> {
    let hello = HelloMessage {
        site_id: "a1b2c3d4e5f60718".to_string(),
        protocol_version: 3,
        supported_tables: vec![
            "vault_entries".into(),
            "vault_guides".into(),
            "vault_meta".into(),
        ],
        supported_features: vec!["incremental_sync".into(), "hello_negotiation".into()],
        schema_version: 5,
        nonce: "deadbeef01020304aabbccdd11223344".to_string(),
    };
    let payload = serde_json::to_vec(&hello).unwrap();
    let frame = WireFrame::new(MessageType::Hello, payload);
    frame.pack().unwrap()
}

/// Build a v1 HELLO frame (2-byte length) — should be rejected.
fn v1_hello_fixture() -> Vec<u8> {
    let hello = HelloMessage {
        site_id: "deadbeef01020304".to_string(),
        protocol_version: 1,
        supported_tables: vec!["vault_entries".into(), "vault_guides".into()],
        supported_features: vec![],
        schema_version: 3,
        nonce: String::new(),
    };
    let payload = serde_json::to_vec(&hello).unwrap();

    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.push(0x01); // v1
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    let mut type_field = [0u8; 16];
    type_field[..5].copy_from_slice(b"HELLO");
    buf.extend_from_slice(&type_field);
    buf.extend_from_slice(&payload);
    buf
}

/// Build a v2 HELLO frame — should be rejected.
fn v2_hello_fixture() -> Vec<u8> {
    let hello = HelloMessage {
        site_id: "deadbeef01020304".to_string(),
        protocol_version: 2,
        supported_tables: vec!["vault_entries".into()],
        supported_features: vec![],
        schema_version: 4,
        nonce: String::new(),
    };
    let payload = serde_json::to_vec(&hello).unwrap();

    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.push(0x02); // v2
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes()); // 4-byte length
    let mut type_field = [0u8; 16];
    type_field[..5].copy_from_slice(b"HELLO");
    buf.extend_from_slice(&type_field);
    buf.extend_from_slice(&payload);
    buf
}

/// Build a binary SYNC_REQUEST with sample changes (v3).
fn v3_sync_request_fixture() -> Vec<u8> {
    let changes = vec![
        json!([
            "vault_entries",
            {"__bytes__": "6170692f6f70656e61692f6b6579"},
            "value",
            "sk-secret-12345",
            1,
            42,
            "a1b2c3d4e5f60718",
            1,
            0
        ]),
        json!([
            "vault_entries",
            {"__bytes__": "6170692f6f70656e61692f6b6579"},
            "category",
            "api_key",
            1,
            42,
            "a1b2c3d4e5f60718",
            1,
            1
        ]),
        json!([
            "vault_guides",
            {"__bytes__": "6465706c6f792d67756964"},
            "content",
            "# Deploy Guide\n\nStep 1...",
            1,
            43,
            "a1b2c3d4e5f60718",
            1,
            2
        ]),
    ];

    let req = SyncRequest {
        site_id: "a1b2c3d4e5f60718".to_string(),
        db_version: 43,
        changes,
        last_seen_version: 0,
    };
    let payload = serde_json::to_vec(&req).unwrap();
    let frame = WireFrame::new(MessageType::SyncRequest, payload);
    frame.pack().unwrap()
}

/// Build a binary SYNC_RESPONSE fixture (v3).
fn v3_sync_response_fixture() -> Vec<u8> {
    let resp = SyncResponse {
        site_id: "bbccddee11223344".to_string(),
        db_version: 100,
        changes: vec![json!([
            "vault_entries",
            {"__bytes__": "6462f706f73746772657373"},
            "value",
            "postgres://user:pass@host/db",
            5,
            99,
            "bbccddee11223344",
            1,
            0
        ])],
        current_version: 100,
        has_more_changes: false,
    };
    let payload = serde_json::to_vec(&resp).unwrap();
    let frame = WireFrame::new(MessageType::SyncResponse, payload);
    frame.pack().unwrap()
}

// =========================================================================
// Wire Frame Decode Tests
// =========================================================================

#[test]
fn test_v3_hello_decoded() {
    let data = v3_hello_fixture();

    let frame = WireFrame::unpack(&data).unwrap();
    assert_eq!(frame.version, PROTOCOL_VERSION);
    assert_eq!(frame.msg_type, MessageType::Hello);

    let hello: HelloMessage = serde_json::from_slice(&frame.payload).unwrap();
    assert_eq!(hello.site_id, "a1b2c3d4e5f60718");
    assert_eq!(hello.protocol_version, 3);
    assert_eq!(hello.supported_tables.len(), 3);
    assert!(hello
        .supported_tables
        .contains(&"vault_entries".to_string()));
    assert!(hello.supported_tables.contains(&"vault_guides".to_string()));
    assert!(hello.supported_tables.contains(&"vault_meta".to_string()));
    assert_eq!(hello.schema_version, 5);
    assert_eq!(hello.nonce, "deadbeef01020304aabbccdd11223344");
}

#[test]
fn test_v1_hello_rejected() {
    let data = v1_hello_fixture();

    let result = WireFrame::unpack(&data);
    assert!(result.is_err());
    match result {
        Err(ProtocolError::UnsupportedVersion(1)) => {}
        other => panic!("Expected UnsupportedVersion(1), got {other:?}"),
    }
}

#[test]
fn test_v2_hello_rejected() {
    let data = v2_hello_fixture();

    let result = WireFrame::unpack(&data);
    assert!(result.is_err());
    match result {
        Err(ProtocolError::UnsupportedVersion(2)) => {}
        other => panic!("Expected UnsupportedVersion(2), got {other:?}"),
    }
}

#[test]
fn test_v3_sync_request_decoded() {
    let data = v3_sync_request_fixture();

    let frame = WireFrame::unpack(&data).unwrap();
    assert_eq!(frame.msg_type, MessageType::SyncRequest);

    let req: SyncRequest = serde_json::from_slice(&frame.payload).unwrap();
    assert_eq!(req.site_id, "a1b2c3d4e5f60718");
    assert_eq!(req.db_version, 43);
    assert_eq!(req.changes.len(), 3);
    assert_eq!(req.last_seen_version, 0);

    // Decode the first change and verify BLOB handling
    let change = decode_change(&req.changes[0]).unwrap();
    assert_eq!(change.table, "vault_entries");
    assert_eq!(std::str::from_utf8(&change.pk).unwrap(), "api/openai/key");
    assert_eq!(change.cid, "value");
    assert_eq!(change.db_version, 42);
}

#[test]
fn test_v3_sync_response_decoded() {
    let data = v3_sync_response_fixture();

    let frame = WireFrame::unpack(&data).unwrap();
    assert_eq!(frame.msg_type, MessageType::SyncResponse);

    let resp: SyncResponse = serde_json::from_slice(&frame.payload).unwrap();
    assert_eq!(resp.site_id, "bbccddee11223344");
    assert_eq!(resp.current_version, 100);
    assert!(!resp.has_more_changes);
    assert_eq!(resp.changes.len(), 1);
}

// =========================================================================
// Authenticated Frame Tests
// =========================================================================

#[test]
fn test_authenticated_frame_round_trip() {
    let hmac_key = vault_core::crypto::derive_sync_hmac_key("test-passphrase");

    let hello = HelloMessage {
        site_id: "abc123".to_string(),
        protocol_version: 3,
        supported_tables: vec!["vault_entries".into()],
        supported_features: vec![],
        schema_version: 5,
        nonce: "aabbccdd".to_string(),
    };
    let payload = serde_json::to_vec(&hello).unwrap();
    let frame = WireFrame::new(MessageType::Hello, payload);

    let packed = frame.pack_authenticated(&hmac_key).unwrap();
    let unpacked = WireFrame::unpack_authenticated(&packed, &hmac_key).unwrap();

    let decoded: HelloMessage = serde_json::from_slice(&unpacked.payload).unwrap();
    assert_eq!(decoded.site_id, "abc123");
    assert_eq!(decoded.nonce, "aabbccdd");
}

#[test]
fn test_authenticated_frame_wrong_passphrase_rejected() {
    let key1 = vault_core::crypto::derive_sync_hmac_key("passphrase-one");
    let key2 = vault_core::crypto::derive_sync_hmac_key("passphrase-two");

    let frame = WireFrame::new(MessageType::Hello, b"{}".to_vec());
    let packed = frame.pack_authenticated(&key1).unwrap();

    match WireFrame::unpack_authenticated(&packed, &key2) {
        Err(ProtocolError::HmacVerificationFailed) => {}
        other => panic!("Expected HmacVerificationFailed, got {other:?}"),
    }
}

#[test]
fn test_authenticated_sync_request_round_trip() {
    let hmac_key = vault_core::crypto::derive_sync_hmac_key("shared-vault-pass");

    let req = SyncRequest {
        site_id: "f5e6d7c8b9a01234".to_string(),
        db_version: 42,
        changes: vec![json!([
            "vault_entries",
            {"__bytes__": "6b6579"},
            "value",
            "secret",
            1, 42, "aabb", 1, 0
        ])],
        last_seen_version: 0,
    };

    let payload = serde_json::to_vec(&req).unwrap();
    let frame = WireFrame::new(MessageType::SyncRequest, payload);
    let packed = frame.pack_authenticated(&hmac_key).unwrap();

    // Verify size includes HMAC
    let plain = frame.pack().unwrap();
    assert_eq!(packed.len(), plain.len() + HMAC_SIZE);

    // Round-trip
    let unpacked = WireFrame::unpack_authenticated(&packed, &hmac_key).unwrap();
    let decoded: SyncRequest = serde_json::from_slice(&unpacked.payload).unwrap();
    assert_eq!(decoded.site_id, "f5e6d7c8b9a01234");
    assert_eq!(decoded.db_version, 42);
}

// =========================================================================
// Wire Frame Encode Tests (verify Rust output can be decoded)
// =========================================================================

#[test]
fn test_rust_hello_encoded_round_trip() {
    let hello = HelloMessage {
        site_id: "f5e6d7c8b9a01234".to_string(),
        protocol_version: PROTOCOL_VERSION,
        supported_tables: ALL_CRR_TABLES.iter().map(|s| s.to_string()).collect(),
        supported_features: ALL_FEATURES.iter().map(|s| s.to_string()).collect(),
        schema_version: 5,
        nonce: "aabbccdd11223344".to_string(),
    };

    let payload = serde_json::to_vec(&hello).unwrap();
    let frame = WireFrame::new(MessageType::Hello, payload);
    let packed = frame.pack().unwrap();

    // Verify header structure
    assert_eq!(&packed[..9], MAGIC);
    assert_eq!(packed[9], PROTOCOL_VERSION);

    // Verify round-trip
    let unpacked = WireFrame::unpack(&packed).unwrap();
    let decoded: HelloMessage = serde_json::from_slice(&unpacked.payload).unwrap();
    assert_eq!(decoded.site_id, hello.site_id);
    assert_eq!(decoded.supported_tables.len(), ALL_CRR_TABLES.len());
    assert_eq!(decoded.supported_features.len(), ALL_FEATURES.len());
    assert_eq!(decoded.nonce, "aabbccdd11223344");
}

#[test]
fn test_rust_sync_request_encoded_round_trip() {
    let change = SyncChange {
        table: "vault_entries".to_string(),
        pk: b"api/test/key".to_vec(),
        cid: "value".to_string(),
        val: Some(rusqlite::types::Value::Text("secret-val".to_string())),
        col_version: 1,
        db_version: 10,
        site_id: Some(vec![0xF5, 0xE6, 0xD7, 0xC8, 0xB9, 0xA0, 0x12, 0x34]),
        cl: 1,
        seq: 0,
    };

    let req = SyncRequest {
        site_id: "f5e6d7c8b9a01234".to_string(),
        db_version: 10,
        changes: encode_changes(std::slice::from_ref(&change)),
        last_seen_version: 0,
    };

    let payload = serde_json::to_vec(&req).unwrap();
    let frame = WireFrame::new(MessageType::SyncRequest, payload);
    let packed = frame.pack().unwrap();

    // Decode and verify
    let unpacked = WireFrame::unpack(&packed).unwrap();
    let decoded_req: SyncRequest = serde_json::from_slice(&unpacked.payload).unwrap();
    assert_eq!(decoded_req.changes.len(), 1);

    let decoded_change = decode_change(&decoded_req.changes[0]).unwrap();
    assert_eq!(decoded_change.table, "vault_entries");
    assert_eq!(decoded_change.pk, b"api/test/key");
    assert_eq!(decoded_change.cid, "value");
}

// =========================================================================
// BLOB Encoding Compatibility
// =========================================================================

#[test]
fn test_blob_encoding_matches_python() {
    // Python encodes bytes as: {"__bytes__": "hex_string"}
    let data = vec![0xAB, 0xCD, 0xEF, 0x01];
    let encoded = encode_bytes(&data);

    assert!(is_bytes_encoded(&encoded));
    let obj = encoded.as_object().unwrap();
    assert_eq!(obj.get("__bytes__").unwrap().as_str().unwrap(), "abcdef01");

    // Decode round-trip
    let decoded = decode_bytes(&encoded).unwrap();
    assert_eq!(decoded, data);
}

#[test]
fn test_python_blob_format_decoded() {
    // Simulate a Python-encoded BLOB value
    let python_json = json!({"__bytes__": "48656c6c6f"});
    assert!(is_bytes_encoded(&python_json));

    let decoded = decode_bytes(&python_json).unwrap();
    assert_eq!(decoded, b"Hello");
}

#[test]
fn test_change_tuple_9_elements() {
    // Python always sends 9-element arrays
    let change = SyncChange {
        table: "vault_entries".to_string(),
        pk: b"test/path".to_vec(),
        cid: "value".to_string(),
        val: Some(rusqlite::types::Value::Text("data".to_string())),
        col_version: 5,
        db_version: 100,
        site_id: Some(vec![0xAA, 0xBB, 0xCC, 0xDD]),
        cl: 1,
        seq: 3,
    };

    let encoded = encode_change(&change);
    let arr = encoded.as_array().unwrap();
    assert_eq!(arr.len(), 9, "Change tuple must have exactly 9 elements");

    // Verify positions match Python convention
    assert_eq!(arr[0].as_str().unwrap(), "vault_entries"); // [0] table
    assert!(is_bytes_encoded(&arr[1])); // [1] pk (BLOB)
    assert_eq!(arr[2].as_str().unwrap(), "value"); // [2] cid
    assert_eq!(arr[3].as_str().unwrap(), "data"); // [3] val
    assert_eq!(arr[4].as_i64().unwrap(), 5); // [4] col_version
    assert_eq!(arr[5].as_i64().unwrap(), 100); // [5] db_version
    assert_eq!(arr[6].as_str().unwrap(), "aabbccdd"); // [6] site_id hex
    assert_eq!(arr[7].as_i64().unwrap(), 1); // [7] cl
    assert_eq!(arr[8].as_i64().unwrap(), 3); // [8] seq
}

// =========================================================================
// MessagePack Interop
// =========================================================================

#[test]
fn test_msgpack_sync_request_interop() {
    let req = SyncRequest {
        site_id: "aabbccdd11223344".to_string(),
        db_version: 500,
        changes: vec![json!([
            "vault_entries",
            {"__bytes__": "6b657931"},
            "value",
            "test-secret",
            1,
            500,
            "aabbccdd11223344",
            1,
            0
        ])],
        last_seen_version: 450,
    };

    // Encode as MessagePack
    let packed = rmp_serde::to_vec(&req).unwrap();
    assert!(!packed.is_empty());

    // Decode from MessagePack
    let decoded: SyncRequest = rmp_serde::from_slice(&packed).unwrap();
    assert_eq!(decoded.site_id, req.site_id);
    assert_eq!(decoded.db_version, req.db_version);
    assert_eq!(decoded.changes.len(), 1);
    assert_eq!(decoded.last_seen_version, 450);
}

// =========================================================================
// Capability Negotiation Compat
// =========================================================================

#[test]
fn test_filter_changes_for_legacy_peer() {
    // Simulate a Python peer that only supports 3 tables (older version)
    let legacy_peer =
        PeerCapabilities::with_tables(&["vault_entries", "vault_guides", "vault_meta"]);

    let changes = vec![
        SyncChange {
            table: "vault_entries".to_string(),
            pk: b"key1".to_vec(),
            cid: "value".to_string(),
            val: None,
            col_version: 1,
            db_version: 1,
            site_id: None,
            cl: 1,
            seq: 0,
        },
        SyncChange {
            table: "sync_conflicts".to_string(),
            pk: b"conflict1".to_vec(),
            cid: "path".to_string(),
            val: None,
            col_version: 1,
            db_version: 2,
            site_id: None,
            cl: 1,
            seq: 0,
        },
        SyncChange {
            table: "sync_conflicts".to_string(),
            pk: b"conflict2".to_vec(),
            cid: "path".to_string(),
            val: None,
            col_version: 1,
            db_version: 3,
            site_id: None,
            cl: 1,
            seq: 0,
        },
    ];

    let (accepted, backlog) = filter_changes_for_peer(&changes, &legacy_peer);
    assert_eq!(accepted.len(), 1); // Only vault_entries
    assert_eq!(backlog.len(), 2); // unsupported sync_conflicts rows
}

// =========================================================================
// Error Message Format
// =========================================================================

#[test]
fn test_error_message_wire_format() {
    let err = ErrorMessage {
        code: "SYNC_FAILED".to_string(),
        message: "Database is locked by another process".to_string(),
    };

    let payload = serde_json::to_vec(&err).unwrap();
    let frame = WireFrame::new(MessageType::Error, payload);
    let packed = frame.pack().unwrap();

    let unpacked = WireFrame::unpack(&packed).unwrap();
    assert_eq!(unpacked.msg_type, MessageType::Error);

    let decoded: ErrorMessage = serde_json::from_slice(&unpacked.payload).unwrap();
    assert_eq!(decoded.code, "SYNC_FAILED");
    assert_eq!(decoded.message, "Database is locked by another process");
}

// =========================================================================
// Trigger / Ack Wire Format
// =========================================================================

#[test]
fn test_sync_trigger_wire_format() {
    let trigger = SyncTrigger {
        site_id: "abcdef0123456789".to_string(),
        db_version: 200,
        reason: "credential_update".to_string(),
        timestamp: "2025-06-15T10:30:00Z".to_string(),
    };

    let payload = serde_json::to_vec(&trigger).unwrap();
    let frame = WireFrame::new(MessageType::SyncTrigger, payload);
    let packed = frame.pack().unwrap();

    let unpacked = WireFrame::unpack(&packed).unwrap();
    assert_eq!(unpacked.msg_type, MessageType::SyncTrigger);

    let decoded: SyncTrigger = serde_json::from_slice(&unpacked.payload).unwrap();
    assert_eq!(decoded.reason, "credential_update");
}

#[test]
fn test_trigger_ack_wire_format() {
    let ack = TriggerAck {
        status: "ok".to_string(),
        will_sync: true,
    };

    let payload = serde_json::to_vec(&ack).unwrap();
    let frame = WireFrame::new(MessageType::TriggerAck, payload);
    let packed = frame.pack().unwrap();

    let unpacked = WireFrame::unpack(&packed).unwrap();
    let decoded: TriggerAck = serde_json::from_slice(&unpacked.payload).unwrap();
    assert_eq!(decoded.status, "ok");
    assert!(decoded.will_sync);
}

// =========================================================================
// Incremental Sync Version Tracking
// =========================================================================

#[test]
fn test_incremental_sync_versions() {
    // Simulate incremental sync: first sync sends all changes, second sends only new
    let all_changes: Vec<SyncChange> = (0..10)
        .map(|i| SyncChange {
            table: "vault_entries".to_string(),
            pk: format!("key{i}").into_bytes(),
            cid: "value".to_string(),
            val: Some(rusqlite::types::Value::Text(format!("val{i}"))),
            col_version: 1,
            db_version: (i + 1) as i64,
            site_id: Some(vec![0xAA, 0xBB]),
            cl: 1,
            seq: i as i64,
        })
        .collect();

    // First sync: version 0 → all 10 changes
    let first_batch: Vec<_> = all_changes
        .iter()
        .filter(|c| c.db_version > 0)
        .cloned()
        .collect();
    assert_eq!(first_batch.len(), 10);

    // Second sync: version 5 → only changes with db_version > 5
    let second_batch: Vec<_> = all_changes
        .iter()
        .filter(|c| c.db_version > 5)
        .cloned()
        .collect();
    assert_eq!(second_batch.len(), 5);

    // Encode and verify
    let encoded = encode_changes(&second_batch);
    assert_eq!(encoded.len(), 5);

    let decoded = decode_changes(&encoded);
    assert_eq!(decoded.len(), 5);
    assert!(decoded.iter().all(|c| c.db_version > 5));
}

// =========================================================================
// HELLO Nonce Tests
// =========================================================================

#[test]
fn test_hello_nonce_in_wire_frame() {
    let hello = HelloMessage {
        site_id: "test123".to_string(),
        protocol_version: 3,
        supported_tables: vec![],
        supported_features: vec![],
        schema_version: 5,
        nonce: "aabbccdd11223344eeff00112233aabb".to_string(),
    };

    let payload = serde_json::to_vec(&hello).unwrap();
    let frame = WireFrame::new(MessageType::Hello, payload);
    let packed = frame.pack().unwrap();
    let unpacked = WireFrame::unpack(&packed).unwrap();

    let decoded: HelloMessage = serde_json::from_slice(&unpacked.payload).unwrap();
    assert_eq!(decoded.nonce, "aabbccdd11223344eeff00112233aabb");
}

#[test]
fn test_hello_ack_peer_nonce_in_wire_frame() {
    let ack = HelloAckMessage {
        site_id: "responder123".to_string(),
        protocol_version: 3,
        supported_tables: vec![],
        supported_features: vec![],
        schema_version: 5,
        peer_nonce: "aabbccdd11223344eeff00112233aabb".to_string(),
        db_version: 0,
    };

    let payload = serde_json::to_vec(&ack).unwrap();
    let frame = WireFrame::new(MessageType::HelloAck, payload);
    let packed = frame.pack().unwrap();
    let unpacked = WireFrame::unpack(&packed).unwrap();

    let decoded: HelloAckMessage = serde_json::from_slice(&unpacked.payload).unwrap();
    assert_eq!(decoded.peer_nonce, "aabbccdd11223344eeff00112233aabb");
}
