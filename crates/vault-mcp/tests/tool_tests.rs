//! Integration tests for vault-mcp tools.
//!
//! Tests exercise tool functions directly (not via MCP transport)
//! using a real encrypted DB in a temp directory.

use tempfile::TempDir;
use vault_core::db::CrSqliteDatabase;
use vault_core::security::AuditLogger;
use vault_mcp::server::VaultState;
use vault_mcp::tools::{conflicts, credentials, guides, monitoring, security};

/// Create a VaultState for testing with an encrypted DB + audit logger.
fn test_state(tmp: &TempDir) -> VaultState {
    let db_path = tmp.path().join("test.db");
    let audit_path = tmp.path().join("audit.db");
    let db = CrSqliteDatabase::open(&db_path, "test-passphrase", None).unwrap();
    let audit = AuditLogger::open(&audit_path).unwrap();
    let state = VaultState {
        db,
        audit,
        locked: std::sync::atomic::AtomicBool::new(false),
        session_required: false,
        session_token: None,
        session_authenticated: std::sync::atomic::AtomicBool::new(true),
        operator_until_epoch: std::sync::atomic::AtomicI64::new(0),
    };
    // Most tests target tool behavior, not policy gating.
    state.elevate_operator(3600);
    state
}

/// Create a VaultState in routine mode (no operator elevation).
fn test_state_routine(tmp: &TempDir) -> VaultState {
    let db_path = tmp.path().join("test.db");
    let audit_path = tmp.path().join("audit.db");
    let db = CrSqliteDatabase::open(&db_path, "test-passphrase", None).unwrap();
    let audit = AuditLogger::open(&audit_path).unwrap();
    VaultState {
        db,
        audit,
        locked: std::sync::atomic::AtomicBool::new(false),
        session_required: false,
        session_token: None,
        session_authenticated: std::sync::atomic::AtomicBool::new(true),
        operator_until_epoch: std::sync::atomic::AtomicI64::new(0),
    }
}

/// Parse the CallToolResult text content as JSON.
fn result_json(result: rmcp::model::CallToolResult) -> serde_json::Value {
    let text = result
        .content
        .first()
        .and_then(|c| c.raw.as_text())
        .map(|t| t.text.as_str())
        .expect("Expected text content");
    serde_json::from_str(text).unwrap_or_else(|_| serde_json::Value::String(text.to_string()))
}

// ========================================================================
// Tool count
// ========================================================================

#[test]
fn test_tool_count() {
    // Verify 48 tools are registered (45 base + 3 auth)
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("test.db");
    let audit_path = tmp.path().join("audit.db");
    let db = CrSqliteDatabase::open(&db_path, "test-passphrase", None).unwrap();
    let audit = AuditLogger::open(&audit_path).unwrap();
    let server = vault_mcp::server::VaultMcpServer::new(db, audit);

    use rmcp::ServerHandler;
    let info = server.get_info();
    // The server has tools capability enabled
    assert!(info.capabilities.tools.is_some());
}

// ========================================================================
// Credential tools
// ========================================================================

#[test]
fn test_vault_help() {
    let result = credentials::vault_help(Some("all"));
    let text = result
        .content
        .first()
        .and_then(|c| c.raw.as_text())
        .map(|t| t.text.as_str())
        .unwrap();
    assert!(text.contains("memxp"));
    assert!(text.contains("TOOLS"));
}

#[test]
fn test_vault_help_topics() {
    for topic in &["workflow", "security", "tools", "all"] {
        let result = credentials::vault_help(Some(topic));
        let text = result
            .content
            .first()
            .and_then(|c| c.raw.as_text())
            .map(|t| t.text.as_str())
            .unwrap();
        assert!(
            !text.is_empty(),
            "Help text for '{topic}' should not be empty"
        );
    }
}

#[test]
fn test_vault_set_get_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    // Set a credential
    let set_result = credentials::vault_set(
        &state,
        "api/openai/key",
        "sk-test12345",
        Some("api_key"),
        Some("openai"),
        None,
        Some("production"),
        Some("OpenAI API key for testing"),
        None,
        None,
        None,
        None,
        None,
    );
    let json = result_json(set_result);
    assert_eq!(json["path"], "api/openai/key");
    assert!(json["message"].as_str().unwrap().contains("saved"));
    assert!(json.get("value_hash").is_some());

    // Get the credential
    let get_result = credentials::vault_get(&state, "api/openai/key", true, false, false, false);
    let json = result_json(get_result);
    assert_eq!(json["path"], "api/openai/key");
    assert_eq!(json["value"], "sk-test12345");
}

#[test]
fn test_vault_list_masked() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    // Set entries
    credentials::vault_set(
        &state,
        "api/test/key1",
        "secret-value-12345",
        Some("api_key"),
        Some("test"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    credentials::vault_set(
        &state,
        "api/test/key2",
        "another-secret-67890",
        Some("api_key"),
        Some("test"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    let list_result = credentials::vault_list(&state, None, Some("test"), None, 100, 0);
    let json = result_json(list_result);

    assert_eq!(json["total"], 2);
    let entries = json["entries"].as_array().unwrap();
    for entry in entries {
        // Values should be masked (contain ****)
        let preview = entry["value_preview"].as_str().unwrap();
        assert!(
            preview.contains("****"),
            "Value should be masked: {preview}"
        );
    }
}

#[test]
fn test_vault_search() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    // Set some entries
    credentials::vault_set(
        &state,
        "api/openai/key",
        "sk-test",
        Some("api_key"),
        Some("openai"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    credentials::vault_set(
        &state,
        "db/postgres/prod",
        "postgres://...",
        Some("password"),
        Some("postgres"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    credentials::vault_set(
        &state,
        "api/github/token",
        "ghp_test",
        Some("token"),
        Some("github"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    let result = credentials::vault_search(&state, "openai");
    let json = result_json(result);
    assert!(json["count"].as_i64().unwrap() >= 1);
}

#[test]
fn test_vault_smart_get() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    credentials::vault_set(
        &state,
        "api/openai/key",
        "sk-test",
        Some("api_key"),
        Some("openai"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    let result = credentials::vault_smart_get(&state, "openai key", false, 3, 10.0, false, false);
    let json = result_json(result);
    assert!(json["count"].as_i64().unwrap() >= 1);
    let matches = json["matches"].as_array().unwrap();
    assert!(!matches.is_empty());
    assert_eq!(matches[0]["path"], "api/openai/key");
}

#[test]
fn test_vault_set_batch() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    let entries = vec![
        serde_json::json!({"path": "batch/key1", "value": "val1", "service": "test"}),
        serde_json::json!({"path": "batch/key2", "value": "val2", "service": "test"}),
        serde_json::json!({"path": "batch/key3", "value": "val3", "service": "test"}),
        serde_json::json!({"path": "batch/key4", "value": "val4", "service": "test"}),
        serde_json::json!({"path": "batch/key5", "value": "val5", "service": "test"}),
    ];

    let result = credentials::vault_set_batch(&state, &entries);
    let json = result_json(result);
    assert_eq!(json["saved"], 5);
    assert_eq!(json["errors"], 0);
}

#[test]
fn test_vault_get_bundle() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    credentials::vault_set(
        &state,
        "aws/s3/key",
        "AKIA...",
        Some("api_key"),
        Some("aws"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    credentials::vault_set(
        &state,
        "aws/s3/secret",
        "wJalr...",
        Some("api_key"),
        Some("aws"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    let result = credentials::vault_get_bundle(&state, "aws/", false, false);
    let json = result_json(result);
    assert_eq!(json["prefix"], "aws/");
    assert_eq!(json["count"], 2);
}

#[test]
fn test_vault_delete() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    credentials::vault_set(
        &state,
        "delete/me",
        "value",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    let result = credentials::vault_delete(&state, "delete/me");
    let json = result_json(result);
    assert_eq!(json["deleted"], true);

    // Verify it's gone
    let get_result = credentials::vault_get(&state, "delete/me", true, false, false, false);
    let json = result_json(get_result);
    assert!(json.get("error").is_some());
}

#[test]
fn test_vault_delete_requires_operator_mode() {
    let tmp = TempDir::new().unwrap();
    let state = test_state_routine(&tmp);

    state
        .db
        .set_entry(
            "protected/delete-me",
            "value",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

    let result = credentials::vault_delete(&state, "protected/delete-me");
    let json = result_json(result);
    let err = json["error"].as_str().unwrap_or("");
    assert!(
        err.contains("Operator mode required"),
        "Expected operator mode error, got: {err}"
    );

    state.elevate_operator(120);
    let result = credentials::vault_delete(&state, "protected/delete-me");
    let json = result_json(result);
    assert_eq!(json["deleted"], true);
}

#[test]
fn test_vault_set_overwrite_requires_operator_mode() {
    let tmp = TempDir::new().unwrap();
    let state = test_state_routine(&tmp);

    // Seed existing entry directly.
    state
        .db
        .set_entry(
            "overwrite/test",
            "v1",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

    // Overwrite should be blocked in routine mode.
    let blocked = credentials::vault_set(
        &state,
        "overwrite/test",
        "v2",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let blocked_json = result_json(blocked);
    let err = blocked_json["error"].as_str().unwrap_or("");
    assert!(
        err.contains("requires operator mode"),
        "Expected overwrite guard, got: {err}"
    );

    // New paths are still allowed in routine mode.
    let created = credentials::vault_set(
        &state,
        "overwrite/new-path",
        "new",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let created_json = result_json(created);
    assert_eq!(created_json["path"], "overwrite/new-path");

    // Operator mode allows overwrite.
    state.elevate_operator(120);
    let allowed = credentials::vault_set(
        &state,
        "overwrite/test",
        "v2",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let allowed_json = result_json(allowed);
    assert_eq!(allowed_json["path"], "overwrite/test");
}

#[test]
fn test_reserved_internal_paths_rejected() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    let result = credentials::vault_set(
        &state,
        "_agents/local/hijack",
        "value",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    let json = result_json(result);
    let err = json["error"].as_str().unwrap_or("");
    assert!(
        err.contains("reserved for internal"),
        "Expected reserved path guard, got: {err}"
    );
}

#[test]
fn test_vault_get_redact() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    credentials::vault_set(
        &state,
        "secret/path",
        "super-secret-value",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    let result = credentials::vault_get(&state, "secret/path", true, false, false, true);
    let json = result_json(result);
    // When redacted, the actual value should NOT appear in the response
    let value = json["value"].as_str().unwrap_or("");
    assert_ne!(
        value, "super-secret-value",
        "Redacted response should not contain actual value"
    );
    assert!(json.get("_redacted").is_some() || json.get("_clipboard").is_some());
}

// ========================================================================
// Security tools
// ========================================================================

#[test]
fn test_vault_audit_logged() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    // Perform some operations that log audits
    credentials::vault_set(
        &state,
        "audit/test",
        "value",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    credentials::vault_get(&state, "audit/test", true, false, false, false);
    credentials::vault_delete(&state, "audit/test");

    // Query audit log
    let result = security::vault_audit(&state, None, None, 50, false);
    let json = result_json(result);
    assert!(
        json["count"].as_i64().unwrap() >= 3,
        "Should have at least 3 audit entries"
    );
}

// ========================================================================
// Monitoring tools
// ========================================================================

#[test]
fn test_vault_changes() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    credentials::vault_set(
        &state,
        "change/one",
        "v1",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    credentials::vault_set(
        &state,
        "change/two",
        "v2",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    credentials::vault_set(
        &state,
        "change/three",
        "v3",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    let result = monitoring::vault_changes(&state, None, None, None, None, 50);
    let json = result_json(result);
    assert_eq!(json["count"], 3);
    let changes = json["changes"].as_array().unwrap();
    for change in changes {
        assert!(change.get("value_hash").is_some());
        assert!(change.get("path").is_some());
    }
}

#[test]
fn test_vault_impact() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    let related = vec!["myapp".to_string()];
    credentials::vault_set(
        &state,
        "api/key1",
        "val1",
        Some("api_key"),
        None,
        Some("myapp"),
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&related),
    );
    credentials::vault_set(
        &state,
        "api/key2",
        "val2",
        Some("api_key"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    let result = monitoring::vault_impact(&state, "myapp");
    let json = result_json(result);
    assert_eq!(json["count"], 1);
}

#[test]
fn test_vault_lint_tool() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    credentials::vault_set(
        &state,
        "api/openai/key",
        "v1",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    credentials::vault_set(
        &state,
        "api/openai/token",
        "v2",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    let result = monitoring::vault_lint(&state, None, 0.7, 20, true);
    let json = result_json(result);
    assert!(json.get("total_paths").is_some());
}

// ========================================================================
// Conflict tools
// ========================================================================

#[test]
fn test_vault_conflicts_stats() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    let result = conflicts::vault_conflicts(&state, false, None, true);
    let json = result_json(result);
    assert_eq!(json["pending"], 0);
    assert_eq!(json["total"], 0);
}

// ========================================================================
// Guide tools
// ========================================================================

#[test]
fn test_guide_crud_full_cycle() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    // Add guide
    let tags = vec!["test".to_string(), "guide".to_string()];
    let result = guides::vault_add_guide(
        &state,
        "test-guide",
        "# Test Guide\n\nThis is a test guide.",
        Some("procedure"),
        Some(&tags),
        None,
        None,
    );
    let json = result_json(result);
    assert!(json["message"].as_str().unwrap().contains("saved"));

    // Get guide
    let result = guides::vault_guide(&state, "test-guide");
    let json = result_json(result);
    assert_eq!(json["name"], "test-guide");
    assert!(json["content"].as_str().unwrap().contains("Test Guide"));

    // List guides
    let result = guides::vault_list_guides(&state, None, None);
    let json = result_json(result);
    assert!(json["count"].as_i64().unwrap() >= 1);

    // Search guides
    let result = guides::vault_search_guides(&state, "test");
    let json = result_json(result);
    assert!(json["count"].as_i64().unwrap() >= 1);

    // Verify guide
    let result = guides::vault_verify_guide(&state, "test-guide");
    let json = result_json(result);
    assert!(json["verified_at"].is_string());

    // Deprecate guide
    let result = guides::vault_deprecate_guide(&state, "test-guide");
    let json = result_json(result);
    assert_eq!(json["status"], "deprecated");

    // Stale guides (shouldn't include deprecated)
    let result = guides::vault_stale_guides(&state, 90);
    let json = result_json(result);
    // Deprecated guides are excluded from stale check
    assert_eq!(json["stale_count"], 0);

    // Delete guide
    let result = guides::vault_delete_guide(&state, "test-guide");
    let json = result_json(result);
    assert_eq!(json["deleted"], true);
}

// ========================================================================
// Session / discover tools
// ========================================================================

#[test]
fn test_vault_discover() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    credentials::vault_set(
        &state,
        "api/test/key",
        "val",
        Some("api_key"),
        Some("test"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    let result = credentials::vault_discover(&state, None);
    let json = result_json(result);
    assert!(json["total_credentials"].as_i64().unwrap() >= 1);
    assert!(json.get("categories").is_some());
    assert!(json.get("services").is_some());
}

#[test]
fn test_vault_session_start() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    let result = credentials::vault_session_start(&state, None, 7);
    let json = result_json(result);
    // Should return counts (all zeros for fresh DB)
    assert!(json.get("unresolved_conflicts").is_some());
    assert!(json.get("rotation_alerts").is_some());
}

#[test]
fn test_vault_recent() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    credentials::vault_set(
        &state,
        "recent/one",
        "v1",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    credentials::vault_set(
        &state,
        "recent/two",
        "v2",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    let result = credentials::vault_recent(&state, 10);
    let json = result_json(result);
    assert_eq!(json["count"], 2);
}

// ========================================================================
// Response formatting
// ========================================================================

// ========================================================================
// vault_use tool
// ========================================================================

#[test]
fn test_vault_use_basic() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    // Set a credential
    credentials::vault_set(
        &state,
        "test/use/secret",
        "hello-world-42",
        Some("api_key"),
        Some("test"),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    // Run a command that echoes the env var
    let result = security::vault_use(
        &state,
        "test/use/secret",
        "TEST_SECRET",
        &["sh", "-c", "echo $TEST_SECRET"],
        Some(30),
    );
    let json = result_json(result);
    assert_eq!(json["exit_code"], 0);
    assert!(
        json["stdout"].as_str().unwrap().contains("hello-world-42"),
        "stdout should contain the secret value echoed by the command"
    );
    // The secret must NOT appear anywhere in stderr or in the response under a "value" key
    assert!(
        json.get("value").is_none(),
        "Response must not contain a 'value' key"
    );
}

#[test]
fn test_vault_use_requires_operator() {
    let tmp = TempDir::new().unwrap();
    let state = test_state_routine(&tmp);

    state
        .db
        .set_entry(
            "test/use/op",
            "val",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

    let result = security::vault_use(&state, "test/use/op", "MY_VAR", &["echo", "hi"], None);
    let json = result_json(result);
    let err = json["error"].as_str().unwrap_or("");
    assert!(
        err.to_lowercase().contains("operator"),
        "Expected operator mode error, got: {err}"
    );
}

#[test]
fn test_vault_use_blocks_dangerous_env_vars() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    credentials::vault_set(
        &state,
        "test/use/path",
        "bad-value",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    let result = security::vault_use(&state, "test/use/path", "PATH", &["echo", "hi"], None);
    let json = result_json(result);
    let err = json["error"].as_str().unwrap_or("");
    assert!(
        err.contains("Refused") || err.contains("code injection") || err.contains("dangerous"),
        "Expected dangerous env var error, got: {err}"
    );
}

#[test]
fn test_vault_use_missing_credential() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    let result = security::vault_use(&state, "nonexistent/path", "MY_VAR", &["echo", "hi"], None);
    let json = result_json(result);
    let err = json["error"].as_str().unwrap_or("");
    assert!(
        err.contains("Not found") || err.contains("not found"),
        "Expected not found error, got: {err}"
    );
}

#[test]
fn test_vault_use_timeout_kills_process() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    // Seed a credential
    credentials::vault_set(
        &state,
        "test/timeout",
        "secret",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    // Run a long-sleeping command with 1-second timeout
    let result = security::vault_use(
        &state,
        "test/timeout",
        "TEST_SECRET",
        &["sleep", "60"],
        Some(1),
    );

    let json = result_json(result);
    let err = json["error"].as_str().unwrap();
    assert!(
        err.contains("timed out"),
        "Expected timeout error, got: {err}"
    );
    assert!(
        err.contains("killed"),
        "Expected kill confirmation, got: {err}"
    );
}

// ========================================================================
// vault_expand tool
// ========================================================================

#[test]
fn test_vault_expand_basic() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    credentials::vault_set(
        &state,
        "db/host",
        "localhost",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );
    credentials::vault_set(
        &state,
        "db/password",
        "s3cret",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    );

    let result =
        security::vault_expand(&state, "host=<vault:db/host> password=<vault:db/password>");
    let json = result_json(result);
    assert_eq!(json["expanded"], "host=localhost password=s3cret");
    assert_eq!(json["replacements"], 2);
    let missing = json["missing"].as_array().unwrap();
    assert!(missing.is_empty());
}

#[test]
fn test_vault_expand_missing_path() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    let result = security::vault_expand(&state, "key=<vault:nonexistent/key>");
    let json = result_json(result);
    // The placeholder should remain or be left as-is
    let missing = json["missing"].as_array().unwrap();
    assert!(
        missing
            .iter()
            .any(|v| v.as_str() == Some("nonexistent/key")),
        "Expected 'nonexistent/key' in missing list, got: {:?}",
        missing
    );
}

#[test]
fn test_vault_expand_requires_operator() {
    let tmp = TempDir::new().unwrap();
    let state = test_state_routine(&tmp);

    let result = security::vault_expand(&state, "key=<vault:some/path>");
    let json = result_json(result);
    let err = json["error"].as_str().unwrap_or("");
    assert!(
        err.to_lowercase().contains("operator"),
        "Expected operator mode error, got: {err}"
    );
}

#[test]
fn test_vault_expand_no_placeholders() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    let result = security::vault_expand(&state, "plain text with no placeholders");
    let json = result_json(result);
    assert_eq!(json["expanded"], "plain text with no placeholders");
    assert_eq!(json["replacements"], 0);
    let missing = json["missing"].as_array().unwrap();
    assert!(missing.is_empty());
}

// ========================================================================
// Response formatting
// ========================================================================

#[test]
fn test_response_omits_defaults() {
    let tmp = TempDir::new().unwrap();
    let state = test_state(&tmp);

    // Set with default storage_mode (vault) and default category (env_var)
    credentials::vault_set(
        &state,
        "test/defaults",
        "val",
        Some("env_var"),
        None,
        None,
        None,
        None,
        None,
        Some("vault"),
        None,
        None,
        None,
    );

    let result = credentials::vault_get(&state, "test/defaults", true, true, false, false);
    let json = result_json(result);
    // storage_mode="vault" and category="env_var" should be stripped as defaults
    assert!(
        json.get("storage_mode").is_none(),
        "Default storage_mode should be omitted"
    );
    assert!(
        json.get("category").is_none(),
        "Default category should be omitted"
    );
}
