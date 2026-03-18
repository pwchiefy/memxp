//! Integration tests for vault-cli.
//!
//! Tests exercise CLI commands by calling the underlying functions directly
//! with a temp database, not by spawning subprocesses.

use tempfile::TempDir;
use vault_core::config;
use vault_core::db::CrSqliteDatabase;

/// Open a test database in a temp directory.
fn test_db(tmp: &TempDir) -> CrSqliteDatabase {
    let db_path = tmp.path().join("test.db");
    CrSqliteDatabase::open(&db_path, "test-passphrase", None).unwrap()
}

#[test]
fn test_cli_init_creates_db() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("test.db");

    // DB should not exist yet
    assert!(!db_path.exists());

    // Create DB
    let db = CrSqliteDatabase::open(&db_path, "test-passphrase", None).unwrap();
    assert!(db_path.exists());
    assert!(db.schema_version() > 0);
    // cr_enabled() depends on cr-sqlite extension being available
    db.close().unwrap();
}

#[test]
fn test_cli_set_get() {
    let tmp = TempDir::new().unwrap();
    let db = test_db(&tmp);

    // Set
    let entry = db
        .set_entry(
            "api/test/key",
            "secret-value-123",
            Some("api_key"),
            Some("test"),
            None,
            None,
            Some("test notes"),
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
    assert_eq!(entry.path, "api/test/key");
    assert_eq!(entry.value, "secret-value-123");
    assert_eq!(entry.category, "api_key");

    // Get
    let retrieved = db.get_entry("api/test/key").unwrap().unwrap();
    assert_eq!(retrieved.value, "secret-value-123");
    assert_eq!(retrieved.category, "api_key");
    assert_eq!(retrieved.service.as_deref(), Some("test"));
    assert_eq!(retrieved.notes.as_deref(), Some("test notes"));
}

#[test]
fn test_cli_list_masked() {
    let tmp = TempDir::new().unwrap();
    let db = test_db(&tmp);

    db.set_entry(
        "api/a/key",
        "secret-abc-123",
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
    db.set_entry(
        "api/b/key",
        "another-secret",
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

    let entries = db.list_entries(None, None, None).unwrap();
    assert_eq!(entries.len(), 2);

    // Values should be maskable
    for e in &entries {
        let masked = vault_core::security::mask_value(&e.value);
        assert!(masked.contains('*'));
    }
}

#[test]
fn test_cli_search() {
    let tmp = TempDir::new().unwrap();
    let db = test_db(&tmp);

    db.set_entry(
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
    )
    .unwrap();
    db.set_entry(
        "api/github/token",
        "ghp-test",
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
    )
    .unwrap();
    db.set_entry(
        "db/postgres/password",
        "pg-pass",
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
    )
    .unwrap();

    let results = db.search_entries("openai", 10).unwrap();
    assert!(!results.is_empty());
    assert!(results.iter().any(|e| e.path.contains("openai")));
}

#[test]
fn test_cli_export_import() {
    let tmp = TempDir::new().unwrap();

    // Create DB with entries
    let db = test_db(&tmp);
    db.set_entry(
        "api/test/a",
        "val-a",
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
    )
    .unwrap();
    db.set_entry(
        "api/test/b",
        "val-b",
        Some("token"),
        Some("test"),
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
    db.set_guide(
        "test-guide",
        "# Test\nContent here",
        Some("procedure"),
        None,
        None,
        None,
        None,
    )
    .unwrap();

    let entries = db.list_entries(None, None, None).unwrap();
    let guides = db.list_guides(None, None).unwrap();

    // Export
    let version = db.db_version().unwrap();
    let export_data = serde_json::json!({
        "version": 1,
        "db_version": version,
        "entries": entries.iter().map(|e| {
            serde_json::json!({
                "path": e.path,
                "value": e.value,
                "category": e.category,
                "service": e.service,
            })
        }).collect::<Vec<_>>(),
        "guides": guides.iter().map(|g| {
            serde_json::json!({
                "name": g.name,
                "content": g.content,
                "category": g.category,
            })
        }).collect::<Vec<_>>(),
    });

    let export_path = tmp.path().join("export.json");
    let json = serde_json::to_string_pretty(&export_data).unwrap();
    std::fs::write(&export_path, &json).unwrap();

    // Create new DB and import
    let db2_path = tmp.path().join("test2.db");
    let db2 = CrSqliteDatabase::open(&db2_path, "test-passphrase", None).unwrap();

    // Import entries
    let data: serde_json::Value = serde_json::from_str(&json).unwrap();
    if let Some(entries) = data.get("entries").and_then(|v| v.as_array()) {
        for e in entries {
            let path = e.get("path").and_then(|v| v.as_str()).unwrap();
            let value = e.get("value").and_then(|v| v.as_str()).unwrap();
            db2.set_entry(
                path,
                value,
                e.get("category").and_then(|v| v.as_str()),
                e.get("service").and_then(|v| v.as_str()),
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
        }
    }
    if let Some(guides) = data.get("guides").and_then(|v| v.as_array()) {
        for g in guides {
            let name = g.get("name").and_then(|v| v.as_str()).unwrap();
            let content = g.get("content").and_then(|v| v.as_str()).unwrap();
            db2.set_guide(
                name,
                content,
                g.get("category").and_then(|v| v.as_str()),
                None,
                None,
                None,
                None,
            )
            .unwrap();
        }
    }

    // Verify
    let imported_entries = db2.list_entries(None, None, None).unwrap();
    assert_eq!(imported_entries.len(), 2);

    let imported_guides = db2.list_guides(None, None).unwrap();
    assert_eq!(imported_guides.len(), 1);

    let a = db2.get_entry("api/test/a").unwrap().unwrap();
    assert_eq!(a.value, "val-a");
}

#[test]
fn test_cli_daemon_pid_check() {
    // check_pid_file should return None when no daemon is running
    let pid = vault_sync::daemon::check_pid_file();
    // This might be None or Some if a real daemon is running; just verify it doesn't panic
    let _ = pid;
}

#[test]
fn test_cli_status() {
    let tmp = TempDir::new().unwrap();
    let db = test_db(&tmp);

    // Add some entries
    db.set_entry(
        "api/a/key",
        "val",
        Some("api_key"),
        Some("svc_a"),
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
    db.set_entry(
        "api/b/key",
        "val",
        Some("token"),
        Some("svc_b"),
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
    db.set_entry(
        "api/c/key",
        "val",
        Some("api_key"),
        Some("svc_a"),
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

    let entries = db.list_entries(None, None, None).unwrap();
    assert_eq!(entries.len(), 3);

    // Count by category
    let mut by_cat = std::collections::HashMap::new();
    for e in &entries {
        *by_cat.entry(e.category.clone()).or_insert(0u32) += 1;
    }
    assert_eq!(by_cat.get("api_key"), Some(&2));
    assert_eq!(by_cat.get("token"), Some(&1));

    // Count by service
    let mut by_svc = std::collections::HashMap::new();
    for e in &entries {
        if let Some(ref s) = e.service {
            *by_svc.entry(s.clone()).or_insert(0u32) += 1;
        }
    }
    assert_eq!(by_svc.get("svc_a"), Some(&2));
    assert_eq!(by_svc.get("svc_b"), Some(&1));
}

#[test]
fn test_cli_config_show() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("config.yaml");

    let cfg = config::VaultConfig::default();
    cfg.save(&config_path).unwrap();

    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(!content.is_empty());
    // Should contain expected YAML keys
    assert!(
        content.contains("database") || content.contains("sync") || content.contains("security")
    );
}

#[test]
fn test_cli_mcp_server_constructable() {
    // Verify that VaultMcpServer can be constructed (doesn't test full MCP transport)
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("mcp_test.db");
    let audit_path = tmp.path().join("audit.db");

    let db = CrSqliteDatabase::open(&db_path, "test-passphrase", None).unwrap();
    let audit = vault_core::security::AuditLogger::open(&audit_path).unwrap();

    let _server = vault_mcp::server::VaultMcpServer::new(db, audit);
    // If we get here without panic, the server is constructable
}
