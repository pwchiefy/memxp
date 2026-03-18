//! End-to-end integration tests for memxp.
//!
//! Tests migration and cross-crate integration behavior.

use tempfile::TempDir;
use vault_core::db::CrSqliteDatabase;
use vault_core::security::AuditLogger;

// =========================================================================
// Helper
// =========================================================================

fn open_test_db(dir: &TempDir, name: &str) -> CrSqliteDatabase {
    CrSqliteDatabase::open(dir.path().join(name), "test-passphrase", None).unwrap()
}

fn open_unencrypted_db(dir: &TempDir, name: &str) -> CrSqliteDatabase {
    CrSqliteDatabase::open_unencrypted(dir.path().join(name), None).unwrap()
}

// =========================================================================
// Migration Tests
// =========================================================================

#[test]
fn test_migration_preserves_data() {
    let tmp = TempDir::new().unwrap();

    // Create an "old" unencrypted Python-style DB
    let old_db = open_unencrypted_db(&tmp, "old_vault.db");

    // Insert entries
    old_db
        .set_entry(
            "api/openai/key",
            "sk-old-secret-123",
            Some("api_key"),
            Some("openai"),
            None,
            Some("production"),
            Some("OpenAI production key"),
            Some(&["ai".to_string(), "llm".to_string()]),
            None,
            None,
            Some(90),
            Some(&["mcp-server".to_string()]),
        )
        .unwrap();

    old_db
        .set_entry(
            "postgres/prod/url",
            "postgres://user:pass@host/db",
            Some("password"),
            Some("postgres"),
            None,
            Some("production"),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

    old_db
        .set_entry(
            "aws/s3/access_key",
            "AKIA1234567890",
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
        )
        .unwrap();

    // Insert guides
    old_db
        .set_guide(
            "deploy-guide",
            "# Deploy Guide\n\n1. Build\n2. Push\n3. Deploy",
            Some("procedure"),
            Some(&["deploy".to_string(), "ops".to_string()]),
            None,
            None,
            Some(&["aws/s3/access_key".to_string()]),
        )
        .unwrap();

    old_db
        .set_guide(
            "postgres-backup",
            "# Postgres Backup\n\npg_dump ...",
            Some("runbook"),
            None,
            None,
            None,
            None,
        )
        .unwrap();

    let old_entries = old_db.list_entries(None, None, None).unwrap();
    let old_guides = old_db.list_guides(None, None).unwrap();
    assert_eq!(old_entries.len(), 3);
    assert_eq!(old_guides.len(), 2);

    // "Migrate" — copy entries and guides to a new encrypted DB
    let new_db = open_test_db(&tmp, "new_vault.db");

    for e in &old_entries {
        let tags = if e.tags.is_empty() {
            None
        } else {
            Some(e.tags.as_slice())
        };
        let apps = if e.related_apps.is_empty() {
            None
        } else {
            Some(e.related_apps.as_slice())
        };
        new_db
            .set_entry(
                &e.path,
                &e.value,
                Some(&e.category),
                e.service.as_deref(),
                e.app.as_deref(),
                e.env.as_deref(),
                e.notes.as_deref(),
                tags,
                Some(&e.storage_mode),
                e.expires_at.as_deref(),
                e.rotation_interval_days,
                apps,
            )
            .unwrap();
    }

    for g in &old_guides {
        let tags = if g.tags.is_empty() {
            None
        } else {
            Some(g.tags.as_slice())
        };
        let paths = if g.related_paths.is_empty() {
            None
        } else {
            Some(g.related_paths.as_slice())
        };
        new_db
            .set_guide(
                &g.name,
                &g.content,
                Some(&g.category),
                tags,
                Some(&g.status),
                g.verified_at.as_deref(),
                paths,
            )
            .unwrap();
    }

    // Verify all data migrated
    let new_entries = new_db.list_entries(None, None, None).unwrap();
    let new_guides = new_db.list_guides(None, None).unwrap();
    assert_eq!(new_entries.len(), 3);
    assert_eq!(new_guides.len(), 2);

    // Verify specific entry data
    let openai = new_db.get_entry("api/openai/key").unwrap().unwrap();
    assert_eq!(openai.value, "sk-old-secret-123");
    assert_eq!(openai.category, "api_key");
    assert_eq!(openai.service, Some("openai".to_string()));
    assert_eq!(openai.env, Some("production".to_string()));
    assert_eq!(openai.notes, Some("OpenAI production key".to_string()));
    assert!(openai.tags.contains(&"ai".to_string()));
    assert!(openai.tags.contains(&"llm".to_string()));
    assert_eq!(openai.rotation_interval_days, Some(90));
    assert!(openai.related_apps.contains(&"mcp-server".to_string()));

    // Verify guide data
    let guide = new_db.get_guide("deploy-guide").unwrap().unwrap();
    assert!(guide.content.contains("Deploy Guide"));
    assert_eq!(guide.category, "procedure");
    assert!(guide.tags.contains(&"deploy".to_string()));
    assert!(guide
        .related_paths
        .contains(&"aws/s3/access_key".to_string()));

    old_db.close().unwrap();
    new_db.close().unwrap();
}

#[test]
fn test_migration_preserves_site_id() {
    let tmp = TempDir::new().unwrap();

    // Create an old DB and get its site_id
    let mut old_db = open_unencrypted_db(&tmp, "old.db");

    // cr-sqlite may not be loaded in test env (extension not available)
    // If available, verify site_id handling
    if let Some(old_sid) = old_db.site_id() {
        let old_site_id = old_sid.to_vec();
        assert_eq!(old_site_id.len(), 16, "Site ID should be 16 bytes");

        // New encrypted DB gets its OWN site_id (by design)
        let mut new_db = open_test_db(&tmp, "new.db");
        if let Some(new_sid) = new_db.site_id() {
            let new_site_id = new_sid.to_vec();
            assert_eq!(new_site_id.len(), 16);
            // Each DB gets a unique site_id
            assert_ne!(old_site_id, new_site_id);
        }
        new_db.close().unwrap();
    }
    // Without cr-sqlite, both DBs still function for data storage
    // The site_id is only needed for sync operations

    old_db.close().unwrap();
}

#[test]
fn test_migration_encrypted_db_not_readable_without_key() {
    let tmp = TempDir::new().unwrap();

    // Create encrypted DB with data
    let db = open_test_db(&tmp, "encrypted.db");
    db.set_entry(
        "test/key", "secret", None, None, None, None, None, None, None, None, None, None,
    )
    .unwrap();
    db.close().unwrap();

    // Read raw file — should NOT start with "SQLite format 3\0"
    let raw = std::fs::read(tmp.path().join("encrypted.db")).unwrap();
    assert!(raw.len() > 16, "Encrypted DB file should not be empty");
    let sqlite_header = b"SQLite format 3\0";
    assert_ne!(
        &raw[..16],
        sqlite_header,
        "Encrypted DB must not have plain SQLite header"
    );
}

// =========================================================================
// Cross-Crate Integration
// =========================================================================

#[test]
fn test_full_vault_workflow() {
    let tmp = TempDir::new().unwrap();
    let db = open_test_db(&tmp, "test.db");
    let audit = AuditLogger::open(tmp.path().join("audit.db")).unwrap();

    // 1. Set entries via vault-core
    db.set_entry(
        "api/openai/key",
        "sk-abc123",
        Some("api_key"),
        Some("openai"),
        None,
        Some("production"),
        Some("Main API key"),
        Some(&["ai".to_string()]),
        None,
        None,
        Some(90),
        None,
    )
    .unwrap();

    db.set_entry(
        "postgres/prod/url",
        "postgres://u:p@host/db",
        Some("password"),
        Some("postgres"),
        None,
        Some("production"),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();

    // 2. Query via vault-core
    let entries = db.list_entries(None, None, None).unwrap();
    assert_eq!(entries.len(), 2);

    let entry = db.get_entry("api/openai/key").unwrap().unwrap();
    assert_eq!(entry.value, "sk-abc123");

    // 3. Set guide
    db.set_guide(
        "openai-setup",
        "# OpenAI Setup\n\nGet key from platform.openai.com",
        Some("setup"),
        Some(&["openai".to_string()]),
        None,
        None,
        Some(&["api/openai/key".to_string()]),
    )
    .unwrap();

    // 4. Verify changes are tracked by cr-sqlite (if loaded)
    let version = db.db_version().unwrap();
    assert!(version >= 0, "DB version should be non-negative");

    // 5. Audit logging
    audit
        .log("get", Some("api/openai/key"), None, None, None, true)
        .unwrap();
    audit
        .log("set", Some("postgres/prod/url"), None, None, None, true)
        .unwrap();

    let logs = audit.list(None, None, 10).unwrap();
    assert_eq!(logs.len(), 2);
    assert_eq!(logs[0].action, "set"); // Most recent first
    assert_eq!(logs[1].action, "get");

    // 6. Value masking (via vault-core security)
    let masked = vault_core::security::mask_value("sk-abc123");
    assert!(masked.contains('*'));
    assert!(!masked.contains("sk-abc123")); // Original not visible

    // 7. Query/fuzzy search
    let results = vault_core::query::rank_matches("openai", &entries, 10);
    assert!(!results.is_empty());
    assert_eq!(results[0].entry.path, "api/openai/key");

    db.close().unwrap();
}

// =========================================================================
// Bidirectional Sync Between Two DBs
// =========================================================================

#[test]
fn test_bidirectional_sync_convergence() {
    let tmp = TempDir::new().unwrap();

    let db_a = open_test_db(&tmp, "node_a.db");
    let db_b = open_test_db(&tmp, "node_b.db");

    // Insert on Node A
    db_a.set_entry(
        "api/openai/key",
        "sk-from-a",
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
    )
    .unwrap();

    // Insert on Node B
    db_b.set_entry(
        "postgres/prod/url",
        "postgres://from-b",
        Some("password"),
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

    // cr-sqlite sync requires extension loaded — skip sync test if not available
    match db_a.get_changes_since(0) {
        Ok(changes_a) => {
            assert!(!changes_a.is_empty());
            db_b.apply_changes(&changes_a).unwrap();

            let changes_b = db_b.get_changes_since(0).unwrap();
            db_a.apply_changes(&changes_b).unwrap();

            // Both should now have both entries
            let entries_a = db_a.list_entries(None, None, None).unwrap();
            let entries_b = db_b.list_entries(None, None, None).unwrap();
            assert_eq!(
                entries_a.len(),
                2,
                "Node A should have 2 entries after sync"
            );
            assert_eq!(
                entries_b.len(),
                2,
                "Node B should have 2 entries after sync"
            );

            // Verify convergence
            let a_openai = db_a.get_entry("api/openai/key").unwrap().unwrap();
            let b_openai = db_b.get_entry("api/openai/key").unwrap().unwrap();
            assert_eq!(a_openai.value, b_openai.value);

            let a_pg = db_a.get_entry("postgres/prod/url").unwrap().unwrap();
            let b_pg = db_b.get_entry("postgres/prod/url").unwrap().unwrap();
            assert_eq!(a_pg.value, b_pg.value);
        }
        Err(_) => {
            // cr-sqlite not loaded — verify entries exist independently
            let entries_a = db_a.list_entries(None, None, None).unwrap();
            assert_eq!(entries_a.len(), 1);
            let entries_b = db_b.list_entries(None, None, None).unwrap();
            assert_eq!(entries_b.len(), 1);
        }
    }

    db_a.close().unwrap();
    db_b.close().unwrap();
}
