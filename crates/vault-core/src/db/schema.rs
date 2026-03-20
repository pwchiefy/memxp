//! Schema initialization and migration.

use chrono::Utc;
use rusqlite::params;
use tracing::warn;

use super::{
    CrSqliteDatabase, DbResult, ACTIVE_SYNC_TABLES, AGENT_TASKS_ARCHIVE_TABLE,
    MIGRATION_AGENT_TASKS_ARCHIVE_COUNT_KEY, MIGRATION_AGENT_TASKS_ARCHIVE_KEY,
    MIGRATION_AGENT_TASKS_ARCHIVE_NOTICE_KEY,
};

impl CrSqliteDatabase {
    // =========================================================================
    // Schema Initialization
    // =========================================================================

    pub(crate) fn init_schema(&mut self) -> DbResult<()> {
        // Main credentials table
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS vault_entries (
                path TEXT NOT NULL PRIMARY KEY,
                value TEXT NOT NULL DEFAULT '',
                category TEXT DEFAULT 'env_var',
                service TEXT,
                app TEXT,
                env TEXT,
                notes TEXT,
                tags TEXT,
                storage_mode TEXT DEFAULT 'vault',
                expires_at TEXT,
                rotation_interval_days INTEGER,
                related_apps TEXT,
                created_at TEXT,
                updated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS vault_guides (
                name TEXT NOT NULL PRIMARY KEY,
                content TEXT NOT NULL DEFAULT '',
                category TEXT DEFAULT 'procedure',
                tags TEXT,
                version INTEGER DEFAULT 1,
                status TEXT DEFAULT 'active',
                verified_at TEXT,
                related_paths TEXT,
                created_at TEXT,
                updated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT NOT NULL PRIMARY KEY,
                value TEXT NOT NULL DEFAULT '',
                updated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS file_transfers (
                id TEXT PRIMARY KEY NOT NULL,
                filename TEXT NOT NULL DEFAULT '',
                from_machine TEXT NOT NULL DEFAULT '',
                to_machine TEXT NOT NULL DEFAULT '*',
                size INTEGER NOT NULL DEFAULT 0,
                checksum TEXT NOT NULL DEFAULT '',
                chunk_count INTEGER NOT NULL DEFAULT 0,
                chunk_size INTEGER NOT NULL DEFAULT 262144,
                status TEXT NOT NULL DEFAULT 'pending',
                description TEXT DEFAULT '',
                created_at TEXT DEFAULT '',
                completed_at TEXT DEFAULT NULL,
                compressed INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS file_chunks (
                id TEXT PRIMARY KEY NOT NULL,
                file_id TEXT NOT NULL DEFAULT '',
                chunk_index INTEGER NOT NULL DEFAULT 0,
                data TEXT NOT NULL DEFAULT '',
                checksum TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS sync_conflicts (
                id TEXT PRIMARY KEY NOT NULL,
                path TEXT NOT NULL DEFAULT '',
                local_value TEXT,
                remote_value TEXT,
                local_updated_at TEXT,
                remote_updated_at TEXT,
                remote_site_id TEXT,
                resolution TEXT,
                resolved_value TEXT,
                resolved_at TEXT,
                resolved_by TEXT,
                created_at TEXT DEFAULT '',
                notes TEXT,
                local_site_id TEXT,
                remote_db_version INTEGER,
                local_db_version INTEGER,
                previous_value_hash TEXT,
                related_apps TEXT DEFAULT '',
                audit_context TEXT
            );

            CREATE TABLE IF NOT EXISTS conflict_settings (
                path TEXT PRIMARY KEY NOT NULL,
                conflict_mode TEXT NOT NULL DEFAULT 'auto',
                created_at TEXT DEFAULT '',
                updated_at TEXT DEFAULT ''
            );",
        )?;

        // Auxiliary tables (NOT replicated)
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sync_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                peer_id TEXT,
                direction TEXT,
                protocol_version INTEGER,
                schema_version INTEGER,
                change_count INTEGER,
                payload_bytes INTEGER,
                duration_ms INTEGER,
                result TEXT,
                error_code TEXT,
                request_id TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_sync_audit_ts ON sync_audit(ts);

            CREATE TABLE IF NOT EXISTS sync_peers (
                peer_site_id TEXT PRIMARY KEY,
                last_seen_version INTEGER,
                last_seen_at TEXT,
                last_known_addr TEXT,
                supported_tables TEXT,
                supported_features TEXT
            );

            CREATE TABLE IF NOT EXISTS sync_backlog (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_site_id TEXT NOT NULL,
                peer_addr TEXT,
                change_table TEXT NOT NULL,
                change_pk TEXT NOT NULL,
                change_cid TEXT NOT NULL,
                change_val BLOB,
                col_version INTEGER NOT NULL,
                db_version INTEGER NOT NULL,
                site_id BLOB NOT NULL,
                cl INTEGER,
                seq INTEGER,
                reason TEXT,
                created_at TEXT NOT NULL,
                UNIQUE(peer_site_id, change_table, change_pk, change_cid, db_version)
            );
            CREATE INDEX IF NOT EXISTS idx_sync_backlog_peer ON sync_backlog(peer_site_id);
            CREATE INDEX IF NOT EXISTS idx_sync_backlog_created ON sync_backlog(created_at);",
        )?;

        // Enable CRR replication on tables
        if self.cr_enabled {
            for table in &[
                "vault_entries",
                "vault_guides",
                "vault_meta",
                "file_transfers",
                "file_chunks",
                "sync_conflicts",
                "conflict_settings",
            ] {
                // Use query_row (not execute) because crsql_as_crr returns a result row
                match self
                    .conn
                    .query_row(
                        &format!("SELECT crsql_as_crr('{table}')"),
                        [],
                        |_row| Ok(()),
                    ) {
                    Ok(()) => {}
                    Err(e) => {
                        let msg = e.to_string().to_lowercase();
                        // Ignore "already a crr" and "not null" schema issues
                        // (happens when opening existing Python DBs)
                        if !msg.contains("already") && !msg.contains("not null") {
                            warn!("Could not enable CRR for {table}: {e}");
                        }
                    }
                }
            }
        }

        self.migrate_schema()?;
        self.conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        Ok(())
    }

    // =========================================================================
    // Schema Version Management
    // =========================================================================

    fn get_schema_version(&self) -> i32 {
        self.conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'schema_version'",
                [],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    fn set_schema_version(&self, version: i32) -> DbResult<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO vault_meta (key, value, updated_at)
             VALUES ('schema_version', ?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![version.to_string(), now],
        )?;
        Ok(())
    }

    /// Get the schema version from vault_meta.
    pub fn schema_version(&self) -> i32 {
        self.get_schema_version()
    }

    // =========================================================================
    // Column Helpers
    // =========================================================================

    fn column_exists(&self, table: &str, column: &str) -> bool {
        let sql = format!("PRAGMA table_info({table})");
        let mut stmt = match self.conn.prepare(&sql) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let names: Vec<String> = match stmt.query_map([], |row| row.get::<_, String>(1)) {
            Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
            Err(_) => return false,
        };
        names.iter().any(|n| n == column)
    }

    fn ensure_column(&self, table: &str, column: &str, definition: &str) {
        if !self.column_exists(table, column) {
            if self.cr_enabled {
                let _ = self.conn.query_row(
                    &format!("SELECT crsql_begin_alter('{table}')"),
                    [],
                    |_| Ok(()),
                );
            }
            let sql = format!("ALTER TABLE {table} ADD COLUMN {definition}");
            let _ = self.conn.execute(&sql, []);
            if self.cr_enabled {
                let _ = self.conn.query_row(
                    &format!("SELECT crsql_commit_alter('{table}')"),
                    [],
                    |_| Ok(()),
                );
            }
        }
    }

    // =========================================================================
    // Migrations
    // =========================================================================

    fn migrate_schema(&self) -> DbResult<()> {
        let mut current = self.get_schema_version();

        if current < 1 {
            self.set_schema_version(1)?;
            current = 1;
        }

        if current < 2 {
            self.ensure_column("vault_entries", "expires_at", "expires_at TEXT");
            self.ensure_column(
                "vault_entries",
                "rotation_interval_days",
                "rotation_interval_days INTEGER",
            );
            self.set_schema_version(2)?;
            current = 2;
        }

        if current < 3 {
            self.ensure_column("vault_entries", "related_apps", "related_apps TEXT");
            self.set_schema_version(3)?;
            current = 3;
        }

        if current < 4 {
            self.ensure_column("vault_guides", "status", "status TEXT DEFAULT 'active'");
            self.ensure_column("vault_guides", "verified_at", "verified_at TEXT");
            self.ensure_column("vault_guides", "related_paths", "related_paths TEXT");
            self.set_schema_version(4)?;
            current = 4;
        }

        if current < 5 {
            self.ensure_column("sync_peers", "supported_tables", "supported_tables TEXT");
            self.ensure_column(
                "sync_peers",
                "supported_features",
                "supported_features TEXT",
            );
            self.set_schema_version(5)?;
            current = 5;
        }

        if current < 6 {
            // Add read_at/completed_at to agent_tasks only if the legacy table exists
            if self.table_exists("agent_tasks") {
                self.ensure_column("agent_tasks", "read_at", "read_at TEXT DEFAULT NULL");
                self.ensure_column(
                    "agent_tasks",
                    "completed_at",
                    "completed_at TEXT DEFAULT NULL",
                );
            }
            // file_transfers and file_chunks tables are created in init_schema
            // (CREATE TABLE IF NOT EXISTS handles both fresh and existing DBs)
            self.set_schema_version(6)?;
            current = 6;
        }

        if current < 7 {
            // Reserved for future migration ordering.
            self.set_schema_version(7)?;
            current = 7;
        }

        if current < 8 {
            // Reserved for future migration ordering.
            self.set_schema_version(8)?;
            current = 8;
        }

        if current < 9 {
            // Migrate active messaging/task rows into archive table for compatibility.
            let _ = self.migrate_agent_tasks_to_archive()?;
            self.set_schema_version(9)?;
            current = 9;
        }

        if current < 10 {
            // Repair CRR metadata for tables that had columns added via ALTER TABLE
            // without crsql_begin_alter/crsql_commit_alter. This caused stale triggers
            // (e.g. "expected 21 values, got 15" on UPDATE for vault_guides).
            if self.cr_enabled {
                for table in &ACTIVE_SYNC_TABLES {
                    let _ = self.conn.query_row(
                        &format!("SELECT crsql_begin_alter('{table}')"),
                        [],
                        |_| Ok(()),
                    );
                    let _ = self.conn.query_row(
                        &format!("SELECT crsql_commit_alter('{table}')"),
                        [],
                        |_| Ok(()),
                    );
                }
            }
            self.set_schema_version(10)?;
        }

        Ok(())
    }

    /// Migrate legacy `agent_tasks` rows into an archive table.
    ///
    /// The archive table is only created here (on-the-fly) when upgrading a DB
    /// that actually has the legacy `agent_tasks` table. Fresh installs never
    /// create either table.
    fn migrate_agent_tasks_to_archive(&self) -> DbResult<bool> {
        if self.has_agent_task_archive_migration() {
            return Ok(false);
        }

        // No legacy table → nothing to migrate.
        if !self.table_exists("agent_tasks") {
            self.set_meta(MIGRATION_AGENT_TASKS_ARCHIVE_KEY, "1")?;
            self.set_meta(MIGRATION_AGENT_TASKS_ARCHIVE_COUNT_KEY, "0")?;
            self.set_meta(MIGRATION_AGENT_TASKS_ARCHIVE_NOTICE_KEY, "0")?;
            return Ok(false);
        }

        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM agent_tasks", [], |row| row.get(0))
            .unwrap_or(0);

        if count > 0 {
            warn!(
                "Migrating {count} legacy agent_tasks rows into agent_tasks_archive for compatibility.",
            );
        }

        // Create the archive table on-the-fly (upgrade-only artifact).
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS agent_tasks_archive (
                id TEXT PRIMARY KEY NOT NULL,
                title TEXT NOT NULL DEFAULT '',
                description TEXT DEFAULT '',
                from_machine TEXT NOT NULL DEFAULT '',
                to_machine TEXT NOT NULL DEFAULT '*',
                status TEXT NOT NULL DEFAULT 'pending',
                priority INTEGER NOT NULL DEFAULT 2,
                tags TEXT DEFAULT '[]',
                result TEXT DEFAULT '',
                reply_to TEXT DEFAULT NULL,
                claimed_by TEXT DEFAULT NULL,
                created_at TEXT DEFAULT '',
                updated_at TEXT DEFAULT '',
                completed_at TEXT DEFAULT NULL,
                read_at TEXT DEFAULT NULL,
                migrated_at TEXT NOT NULL DEFAULT '',
                migration_version INTEGER NOT NULL DEFAULT 9
            )",
        )?;

        let insert_sql = format!(
            "INSERT OR IGNORE INTO {0} (
                id, title, description, from_machine, to_machine, status, priority,
                tags, result, reply_to, claimed_by, created_at, updated_at,
                completed_at, read_at, migrated_at, migration_version
            )
            SELECT id, title, description, from_machine, to_machine, status, priority,
                COALESCE(tags, '[]'), COALESCE(result, ''), reply_to, claimed_by,
                COALESCE(created_at, ''), COALESCE(updated_at, ''),
                completed_at, read_at, datetime('now'), 9
            FROM agent_tasks",
            AGENT_TASKS_ARCHIVE_TABLE
        );
        self.conn.execute(&insert_sql, [])?;

        self.set_meta(MIGRATION_AGENT_TASKS_ARCHIVE_KEY, "1")?;
        self.set_meta(MIGRATION_AGENT_TASKS_ARCHIVE_COUNT_KEY, &count.to_string())?;
        self.set_meta(
            MIGRATION_AGENT_TASKS_ARCHIVE_NOTICE_KEY,
            if count > 0 { "1" } else { "0" },
        )?;
        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use crate::db::CrSqliteDatabase;
    use tempfile::TempDir;

    fn test_db(tmp: &TempDir) -> CrSqliteDatabase {
        let path = tmp.path().join("test.db");
        CrSqliteDatabase::open(&path, "test-passphrase", None).unwrap()
    }

    #[test]
    fn test_schema_init_all_tables() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);

        let tables: Vec<String> = db
            .conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        // Core tables
        assert!(tables.contains(&"vault_entries".to_string()));
        assert!(tables.contains(&"vault_guides".to_string()));
        assert!(tables.contains(&"vault_meta".to_string()));
        assert!(tables.contains(&"sync_conflicts".to_string()));
        assert!(tables.contains(&"conflict_settings".to_string()));

        // Auxiliary tables
        assert!(tables.contains(&"sync_audit".to_string()));
        assert!(tables.contains(&"sync_peers".to_string()));
        assert!(tables.contains(&"sync_backlog".to_string()));
    }

    #[test]
    fn test_fresh_db_no_legacy_task_tables() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);

        // Fresh installs must NOT create agent_tasks or agent_tasks_archive
        assert!(
            !db.table_exists("agent_tasks"),
            "agent_tasks should not exist on fresh install"
        );
        assert!(
            !db.table_exists("agent_tasks_archive"),
            "agent_tasks_archive should not exist on fresh install"
        );
    }

    #[test]
    fn test_upgrade_migrates_agent_tasks_to_archive() {
        let tmp = TempDir::new().unwrap();
        let db_path = tmp.path().join("upgrade.db");

        // Phase 1: Create a DB, inject legacy agent_tasks, and roll back to pre-v9.
        {
            let db = CrSqliteDatabase::open(&db_path, "test-passphrase", None).unwrap();

            // Manually create legacy agent_tasks table (no longer in init_schema)
            db.conn
                .execute_batch(
                    "CREATE TABLE agent_tasks (
                        id TEXT PRIMARY KEY NOT NULL,
                        title TEXT NOT NULL DEFAULT '',
                        description TEXT DEFAULT '',
                        from_machine TEXT NOT NULL DEFAULT '',
                        to_machine TEXT NOT NULL DEFAULT '*',
                        status TEXT NOT NULL DEFAULT 'pending',
                        priority INTEGER NOT NULL DEFAULT 2,
                        tags TEXT DEFAULT '[]',
                        result TEXT DEFAULT '',
                        reply_to TEXT DEFAULT NULL,
                        claimed_by TEXT DEFAULT NULL,
                        created_at TEXT DEFAULT '',
                        updated_at TEXT DEFAULT '',
                        completed_at TEXT DEFAULT NULL,
                        read_at TEXT DEFAULT NULL
                    )",
                )
                .unwrap();

            // Insert 2 legacy rows
            db.conn
                .execute(
                    "INSERT INTO agent_tasks (id, title, from_machine, created_at, updated_at)
                     VALUES ('task-001', 'Legacy task 1', '100.1.1.1', '2025-01-01', '2025-01-01')",
                    [],
                )
                .unwrap();
            db.conn
                .execute(
                    "INSERT INTO agent_tasks (id, title, from_machine, created_at, updated_at)
                     VALUES ('task-002', 'Legacy task 2', '100.2.2.2', '2025-02-01', '2025-02-01')",
                    [],
                )
                .unwrap();

            // Roll back schema version to 8 (pre-migration) and clear migration flags
            db.conn
                .execute(
                    "UPDATE vault_meta SET value = '8' WHERE key = 'schema_version'",
                    [],
                )
                .unwrap();
            db.conn
                .execute(
                    "DELETE FROM vault_meta WHERE key IN (
                        'agent_tasks_archive_migrated',
                        'agent_tasks_archive_migrated_row_count',
                        'agent_tasks_archive_migration_notice'
                    )",
                    [],
                )
                .unwrap();

            // Drop agent_tasks_archive if it exists (clean slate for migration)
            db.conn
                .execute_batch("DROP TABLE IF EXISTS agent_tasks_archive")
                .unwrap();
        }

        // Phase 2: Reopen — migration should fire.
        {
            let db = CrSqliteDatabase::open(&db_path, "test-passphrase", None).unwrap();

            // agent_tasks_archive must now exist
            assert!(
                db.table_exists("agent_tasks_archive"),
                "archive table should be created during upgrade migration"
            );

            // Verify both rows were archived
            let count: i64 = db
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM agent_tasks_archive",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 2, "both legacy rows should be archived");

            // Verify migration metadata
            assert_eq!(db.agent_task_archive_row_count(), 2);
            assert!(db.has_agent_task_archive_migration());

            // Verify the notice was set for display
            let notice: String = db
                .conn
                .query_row(
                    "SELECT value FROM vault_meta WHERE key = 'agent_tasks_archive_migration_notice'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(notice, "1", "migration notice should be pending");

            // Verify specific row data survived
            let title: String = db
                .conn
                .query_row(
                    "SELECT title FROM agent_tasks_archive WHERE id = 'task-001'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(title, "Legacy task 1");
        }
    }

    #[test]
    fn test_schema_migration_v1_to_v5() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let ver = db.schema_version();
        assert_eq!(ver, crate::models::SCHEMA_VERSION);

        // Verify migration columns exist
        assert!(db.column_exists("vault_entries", "expires_at"));
        assert!(db.column_exists("vault_entries", "rotation_interval_days"));
        assert!(db.column_exists("vault_entries", "related_apps"));
        assert!(db.column_exists("vault_guides", "status"));
        assert!(db.column_exists("vault_guides", "verified_at"));
        assert!(db.column_exists("vault_guides", "related_paths"));
        assert!(db.column_exists("sync_peers", "supported_tables"));
    }
}
