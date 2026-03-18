//! CrSqlite-based database for P2P vault synchronization.
//!
//! Provides the core database with SQLCipher encryption and
//! cr-sqlite CRDT extension for conflict-free replication.

use chrono::Utc;
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, warn};

const ACTIVE_SYNC_TABLES: [&str; 8] = [
    "vault_entries",
    "vault_guides",
    "vault_meta",
    "file_transfers",
    "file_chunks",
    "sync_conflicts",
    "conflict_settings",
    "sync_backlog",
];

const AGENT_TASKS_ARCHIVE_TABLE: &str = "agent_tasks_archive";
const MIGRATION_AGENT_TASKS_ARCHIVE_KEY: &str = "agent_tasks_archive_migrated";
const MIGRATION_AGENT_TASKS_ARCHIVE_COUNT_KEY: &str = "agent_tasks_archive_migrated_row_count";
const MIGRATION_AGENT_TASKS_ARCHIVE_NOTICE_KEY: &str = "agent_tasks_archive_migration_notice";

use crate::models::{SyncChange, VaultEntry, VaultGuide};

#[derive(Debug, Error)]
pub enum DbError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("cr-sqlite not enabled")]
    CrSqliteNotEnabled,
    #[error("schema version mismatch: expected {expected}, got {actual}")]
    SchemaVersionMismatch { expected: i32, actual: i32 },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("database error: {0}")]
    Other(String),
}

pub type DbResult<T> = Result<T, DbError>;

/// SQLite database with SQLCipher encryption and cr-sqlite CRDT extension.
pub struct CrSqliteDatabase {
    pub conn: Connection,
    db_path: PathBuf,
    cr_enabled: bool,
    site_id: Option<Vec<u8>>,
}

impl CrSqliteDatabase {
    /// Open an encrypted database with optional cr-sqlite extension.
    ///
    /// # Arguments
    /// - `db_path`: Path to the SQLite database file
    /// - `passphrase`: SQLCipher encryption passphrase
    /// - `extension_path`: Optional path to cr-sqlite extension (.dylib/.so/.dll)
    pub fn open(
        db_path: impl AsRef<Path>,
        passphrase: &str,
        extension_path: Option<&Path>,
    ) -> DbResult<Self> {
        let db_path = db_path.as_ref().to_path_buf();

        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(&db_path)?;

        // Set restrictive permissions on the vault database (owner-only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(&db_path) {
                let mut perms = metadata.permissions();
                if perms.mode() & 0o077 != 0 {
                    perms.set_mode(0o600);
                    let _ = std::fs::set_permissions(&db_path, perms);
                }
            }
        }

        // Set SQLCipher encryption key
        conn.pragma_update(None, "key", passphrase)?;

        // Verify encryption is working by querying cipher_version
        let _cipher_ver: String = conn
            .pragma_query_value(None, "cipher_version", |row| row.get(0))
            .map_err(|e| DbError::Other(format!("SQLCipher not available: {e}")))?;
        debug!("SQLCipher version: {_cipher_ver}");

        // Load cr-sqlite extension if available
        let cr_enabled = if let Some(ext_path) = extension_path {
            if ext_path.exists() {
                match unsafe { conn.load_extension(ext_path, Some("sqlite3_crsqlite_init")) } {
                    Ok(()) => {
                        debug!("cr-sqlite extension loaded from {}", ext_path.display());
                        true
                    }
                    Err(e) => {
                        warn!("Could not load cr-sqlite: {e}");
                        false
                    }
                }
            } else {
                warn!("cr-sqlite extension not found at {}", ext_path.display());
                false
            }
        } else {
            false
        };

        let mut db = Self {
            conn,
            db_path,
            cr_enabled,
            site_id: None,
        };

        db.init_schema()?;

        Ok(db)
    }

    /// Open a database without encryption (for testing or migration).
    pub fn open_unencrypted(
        db_path: impl AsRef<Path>,
        extension_path: Option<&Path>,
    ) -> DbResult<Self> {
        let db_path = db_path.as_ref().to_path_buf();
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(&db_path)?;

        let cr_enabled = if let Some(ext_path) = extension_path {
            if ext_path.exists() {
                unsafe { conn.load_extension(ext_path, Some("sqlite3_crsqlite_init")) }.is_ok()
            } else {
                false
            }
        } else {
            false
        };

        let mut db = Self {
            conn,
            db_path,
            cr_enabled,
            site_id: None,
        };

        db.init_schema()?;
        Ok(db)
    }

    /// Get a reference to the underlying connection.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Get the database file path.
    pub fn path(&self) -> &Path {
        &self.db_path
    }

    /// Whether cr-sqlite extension is loaded.
    pub fn cr_enabled(&self) -> bool {
        self.cr_enabled
    }

    /// Get this database's unique site ID (cr-sqlite).
    pub fn site_id(&mut self) -> Option<&[u8]> {
        if !self.cr_enabled {
            return None;
        }
        if self.site_id.is_none() {
            if let Ok(id) = self
                .conn
                .query_row("SELECT crsql_site_id()", [], |row| row.get::<_, Vec<u8>>(0))
            {
                self.site_id = Some(id);
            }
        }
        self.site_id.as_deref()
    }

    /// Get the current cr-sqlite database version.
    pub fn db_version(&self) -> DbResult<i64> {
        if !self.cr_enabled {
            return Ok(0);
        }
        Ok(self
            .conn
            .query_row("SELECT crsql_db_version()", [], |row| row.get(0))?)
    }

    // =========================================================================
    // Schema
    // =========================================================================

    fn init_schema(&mut self) -> DbResult<()> {
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

            CREATE TABLE IF NOT EXISTS agent_tasks (
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
            );

            CREATE TABLE IF NOT EXISTS agent_tasks_archive (
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
            // Add read_at to agent_tasks (matches Python schema)
            self.ensure_column("agent_tasks", "read_at", "read_at TEXT DEFAULT NULL");
            // Add completed_at if missing (column order may differ from Python)
            self.ensure_column(
                "agent_tasks",
                "completed_at",
                "completed_at TEXT DEFAULT NULL",
            );
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

    // =========================================================================
    // Vault Entry CRUD
    // =========================================================================

    #[allow(clippy::too_many_arguments)]
    pub fn set_entry(
        &self,
        path: &str,
        value: &str,
        category: Option<&str>,
        service: Option<&str>,
        app: Option<&str>,
        env: Option<&str>,
        notes: Option<&str>,
        tags: Option<&[String]>,
        storage_mode: Option<&str>,
        expires_at: Option<&str>,
        rotation_interval_days: Option<i32>,
        related_apps: Option<&[String]>,
    ) -> DbResult<VaultEntry> {
        let now = Utc::now().to_rfc3339();
        let tags_str = tags.map(|t| t.join(",")).unwrap_or_default();
        let related_str = related_apps.map(|r| r.join(",")).unwrap_or_default();
        let category = category.unwrap_or("env_var");
        let storage_mode = storage_mode.unwrap_or("vault");

        // Preserve created_at if entry exists
        let created_at = self
            .conn
            .query_row(
                "SELECT created_at FROM vault_entries WHERE path = ?1",
                params![path],
                |row| row.get::<_, Option<String>>(0),
            )
            .unwrap_or(None)
            .unwrap_or_else(|| now.clone());

        self.conn.execute(
            "INSERT OR REPLACE INTO vault_entries
             (path, value, category, service, app, env, notes, tags, storage_mode,
              expires_at, rotation_interval_days, related_apps, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                path,
                value,
                category,
                service,
                app,
                env,
                notes,
                tags_str,
                storage_mode,
                expires_at,
                rotation_interval_days,
                related_str,
                created_at,
                now,
            ],
        )?;

        Ok(VaultEntry {
            path: path.to_string(),
            value: value.to_string(),
            category: category.to_string(),
            service: service.map(|s| s.to_string()),
            app: app.map(|s| s.to_string()),
            env: env.map(|s| s.to_string()),
            notes: notes.map(|s| s.to_string()),
            tags: tags.map(|t| t.to_vec()).unwrap_or_default(),
            storage_mode: storage_mode.to_string(),
            expires_at: expires_at.map(|s| s.to_string()),
            rotation_interval_days,
            related_apps: related_apps.map(|r| r.to_vec()).unwrap_or_default(),
            created_at: Some(created_at),
            updated_at: Some(now),
        })
    }

    pub fn get_entry(&self, path: &str) -> DbResult<Option<VaultEntry>> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM vault_entries WHERE path = ?1")?;
        let mut rows = stmt.query(params![path])?;

        if let Some(row) = rows.next()? {
            Ok(Some(row_to_entry(row)?))
        } else {
            Ok(None)
        }
    }

    pub fn delete_entry(&self, path: &str) -> DbResult<bool> {
        let count = self
            .conn
            .execute("DELETE FROM vault_entries WHERE path = ?1", params![path])?;
        Ok(count > 0)
    }

    pub fn list_entries(
        &self,
        service: Option<&str>,
        category: Option<&str>,
        prefix: Option<&str>,
    ) -> DbResult<Vec<VaultEntry>> {
        let mut sql = "SELECT * FROM vault_entries WHERE 1=1".to_string();
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(s) = service {
            sql.push_str(" AND service = ?");
            param_values.push(Box::new(s.to_string()));
        }
        if let Some(c) = category {
            sql.push_str(" AND category = ?");
            param_values.push(Box::new(c.to_string()));
        }
        if let Some(p) = prefix {
            sql.push_str(" AND path LIKE ?");
            param_values.push(Box::new(format!("{p}%")));
        }
        sql.push_str(" ORDER BY path");

        let mut stmt = self.conn.prepare(&sql)?;
        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();
        let rows = stmt.query_map(params_ref.as_slice(), row_to_entry)?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    pub fn search_entries(&self, query: &str, limit: i32) -> DbResult<Vec<VaultEntry>> {
        let pattern = format!("%{query}%");
        let mut stmt = self.conn.prepare(
            "SELECT * FROM vault_entries
             WHERE path LIKE ?1 OR notes LIKE ?1 OR tags LIKE ?1 OR service LIKE ?1
             ORDER BY path LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![pattern, limit], row_to_entry)?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    pub fn list_rotation_candidates(&self) -> DbResult<Vec<VaultEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT * FROM vault_entries
             WHERE (expires_at IS NOT NULL AND expires_at != '')
                OR rotation_interval_days IS NOT NULL
             ORDER BY path",
        )?;
        let rows = stmt.query_map([], row_to_entry)?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    // =========================================================================
    // Guide CRUD
    // =========================================================================

    #[allow(clippy::too_many_arguments)]
    pub fn set_guide(
        &self,
        name: &str,
        content: &str,
        category: Option<&str>,
        tags: Option<&[String]>,
        status: Option<&str>,
        verified_at: Option<&str>,
        related_paths: Option<&[String]>,
    ) -> DbResult<VaultGuide> {
        let now = Utc::now().to_rfc3339();
        let tags_str = tags.map(|t| t.join(",")).unwrap_or_default();
        let related_str = related_paths.map(|r| r.join(",")).unwrap_or_default();
        let category = category.unwrap_or("procedure");
        let status = status.unwrap_or("active");

        // Get existing version
        let (created_at, version) = self
            .conn
            .query_row(
                "SELECT created_at, version FROM vault_guides WHERE name = ?1",
                params![name],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<i32>>(1)?,
                    ))
                },
            )
            .unwrap_or((None, None));

        let created_at = created_at.unwrap_or_else(|| now.clone());
        let version = version.map(|v| v + 1).unwrap_or(1);

        self.conn.execute(
            "INSERT OR REPLACE INTO vault_guides
             (name, content, category, tags, version, status, verified_at, related_paths, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![name, content, category, tags_str, version, status, verified_at, related_str, created_at, now],
        )?;

        Ok(VaultGuide {
            name: name.to_string(),
            content: content.to_string(),
            category: category.to_string(),
            tags: tags.map(|t| t.to_vec()).unwrap_or_default(),
            version,
            status: status.to_string(),
            verified_at: verified_at.map(|s| s.to_string()),
            related_paths: related_paths.map(|r| r.to_vec()).unwrap_or_default(),
            created_at: Some(created_at),
            updated_at: Some(now),
        })
    }

    pub fn get_guide(&self, name: &str) -> DbResult<Option<VaultGuide>> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM vault_guides WHERE name = ?1")?;
        let mut rows = stmt.query(params![name])?;

        if let Some(row) = rows.next()? {
            Ok(Some(row_to_guide(row)?))
        } else {
            Ok(None)
        }
    }

    pub fn delete_guide(&self, name: &str) -> DbResult<bool> {
        let count = self
            .conn
            .execute("DELETE FROM vault_guides WHERE name = ?1", params![name])?;
        Ok(count > 0)
    }

    pub fn list_guides(
        &self,
        category: Option<&str>,
        status: Option<&str>,
    ) -> DbResult<Vec<VaultGuide>> {
        let mut sql = "SELECT * FROM vault_guides WHERE 1=1".to_string();
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(c) = category {
            sql.push_str(" AND category = ?");
            param_values.push(Box::new(c.to_string()));
        }
        if let Some(s) = status {
            sql.push_str(" AND status = ?");
            param_values.push(Box::new(s.to_string()));
        }
        sql.push_str(" ORDER BY name");

        let mut stmt = self.conn.prepare(&sql)?;
        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();
        let rows = stmt.query_map(params_ref.as_slice(), row_to_guide)?;

        let mut guides = Vec::new();
        for row in rows {
            guides.push(row?);
        }
        Ok(guides)
    }

    pub fn search_guides(&self, query: &str) -> DbResult<Vec<VaultGuide>> {
        let pattern = format!("%{query}%");
        let mut stmt = self.conn.prepare(
            "SELECT * FROM vault_guides
             WHERE name LIKE ?1 OR content LIKE ?1 OR tags LIKE ?1
             ORDER BY name",
        )?;
        let rows = stmt.query_map(params![pattern], row_to_guide)?;

        let mut guides = Vec::new();
        for row in rows {
            guides.push(row?);
        }
        Ok(guides)
    }

    pub fn verify_guide(&self, name: &str) -> DbResult<Option<VaultGuide>> {
        let now = Utc::now().to_rfc3339();
        let count = self.conn.execute(
            "UPDATE vault_guides SET verified_at = ?1, updated_at = ?1 WHERE name = ?2",
            params![now, name],
        )?;
        if count == 0 {
            return Ok(None);
        }
        self.get_guide(name)
    }

    pub fn deprecate_guide(&self, name: &str) -> DbResult<Option<VaultGuide>> {
        let now = Utc::now().to_rfc3339();
        let count = self.conn.execute(
            "UPDATE vault_guides SET status = 'deprecated', updated_at = ?1 WHERE name = ?2",
            params![now, name],
        )?;
        if count == 0 {
            return Ok(None);
        }
        self.get_guide(name)
    }

    pub fn list_stale_guides(&self, threshold_days: i32) -> DbResult<Vec<VaultGuide>> {
        let cutoff = Utc::now() - chrono::Duration::days(threshold_days as i64);
        let cutoff_str = cutoff.to_rfc3339();

        let mut stmt = self.conn.prepare(
            "SELECT * FROM vault_guides
             WHERE (status IS NULL OR status = 'active')
               AND (verified_at IS NULL OR verified_at < ?1)
             ORDER BY verified_at ASC NULLS FIRST, updated_at ASC",
        )?;
        let rows = stmt.query_map(params![cutoff_str], row_to_guide)?;

        let mut guides = Vec::new();
        for row in rows {
            guides.push(row?);
        }
        Ok(guides)
    }

    // =========================================================================
    // Sync Operations (cr-sqlite)
    // =========================================================================

    /// Get the last known db_version for a peer, or 0 if unknown.
    pub fn get_peer_version(&self, peer_site_id: &str) -> i64 {
        self.conn
            .query_row(
                "SELECT last_seen_version FROM sync_peers WHERE peer_site_id = ?1",
                params![peer_site_id],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0)
    }

    /// Update the last known db_version for a peer after sync.
    pub fn update_peer_version(&self, peer_site_id: &str, version: i64, addr: &str) {
        let now = Utc::now().to_rfc3339();
        let _ = self.conn.execute(
            "INSERT INTO sync_peers (peer_site_id, last_seen_version, last_seen_at, last_known_addr)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(peer_site_id) DO UPDATE SET
                last_seen_version = excluded.last_seen_version,
                last_seen_at = excluded.last_seen_at,
                last_known_addr = excluded.last_known_addr",
            params![peer_site_id, version, now, addr],
        );
    }

    /// Get all changes since a given database version.
    pub fn get_changes_since(&self, db_version: i64) -> DbResult<Vec<SyncChange>> {
        if !self.cr_enabled {
            return Err(DbError::CrSqliteNotEnabled);
        }

        let mut stmt = self.conn.prepare(
            "SELECT [table], pk, cid, val, col_version, db_version, site_id, cl, seq
             FROM crsql_changes WHERE db_version > ?1
             ORDER BY db_version, seq",
        )?;

        let rows = stmt.query_map(params![db_version], |row| {
            Ok(SyncChange {
                table: row.get(0)?,
                pk: row.get(1)?,
                cid: row.get(2)?,
                val: row.get(3)?,
                col_version: row.get(4)?,
                db_version: row.get(5)?,
                site_id: row.get(6)?,
                cl: row.get(7)?,
                seq: row.get(8)?,
            })
        })?;

        let mut changes = Vec::new();
        for row in rows {
            changes.push(row?);
        }
        Ok(changes)
    }

    /// Apply changes from another peer.
    pub fn apply_changes(&self, changes: &[SyncChange]) -> DbResult<i32> {
        if !self.cr_enabled {
            return Err(DbError::CrSqliteNotEnabled);
        }

        let mut applied = 0;
        let mut skipped = 0;
        for c in changes {
            if !ACTIVE_SYNC_TABLES.contains(&c.table.as_str()) {
                skipped += 1;
                continue;
            }

            match self.conn.execute(
                "INSERT INTO crsql_changes ([table], pk, cid, val, col_version, db_version, site_id, cl, seq)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![c.table, c.pk, c.cid, c.val, c.col_version, c.db_version, c.site_id, c.cl, c.seq],
            ) {
                Ok(_) => applied += 1,
                Err(rusqlite::Error::SqliteFailure(_, _)) => {} // already applied
                Err(e) => return Err(e.into()),
            }
        }

        if skipped > 0 {
            warn!("Skipped {skipped} changes for deprecated/specialized sync tables (inactive in this build).");
        }

        Ok(applied)
    }

    /// Return whether an agent-task migration to archive has already been completed.
    pub fn has_agent_task_archive_migration(&self) -> bool {
        self.get_meta_value(MIGRATION_AGENT_TASKS_ARCHIVE_KEY)
            .ok()
            .and_then(|v| v)
            .as_deref()
            == Some("1")
    }

    /// Read-only visibility of the legacy `agent_tasks` table.
    pub fn has_agent_tasks_table(&self) -> bool {
        self.table_exists("agent_tasks")
    }

    /// Return archived legacy `agent_tasks` row count recorded at migration time.
    pub fn agent_task_archive_row_count(&self) -> i64 {
        self.get_meta_value(MIGRATION_AGENT_TASKS_ARCHIVE_COUNT_KEY)
            .ok()
            .and_then(|v| v)
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0)
    }

    /// Return and clear a one-time migration notice to avoid repeated startup banners.
    pub fn consume_agent_task_archive_migration_notice(&self) -> DbResult<Option<i64>> {
        let pending = self
            .get_meta_value(MIGRATION_AGENT_TASKS_ARCHIVE_NOTICE_KEY)?
            .as_deref()
            == Some("1");
        if !pending {
            return Ok(None);
        }

        let count = self.agent_task_archive_row_count();
        self.set_meta(MIGRATION_AGENT_TASKS_ARCHIVE_NOTICE_KEY, "0")?;
        Ok(Some(count))
    }

    /// Ensure the legacy `agent_tasks` table exists only for compatibility and does
    /// not participate in active sync/runtime.
    fn migrate_agent_tasks_to_archive(&self) -> DbResult<bool> {
        if self.has_agent_task_archive_migration() {
            return Ok(false);
        }

        // Keep legacy table for read compatibility, but migrate rows for hardening.
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

    fn set_meta(&self, key: &str, value: &str) -> DbResult<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO vault_meta (key, value, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![key, value, now],
        )?;
        Ok(())
    }

    fn get_meta_value(&self, key: &str) -> DbResult<Option<String>> {
        self.conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = ?1",
                [key],
                |row| row.get::<_, String>(0),
            )
            .map(Some)
            .or_else(|e| {
                if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
                    Ok(None)
                } else {
                    Err(e)
                }
            })
            .map_err(DbError::from)
    }

    fn table_exists(&self, table_name: &str) -> bool {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                params![table_name],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0)
            > 0
    }

    /// Get the schema version from vault_meta.
    pub fn schema_version(&self) -> i32 {
        self.get_schema_version()
    }

    /// Finalize cr-sqlite before closing.
    pub fn close(self) -> DbResult<()> {
        if self.cr_enabled {
            let _ = self.conn.execute("SELECT crsql_finalize()", []);
        }
        Ok(())
    }
}

// =========================================================================
// Row conversion helpers
// =========================================================================

fn row_to_entry(row: &rusqlite::Row) -> rusqlite::Result<VaultEntry> {
    let tags_str: Option<String> = row.get("tags")?;
    let related_str: Option<String> = row.get("related_apps")?;

    Ok(VaultEntry {
        path: row.get("path")?,
        value: row.get("value")?,
        category: row
            .get::<_, Option<String>>("category")?
            .unwrap_or_else(|| "env_var".into()),
        service: row.get("service")?,
        app: row.get("app")?,
        env: row.get("env")?,
        notes: row.get("notes")?,
        tags: parse_csv(&tags_str.unwrap_or_default()),
        storage_mode: row
            .get::<_, Option<String>>("storage_mode")?
            .unwrap_or_else(|| "vault".into()),
        expires_at: row.get("expires_at").unwrap_or(None),
        rotation_interval_days: row.get("rotation_interval_days").unwrap_or(None),
        related_apps: parse_csv(&related_str.unwrap_or_default()),
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    })
}

fn row_to_guide(row: &rusqlite::Row) -> rusqlite::Result<VaultGuide> {
    let tags_str: Option<String> = row.get("tags")?;
    let related_str: Option<String> = row.get("related_paths").unwrap_or(None);

    Ok(VaultGuide {
        name: row.get("name")?,
        content: row.get("content")?,
        category: row
            .get::<_, Option<String>>("category")?
            .unwrap_or_else(|| "procedure".into()),
        tags: parse_csv(&tags_str.unwrap_or_default()),
        version: row.get::<_, Option<i32>>("version")?.unwrap_or(1),
        status: row
            .get::<_, Option<String>>("status")?
            .unwrap_or_else(|| "active".into()),
        verified_at: row.get("verified_at").unwrap_or(None),
        related_paths: parse_csv(&related_str.unwrap_or_default()),
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
    })
}

fn parse_csv(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_db(tmp: &TempDir) -> CrSqliteDatabase {
        let path = tmp.path().join("test.db");
        CrSqliteDatabase::open(&path, "test-passphrase", None).unwrap()
    }

    fn test_db_with_crsqlite(tmp: &TempDir) -> Option<CrSqliteDatabase> {
        let ext = crate::config::cr_sqlite_extension_path();
        if !ext.exists() {
            // Also check the common dev location (handles both ~/.memxp and ~/.vaultp2p)
            let alt = crate::config::vault_base_dir().join("crsqlite.dylib");
            if !alt.exists() {
                return None;
            }
            let path = tmp.path().join("test_cr.db");
            return Some(CrSqliteDatabase::open(&path, "test-passphrase", Some(&alt)).unwrap());
        }
        let path = tmp.path().join("test_cr.db");
        Some(CrSqliteDatabase::open(&path, "test-passphrase", Some(&ext)).unwrap())
    }

    #[test]
    fn test_open_encrypted_db() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        // Verify it opened successfully — cipher_version check is inside open()
        assert!(db.path().exists());
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
        assert!(tables.contains(&"agent_tasks".to_string()));
        assert!(tables.contains(&"agent_tasks_archive".to_string()));
        assert!(tables.contains(&"sync_conflicts".to_string()));
        assert!(tables.contains(&"conflict_settings".to_string()));

        // Auxiliary tables
        assert!(tables.contains(&"sync_audit".to_string()));
        assert!(tables.contains(&"sync_peers".to_string()));
        assert!(tables.contains(&"sync_backlog".to_string()));
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

    #[test]
    fn test_vault_entry_crud() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);

        // Set
        let entry = db
            .set_entry(
                "api/openai/key",
                "sk-test-123",
                Some("api_key"),
                Some("openai"),
                None,
                None,
                Some("Test key"),
                Some(&["ai".to_string(), "prod".to_string()]),
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(entry.path, "api/openai/key");
        assert_eq!(entry.value, "sk-test-123");

        // Get
        let got = db.get_entry("api/openai/key").unwrap().unwrap();
        assert_eq!(got.value, "sk-test-123");
        assert_eq!(got.category, "api_key");
        assert_eq!(got.service, Some("openai".to_string()));
        assert_eq!(got.tags, vec!["ai", "prod"]);

        // List
        let list = db.list_entries(Some("openai"), None, None).unwrap();
        assert_eq!(list.len(), 1);

        // Search
        let found = db.search_entries("openai", 10).unwrap();
        assert_eq!(found.len(), 1);

        // Delete
        assert!(db.delete_entry("api/openai/key").unwrap());
        assert!(db.get_entry("api/openai/key").unwrap().is_none());
    }

    #[test]
    fn test_vault_guide_crud() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);

        // Set
        let guide = db
            .set_guide(
                "vps-deploy",
                "# Deploy\n1. ssh\n2. pull\n3. restart",
                Some("procedure"),
                Some(&["vps".to_string()]),
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(guide.name, "vps-deploy");
        assert_eq!(guide.version, 1);

        // Update → version increments
        let guide2 = db
            .set_guide("vps-deploy", "# Deploy v2", None, None, None, None, None)
            .unwrap();
        assert_eq!(guide2.version, 2);

        // Get
        let got = db.get_guide("vps-deploy").unwrap().unwrap();
        assert_eq!(got.content, "# Deploy v2");

        // Verify
        let verified = db.verify_guide("vps-deploy").unwrap().unwrap();
        assert!(verified.verified_at.is_some());

        // Deprecate
        let deprecated = db.deprecate_guide("vps-deploy").unwrap().unwrap();
        assert_eq!(deprecated.status, "deprecated");

        // Stale (should not include deprecated)
        let stale = db.list_stale_guides(0).unwrap();
        assert!(stale.is_empty());

        // Search
        let found = db.search_guides("deploy").unwrap();
        assert_eq!(found.len(), 1);

        // Delete
        assert!(db.delete_guide("vps-deploy").unwrap());
        assert!(db.get_guide("vps-deploy").unwrap().is_none());
    }

    #[test]
    fn test_encryption_on_disk() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("encrypted.db");
        {
            let db = CrSqliteDatabase::open(&path, "secret-key", None).unwrap();
            db.set_entry(
                "test/key",
                "test-value",
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
        }

        // Read raw file — should NOT be SQLite plaintext
        let raw = std::fs::read(&path).unwrap();
        assert!(raw.len() >= 16);
        let sqlite_header = b"SQLite format 3\0";
        assert_ne!(&raw[..16], sqlite_header);
    }

    #[test]
    fn test_cannot_read_without_key() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("locked.db");
        {
            let db = CrSqliteDatabase::open(&path, "my-key", None).unwrap();
            db.set_entry(
                "test/key", "value", None, None, None, None, None, None, None, None, None, None,
            )
            .unwrap();
        }

        // Try to open without encryption
        let conn = Connection::open(&path).unwrap();
        let result = conn.query_row("SELECT count(*) FROM vault_entries", [], |row| {
            row.get::<_, i64>(0)
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_crsqlite_loads() {
        let tmp = TempDir::new().unwrap();
        if let Some(mut db) = test_db_with_crsqlite(&tmp) {
            assert!(db.cr_enabled());

            let ver = db.db_version().unwrap();
            assert!(ver >= 0);

            let site_id = db.site_id().unwrap();
            assert_eq!(site_id.len(), 16);
        }
        // Skip if cr-sqlite not available
    }

    #[test]
    fn test_crr_changes_tracked() {
        let tmp = TempDir::new().unwrap();
        if let Some(db) = test_db_with_crsqlite(&tmp) {
            db.set_entry(
                "test/a", "val-a", None, None, None, None, None, None, None, None, None, None,
            )
            .unwrap();
            db.set_entry(
                "test/b", "val-b", None, None, None, None, None, None, None, None, None, None,
            )
            .unwrap();

            let changes = db.get_changes_since(0).unwrap();
            // Each entry has multiple columns, so many changes
            assert!(!changes.is_empty());

            // Verify pk is Vec<u8> (BLOB)
            for c in &changes {
                assert!(!c.pk.is_empty(), "pk should be a non-empty BLOB");
            }
        }
    }

    #[test]
    fn test_pk_is_blob() {
        let tmp = TempDir::new().unwrap();
        if let Some(db) = test_db_with_crsqlite(&tmp) {
            db.set_entry(
                "api/test", "value", None, None, None, None, None, None, None, None, None, None,
            )
            .unwrap();

            let changes = db.get_changes_since(0).unwrap();
            assert!(!changes.is_empty());

            // pk must be Vec<u8>, not String
            let first = &changes[0];
            assert!(!first.pk.is_empty());
            // The pk is encoded as MessagePack or similar BLOB, not a UTF-8 string
        }
    }

    #[test]
    fn test_apply_changes_between_dbs() {
        let tmp = TempDir::new().unwrap();
        let ext = crate::config::vault_base_dir().join("crsqlite.dylib");
        if !ext.exists() {
            return; // Skip if cr-sqlite not available
        }

        let path_a = tmp.path().join("node_a.db");
        let path_b = tmp.path().join("node_b.db");

        let db_a = CrSqliteDatabase::open(&path_a, "key-a", Some(&ext)).unwrap();
        let db_b = CrSqliteDatabase::open(&path_b, "key-b", Some(&ext)).unwrap();

        // Insert on A
        db_a.set_entry(
            "shared/key",
            "from-a",
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

        // Get changes from A, apply to B
        let changes = db_a.get_changes_since(0).unwrap();
        assert!(!changes.is_empty());

        db_b.apply_changes(&changes).unwrap();

        // B should now have the entry
        let entry = db_b.get_entry("shared/key").unwrap().unwrap();
        assert_eq!(entry.value, "from-a");
    }

    #[test]
    fn test_lww_conflict_convergence() {
        let tmp = TempDir::new().unwrap();
        let ext = crate::config::vault_base_dir().join("crsqlite.dylib");
        if !ext.exists() {
            return;
        }

        let path_a = tmp.path().join("lww_a.db");
        let path_b = tmp.path().join("lww_b.db");

        let mut db_a = CrSqliteDatabase::open(&path_a, "key", Some(&ext)).unwrap();
        let mut db_b = CrSqliteDatabase::open(&path_b, "key", Some(&ext)).unwrap();

        // Both insert same initial entry
        db_a.set_entry(
            "conflict/key",
            "initial",
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
        let changes_a = db_a.get_changes_since(0).unwrap();
        db_b.apply_changes(&changes_a).unwrap();

        // Both update concurrently
        db_a.set_entry(
            "conflict/key",
            "a-wins",
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
        db_b.set_entry(
            "conflict/key",
            "b-wins",
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

        // Bidirectional sync
        let _site_a = db_a.site_id().unwrap().to_vec();
        let _site_b = db_b.site_id().unwrap().to_vec();

        let a_changes = db_a.get_changes_since(0).unwrap();
        let b_changes = db_b.get_changes_since(0).unwrap();

        db_b.apply_changes(&a_changes).unwrap();
        db_a.apply_changes(&b_changes).unwrap();

        // Both should converge to same value (LWW)
        let val_a = db_a.get_entry("conflict/key").unwrap().unwrap().value;
        let val_b = db_b.get_entry("conflict/key").unwrap().unwrap().value;
        assert_eq!(val_a, val_b, "LWW should converge");
    }
}
