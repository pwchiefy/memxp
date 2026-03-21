//! CrSqlite-based database for P2P vault synchronization.
//!
//! Provides the core database with SQLCipher encryption and
//! cr-sqlite CRDT extension for conflict-free replication.

use chrono::Utc;
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, warn};

mod entries;
mod guides;
mod schema;

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

use crate::models::SyncChange;

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

    // =========================================================================
    // Agent Task Archive Queries
    // =========================================================================

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

    // =========================================================================
    // Meta Helpers
    // =========================================================================

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

    /// Finalize cr-sqlite before closing.
    pub fn close(self) -> DbResult<()> {
        if self.cr_enabled {
            let _ = self.conn.execute("SELECT crsql_finalize()", []);
        }
        Ok(())
    }
}

// =========================================================================
// Shared helpers
// =========================================================================

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
            // Also check the common dev location (~/.memxp)
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
