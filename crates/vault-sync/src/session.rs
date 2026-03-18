//! Sync session management.
//!
//! Tracks per-peer sync state (last sent/received versions) and provides
//! methods for incremental synchronization.

use vault_core::db::{CrSqliteDatabase, DbResult};
use vault_core::models::SyncChange;

/// Manages a sync session between the local database and a remote peer.
pub struct SyncSession<'a> {
    pub db: &'a CrSqliteDatabase,
    pub remote_site_id: String,
    pub last_sent_version: i64,
    pub last_received_version: i64,
}

impl<'a> SyncSession<'a> {
    /// Create a new sync session.
    pub fn new(
        db: &'a CrSqliteDatabase,
        remote_site_id: &str,
        last_sent_version: i64,
        last_received_version: i64,
    ) -> Self {
        Self {
            db,
            remote_site_id: remote_site_id.to_string(),
            last_sent_version,
            last_received_version,
        }
    }

    /// Get changes to send to the remote peer (since last_sent_version).
    pub fn get_outgoing_changes(&self) -> DbResult<Vec<SyncChange>> {
        self.db.get_changes_since(self.last_sent_version)
    }

    /// Apply changes received from the remote peer.
    pub fn receive_changes(&mut self, changes: &[SyncChange]) -> DbResult<i32> {
        if changes.is_empty() {
            return Ok(0);
        }

        let count = self.db.apply_changes(changes)?;

        // Update tracked version
        if let Some(max_ver) = changes.iter().map(|c| c.db_version).max() {
            self.last_received_version = max_ver;
        }

        Ok(count)
    }

    /// Mark that changes up to `version` were successfully sent.
    pub fn mark_sent(&mut self, version: i64) {
        self.last_sent_version = version;
    }
}

/// Perform a full bidirectional sync between two databases.
///
/// Returns `(applied_to_db1, applied_to_db2)`.
pub fn sync_bidirectional(
    db1: &CrSqliteDatabase,
    db2: &CrSqliteDatabase,
    db1_last_version: i64,
    db2_last_version: i64,
) -> DbResult<(i32, i32)> {
    let changes_from_db1 = db1.get_changes_since(db2_last_version)?;
    let changes_from_db2 = db2.get_changes_since(db1_last_version)?;

    let applied_to_db2 = if changes_from_db1.is_empty() {
        0
    } else {
        db2.apply_changes(&changes_from_db1)?
    };

    let applied_to_db1 = if changes_from_db2.is_empty() {
        0
    } else {
        db1.apply_changes(&changes_from_db2)?
    };

    Ok((applied_to_db1, applied_to_db2))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _make_test_db(tmp: &tempfile::TempDir, name: &str) -> Option<CrSqliteDatabase> {
        let ext = vault_core::config::cr_sqlite_extension_path();
        if !ext.exists() {
            let alt = vault_core::config::vault_base_dir().join("crsqlite.dylib");
            if !alt.exists() {
                return None;
            }
            let path = tmp.path().join(name);
            return Some(CrSqliteDatabase::open(&path, "test-passphrase", Some(&alt)).unwrap());
        }
        let path = tmp.path().join(name);
        Some(CrSqliteDatabase::open(&path, "test-passphrase", Some(&ext)).unwrap())
    }

    #[test]
    fn test_sync_session_basic() {
        let tmp = tempfile::TempDir::new().unwrap();

        let db1 = match _make_test_db(&tmp, "session_a.db") {
            Some(db) => db,
            None => {
                eprintln!("SKIP: cr-sqlite extension not found");
                return;
            }
        };
        let db2 = match _make_test_db(&tmp, "session_b.db") {
            Some(db) => db,
            None => return,
        };

        // Insert into db1
        db1.set_entry(
            "api/test/key",
            "secret-from-db1",
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

        // Create session for db1 -> db2
        let session = SyncSession::new(&db1, "remote-site", 0, 0);
        let outgoing = session.get_outgoing_changes().unwrap();
        assert!(!outgoing.is_empty());

        // Apply to db2
        let mut session2 = SyncSession::new(&db2, "local-site", 0, 0);
        let applied = session2.receive_changes(&outgoing).unwrap();
        assert!(applied > 0);

        // Verify db2 has the entry
        let entry = db2.get_entry("api/test/key").unwrap().unwrap();
        assert_eq!(entry.value, "secret-from-db1");
    }

    #[test]
    fn test_incremental_sync_versions() {
        let tmp = tempfile::TempDir::new().unwrap();

        let db1 = match _make_test_db(&tmp, "incr_a.db") {
            Some(db) => db,
            None => {
                eprintln!("SKIP: cr-sqlite extension not found");
                return;
            }
        };
        let db2 = match _make_test_db(&tmp, "incr_b.db") {
            Some(db) => db,
            None => return,
        };

        // First round: insert key1
        db1.set_entry(
            "api/key1", "val1", None, None, None, None, None, None, None, None, None, None,
        )
        .unwrap();

        let changes1 = db1.get_changes_since(0).unwrap();
        db2.apply_changes(&changes1).unwrap();

        let ver_after_first = changes1.iter().map(|c| c.db_version).max().unwrap_or(0);

        // Second round: insert key2
        db1.set_entry(
            "api/key2", "val2", None, None, None, None, None, None, None, None, None, None,
        )
        .unwrap();

        // Only get changes since the first sync
        let changes2 = db1.get_changes_since(ver_after_first).unwrap();
        assert!(!changes2.is_empty());

        // All new changes should have db_version > ver_after_first
        for c in &changes2 {
            assert!(c.db_version > ver_after_first);
        }

        db2.apply_changes(&changes2).unwrap();

        // Verify both entries exist in db2
        assert!(db2.get_entry("api/key1").unwrap().is_some());
        assert!(db2.get_entry("api/key2").unwrap().is_some());
    }
}
