//! Conflict detection, queue management, and resolution.
//!
//! Manages sync conflicts that need agent review. Conflicts are stored
//! in the `sync_conflicts` table and conflict modes in `conflict_settings`.

use chrono::Utc;
use rusqlite::params;
use uuid::Uuid;

use crate::config;
use crate::crypto::value_hash;
use crate::db::{CrSqliteDatabase, DbError, DbResult};
use crate::models::{ConflictMode, SyncConflict};

/// Manages sync conflicts stored in the vault database.
pub struct ConflictQueue<'a> {
    db: &'a CrSqliteDatabase,
}

impl<'a> ConflictQueue<'a> {
    /// Create a new ConflictQueue wrapping a database.
    pub fn new(db: &'a CrSqliteDatabase) -> Self {
        Self { db }
    }

    // =========================================================================
    // Conflict Mode Settings
    // =========================================================================

    /// Set the conflict handling mode for a path.
    ///
    /// Path can use wildcards like `api/*` to match `api/openai/key`.
    pub fn set_conflict_mode(&self, path: &str, mode: &ConflictMode) -> DbResult<()> {
        let now = Utc::now().to_rfc3339();
        self.db.conn().execute(
            "INSERT INTO conflict_settings (path, conflict_mode, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(path) DO UPDATE SET conflict_mode = ?2, updated_at = ?3",
            params![path, mode.as_str(), now],
        )?;
        Ok(())
    }

    /// Get the conflict mode for a path.
    ///
    /// Checks exact match first, then wildcard patterns. Defaults to Auto.
    pub fn get_conflict_mode(&self, path: &str) -> DbResult<ConflictMode> {
        // Check exact match first
        let exact: Option<String> = self
            .db
            .conn()
            .query_row(
                "SELECT conflict_mode FROM conflict_settings WHERE path = ?1",
                params![path],
                |row| row.get(0),
            )
            .ok();

        if let Some(mode_str) = exact {
            return Ok(ConflictMode::parse(&mode_str));
        }

        // Check wildcard patterns (e.g., 'api/*' matches 'api/openai/key')
        let mut stmt = self.db.conn().prepare(
            "SELECT path, conflict_mode FROM conflict_settings
             WHERE path LIKE '%*%'
             ORDER BY LENGTH(path) DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        for row in rows {
            let (pattern, mode_str) = row?;
            if matches_wildcard(&pattern, path) {
                return Ok(ConflictMode::parse(&mode_str));
            }
        }

        // Default to auto
        Ok(ConflictMode::Auto)
    }

    /// List all conflict mode settings.
    pub fn list_conflict_settings(&self) -> DbResult<Vec<ConflictSetting>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT path, conflict_mode, created_at, updated_at
             FROM conflict_settings ORDER BY path",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(ConflictSetting {
                path: row.get(0)?,
                conflict_mode: row.get(1)?,
                created_at: row.get(2)?,
                updated_at: row.get(3)?,
            })
        })?;

        let mut settings = Vec::new();
        for row in rows {
            settings.push(row?);
        }
        Ok(settings)
    }

    /// Remove a conflict mode setting.
    pub fn remove_conflict_setting(&self, path: &str) -> DbResult<bool> {
        let count = self.db.conn().execute(
            "DELETE FROM conflict_settings WHERE path = ?1",
            params![path],
        )?;
        Ok(count > 0)
    }

    // =========================================================================
    // Conflict Detection
    // =========================================================================

    /// Detect if there's a conflict that needs review.
    ///
    /// A conflict is created if:
    /// - The path has `conflict_mode=review` and values differ
    /// - The path has `conflict_mode=reject` (auto-resolved to keep_local)
    ///
    /// Returns `None` for `auto` mode (let cr-sqlite LWW handle it).
    #[allow(clippy::too_many_arguments)]
    pub fn detect_conflict(
        &self,
        path: &str,
        local_value: &str,
        local_updated_at: &str,
        remote_value: &str,
        remote_updated_at: &str,
        remote_site_id: &str,
        local_site_id: Option<&str>,
        remote_db_version: Option<i64>,
        local_db_version: Option<i64>,
        previous_value: Option<&str>,
        related_apps: Option<&[String]>,
    ) -> DbResult<Option<SyncConflict>> {
        let mode = self.get_conflict_mode(path)?;
        let previous_value_hash = previous_value.map(value_hash);
        let now = Utc::now().to_rfc3339();
        let id = Uuid::new_v4().to_string()[..8].to_string();

        match mode {
            ConflictMode::Auto => {
                // Let cr-sqlite handle it with LWW
                Ok(None)
            }
            ConflictMode::Reject => {
                // Auto-resolve to keep_local
                let conflict = SyncConflict {
                    id,
                    path: path.to_string(),
                    local_value: Some(local_value.to_string()),
                    remote_value: Some(remote_value.to_string()),
                    local_updated_at: Some(local_updated_at.to_string()),
                    remote_updated_at: Some(remote_updated_at.to_string()),
                    remote_site_id: Some(remote_site_id.to_string()),
                    resolution: Some("keep_local".to_string()),
                    resolved_value: Some(local_value.to_string()),
                    resolved_at: Some(now.clone()),
                    resolved_by: Some(config::get_local_machine_id()),
                    created_at: Some(now),
                    notes: Some("Auto-rejected: path has conflict_mode=reject".to_string()),
                    local_site_id: local_site_id.map(|s| s.to_string()),
                    remote_db_version,
                    local_db_version,
                    previous_value_hash,
                    related_apps: related_apps.map(|r| r.to_vec()).unwrap_or_default(),
                    audit_context: None,
                };
                Ok(Some(conflict))
            }
            ConflictMode::Review => {
                // Check if values actually differ
                if local_value == remote_value {
                    return Ok(None);
                }

                let conflict = SyncConflict {
                    id,
                    path: path.to_string(),
                    local_value: Some(local_value.to_string()),
                    remote_value: Some(remote_value.to_string()),
                    local_updated_at: Some(local_updated_at.to_string()),
                    remote_updated_at: Some(remote_updated_at.to_string()),
                    remote_site_id: Some(remote_site_id.to_string()),
                    resolution: Some("pending".to_string()),
                    resolved_value: None,
                    resolved_at: None,
                    resolved_by: None,
                    created_at: Some(now),
                    notes: None,
                    local_site_id: local_site_id.map(|s| s.to_string()),
                    remote_db_version,
                    local_db_version,
                    previous_value_hash,
                    related_apps: related_apps.map(|r| r.to_vec()).unwrap_or_default(),
                    audit_context: None,
                };
                Ok(Some(conflict))
            }
        }
    }

    // =========================================================================
    // Conflict Queue Operations
    // =========================================================================

    /// Add a conflict to the queue for review.
    pub fn add_conflict(&self, conflict: &SyncConflict) -> DbResult<()> {
        let related_apps_json = if conflict.related_apps.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&conflict.related_apps).unwrap_or_default())
        };

        self.db.conn().execute(
            "INSERT INTO sync_conflicts (
                id, path, local_value, remote_value, local_updated_at,
                remote_updated_at, remote_site_id, resolution, resolved_value,
                resolved_at, resolved_by, created_at, notes,
                local_site_id, remote_db_version, local_db_version,
                previous_value_hash, related_apps, audit_context
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
            params![
                conflict.id,
                conflict.path,
                conflict.local_value,
                conflict.remote_value,
                conflict.local_updated_at,
                conflict.remote_updated_at,
                conflict.remote_site_id,
                conflict.resolution,
                conflict.resolved_value,
                conflict.resolved_at,
                conflict.resolved_by,
                conflict.created_at,
                conflict.notes,
                conflict.local_site_id,
                conflict.remote_db_version,
                conflict.local_db_version,
                conflict.previous_value_hash,
                related_apps_json,
                conflict.audit_context,
            ],
        )?;
        Ok(())
    }

    /// Get a conflict by ID.
    pub fn get_conflict(&self, conflict_id: &str) -> DbResult<Option<SyncConflict>> {
        let result = self.db.conn().query_row(
            "SELECT * FROM sync_conflicts WHERE id = ?1",
            params![conflict_id],
            row_to_conflict,
        );

        match result {
            Ok(c) => Ok(Some(c)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get all unresolved conflicts.
    pub fn get_pending_conflicts(&self) -> DbResult<Vec<SyncConflict>> {
        let mut stmt = self.db.conn().prepare(
            "SELECT * FROM sync_conflicts
             WHERE resolution = 'pending'
             ORDER BY created_at DESC",
        )?;

        let rows = stmt.query_map([], row_to_conflict)?;
        let mut conflicts = Vec::new();
        for row in rows {
            conflicts.push(row?);
        }
        Ok(conflicts)
    }

    /// List all conflicts with optional filter.
    pub fn list_conflicts(
        &self,
        include_resolved: bool,
        limit: i32,
    ) -> DbResult<Vec<SyncConflict>> {
        let sql = if include_resolved {
            "SELECT * FROM sync_conflicts ORDER BY created_at DESC LIMIT ?1"
        } else {
            "SELECT * FROM sync_conflicts WHERE resolution = 'pending' ORDER BY created_at DESC LIMIT ?1"
        };

        let mut stmt = self.db.conn().prepare(sql)?;
        let rows = stmt.query_map(params![limit], row_to_conflict)?;
        let mut conflicts = Vec::new();
        for row in rows {
            conflicts.push(row?);
        }
        Ok(conflicts)
    }

    /// Resolve a conflict.
    ///
    /// - `keep_local`: use the local value
    /// - `keep_remote`: use the remote value
    /// - `merge`: use the provided `value`
    pub fn resolve_conflict(
        &self,
        conflict_id: &str,
        resolution: &str,
        value: Option<&str>,
        notes: &str,
    ) -> DbResult<Option<SyncConflict>> {
        let conflict = match self.get_conflict(conflict_id)? {
            Some(c) => c,
            None => return Ok(None),
        };

        let now = Utc::now().to_rfc3339();
        let resolved_by = config::get_local_machine_id();

        let resolved_value = match resolution {
            "keep_local" => conflict.local_value.clone(),
            "keep_remote" => conflict.remote_value.clone(),
            "merge" => {
                if value.is_none() {
                    return Err(DbError::Other("merge resolution requires a value".into()));
                }
                value.map(|v| v.to_string())
            }
            _ => return Err(DbError::Other(format!("invalid resolution: {resolution}"))),
        };

        self.db.conn().execute(
            "UPDATE sync_conflicts
             SET resolution = ?1, resolved_value = ?2, resolved_at = ?3,
                 resolved_by = ?4, notes = ?5
             WHERE id = ?6",
            params![
                resolution,
                resolved_value,
                now,
                resolved_by,
                notes,
                conflict_id
            ],
        )?;

        self.get_conflict(conflict_id)
    }

    /// Apply a resolved conflict to the vault entry.
    pub fn apply_resolution(&self, conflict_id: &str) -> DbResult<bool> {
        let conflict = match self.get_conflict(conflict_id)? {
            Some(c) => c,
            None => return Ok(false),
        };

        if conflict.resolution.as_deref() == Some("pending") {
            return Ok(false);
        }

        if let Some(resolved_value) = &conflict.resolved_value {
            let now = Utc::now().to_rfc3339();
            self.db.conn().execute(
                "UPDATE vault_entries SET value = ?1, updated_at = ?2 WHERE path = ?3",
                params![resolved_value, now, conflict.path],
            )?;
        }

        Ok(true)
    }

    /// Delete a conflict from the queue.
    pub fn delete_conflict(&self, conflict_id: &str) -> DbResult<bool> {
        let count = self.db.conn().execute(
            "DELETE FROM sync_conflicts WHERE id = ?1",
            params![conflict_id],
        )?;
        Ok(count > 0)
    }

    /// Clear old resolved conflicts.
    pub fn clear_resolved_conflicts(&self, older_than_days: i32) -> DbResult<i32> {
        let cutoff = Utc::now() - chrono::Duration::days(older_than_days as i64);
        let cutoff_str = cutoff.to_rfc3339();

        let count = self.db.conn().execute(
            "DELETE FROM sync_conflicts
             WHERE resolution != 'pending' AND resolved_at < ?1",
            params![cutoff_str],
        )?;
        Ok(count as i32)
    }

    // =========================================================================
    // Statistics
    // =========================================================================

    /// Get conflict queue statistics.
    pub fn get_stats(&self) -> DbResult<ConflictStats> {
        let row = self.db.conn().query_row(
            "SELECT
                COUNT(*) as total,
                SUM(CASE WHEN resolution = 'pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN resolution = 'keep_local' THEN 1 ELSE 0 END) as kept_local,
                SUM(CASE WHEN resolution = 'keep_remote' THEN 1 ELSE 0 END) as kept_remote,
                SUM(CASE WHEN resolution = 'merge' THEN 1 ELSE 0 END) as merged
             FROM sync_conflicts",
            [],
            |row| {
                Ok(ConflictStats {
                    total: row.get::<_, i32>(0)? as usize,
                    pending: row.get::<_, i32>(1).unwrap_or(0) as usize,
                    kept_local: row.get::<_, i32>(2).unwrap_or(0) as usize,
                    kept_remote: row.get::<_, i32>(3).unwrap_or(0) as usize,
                    merged: row.get::<_, i32>(4).unwrap_or(0) as usize,
                })
            },
        )?;

        Ok(row)
    }
}

// =========================================================================
// Helper types
// =========================================================================

/// A conflict mode setting for a path.
#[derive(Debug, Clone)]
pub struct ConflictSetting {
    pub path: String,
    pub conflict_mode: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Conflict queue statistics.
#[derive(Debug, Clone)]
pub struct ConflictStats {
    pub total: usize,
    pub pending: usize,
    pub kept_local: usize,
    pub kept_remote: usize,
    pub merged: usize,
}

// =========================================================================
// Helpers
// =========================================================================

/// Check if a wildcard pattern matches a path.
///
/// Supports patterns like `api/*` matching `api/openai/key`.
fn matches_wildcard(pattern: &str, path: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        path.starts_with(prefix)
            && path.len() > prefix.len()
            && path.as_bytes()[prefix.len()] == b'/'
    } else if let Some(prefix) = pattern.strip_suffix('*') {
        path.starts_with(prefix)
    } else {
        pattern == path
    }
}

fn row_to_conflict(row: &rusqlite::Row) -> rusqlite::Result<SyncConflict> {
    let related_apps_str: Option<String> = row.get("related_apps").unwrap_or(None);
    let related_apps: Vec<String> = related_apps_str
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    Ok(SyncConflict {
        id: row.get("id")?,
        path: row.get("path")?,
        local_value: row.get("local_value")?,
        remote_value: row.get("remote_value")?,
        local_updated_at: row.get("local_updated_at")?,
        remote_updated_at: row.get("remote_updated_at")?,
        remote_site_id: row.get("remote_site_id")?,
        resolution: row.get("resolution")?,
        resolved_value: row.get("resolved_value").unwrap_or(None),
        resolved_at: row.get("resolved_at").unwrap_or(None),
        resolved_by: row.get("resolved_by").unwrap_or(None),
        created_at: row.get("created_at")?,
        notes: row.get("notes").unwrap_or(None),
        local_site_id: row.get("local_site_id").unwrap_or(None),
        remote_db_version: row.get("remote_db_version").unwrap_or(None),
        local_db_version: row.get("local_db_version").unwrap_or(None),
        previous_value_hash: row.get("previous_value_hash").unwrap_or(None),
        related_apps,
        audit_context: row.get("audit_context").unwrap_or(None),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_db(tmp: &TempDir) -> CrSqliteDatabase {
        let path = tmp.path().join("conflict_test.db");
        CrSqliteDatabase::open(&path, "test-passphrase", None).unwrap()
    }

    #[test]
    fn test_conflict_queue_crud() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let queue = ConflictQueue::new(&db);

        let conflict = SyncConflict {
            id: "test-001".to_string(),
            path: "api/openai/key".to_string(),
            local_value: Some("local-val".to_string()),
            remote_value: Some("remote-val".to_string()),
            local_updated_at: Some("2025-01-01T00:00:00+00:00".to_string()),
            remote_updated_at: Some("2025-01-01T00:01:00+00:00".to_string()),
            remote_site_id: Some("site-abc".to_string()),
            resolution: Some("pending".to_string()),
            resolved_value: None,
            resolved_at: None,
            resolved_by: None,
            created_at: Some(Utc::now().to_rfc3339()),
            notes: None,
            local_site_id: None,
            remote_db_version: None,
            local_db_version: None,
            previous_value_hash: None,
            related_apps: Vec::new(),
            audit_context: None,
        };

        // Add
        queue.add_conflict(&conflict).unwrap();

        // Get
        let got = queue.get_conflict("test-001").unwrap().unwrap();
        assert_eq!(got.path, "api/openai/key");
        assert_eq!(got.resolution.as_deref(), Some("pending"));

        // Pending list
        let pending = queue.get_pending_conflicts().unwrap();
        assert_eq!(pending.len(), 1);

        // Resolve (keep_local)
        let resolved = queue
            .resolve_conflict("test-001", "keep_local", None, "keeping local")
            .unwrap()
            .unwrap();
        assert_eq!(resolved.resolution.as_deref(), Some("keep_local"));
        assert_eq!(resolved.resolved_value.as_deref(), Some("local-val"));

        // No more pending
        let pending = queue.get_pending_conflicts().unwrap();
        assert_eq!(pending.len(), 0);

        // Resolve keep_remote (add second conflict)
        let conflict2 = SyncConflict {
            id: "test-002".to_string(),
            path: "api/test/key".to_string(),
            local_value: Some("local-2".to_string()),
            remote_value: Some("remote-2".to_string()),
            resolution: Some("pending".to_string()),
            created_at: Some(Utc::now().to_rfc3339()),
            ..conflict.clone()
        };
        queue.add_conflict(&conflict2).unwrap();
        let resolved2 = queue
            .resolve_conflict("test-002", "keep_remote", None, "")
            .unwrap()
            .unwrap();
        assert_eq!(resolved2.resolved_value.as_deref(), Some("remote-2"));

        // Resolve merge (add third conflict)
        let conflict3 = SyncConflict {
            id: "test-003".to_string(),
            path: "api/merged/key".to_string(),
            local_value: Some("local-3".to_string()),
            remote_value: Some("remote-3".to_string()),
            resolution: Some("pending".to_string()),
            created_at: Some(Utc::now().to_rfc3339()),
            ..conflict
        };
        queue.add_conflict(&conflict3).unwrap();
        let resolved3 = queue
            .resolve_conflict("test-003", "merge", Some("merged-value"), "merged manually")
            .unwrap()
            .unwrap();
        assert_eq!(resolved3.resolved_value.as_deref(), Some("merged-value"));
    }

    #[test]
    fn test_conflict_mode_wildcards() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let queue = ConflictQueue::new(&db);

        // Set wildcard mode
        queue
            .set_conflict_mode("api/*", &ConflictMode::Review)
            .unwrap();

        // Check that it matches
        let mode = queue.get_conflict_mode("api/openai/key").unwrap();
        assert_eq!(mode, ConflictMode::Review);

        // Check that non-matching path defaults to auto
        let mode = queue.get_conflict_mode("db/postgres/pass").unwrap();
        assert_eq!(mode, ConflictMode::Auto);

        // Exact match should override wildcard
        queue
            .set_conflict_mode("api/openai/key", &ConflictMode::Reject)
            .unwrap();
        let mode = queue.get_conflict_mode("api/openai/key").unwrap();
        assert_eq!(mode, ConflictMode::Reject);

        // Other api/* paths still get review
        let mode = queue.get_conflict_mode("api/anthropic/key").unwrap();
        assert_eq!(mode, ConflictMode::Review);
    }

    #[test]
    fn test_conflict_detection() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let queue = ConflictQueue::new(&db);

        // Auto mode: no conflict detected
        let result = queue
            .detect_conflict(
                "api/test/key",
                "local",
                "2025-01-01T00:00:00+00:00",
                "remote",
                "2025-01-01T00:01:00+00:00",
                "site-abc",
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert!(result.is_none());

        // Set review mode
        queue
            .set_conflict_mode("api/*", &ConflictMode::Review)
            .unwrap();

        // Review mode: conflict detected (different values)
        let result = queue
            .detect_conflict(
                "api/test/key",
                "local-val",
                "2025-01-01T00:00:00+00:00",
                "remote-val",
                "2025-01-01T00:01:00+00:00",
                "site-abc",
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert!(result.is_some());
        let conflict = result.unwrap();
        assert_eq!(conflict.resolution.as_deref(), Some("pending"));

        // Review mode: no conflict if values are same
        let result = queue
            .detect_conflict(
                "api/test/key",
                "same-val",
                "2025-01-01T00:00:00+00:00",
                "same-val",
                "2025-01-01T00:01:00+00:00",
                "site-abc",
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_conflict_reject_mode() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let queue = ConflictQueue::new(&db);

        queue
            .set_conflict_mode("secret/*", &ConflictMode::Reject)
            .unwrap();

        let result = queue
            .detect_conflict(
                "secret/key",
                "local-val",
                "2025-01-01T00:00:00+00:00",
                "remote-val",
                "2025-01-01T00:01:00+00:00",
                "site-abc",
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        let conflict = result.unwrap();
        assert_eq!(conflict.resolution.as_deref(), Some("keep_local"));
        assert_eq!(conflict.resolved_value.as_deref(), Some("local-val"));
        assert!(conflict.notes.as_deref().unwrap().contains("reject"));
    }

    #[test]
    fn test_conflict_value_hash() {
        // SHA-256[:4] hex (8 chars)
        let hash = value_hash("test-value");
        assert_eq!(hash.len(), 8);
        // Deterministic
        assert_eq!(hash, value_hash("test-value"));
        // Different values, different hashes
        assert_ne!(value_hash("val-a"), value_hash("val-b"));
    }

    #[test]
    fn test_apply_with_conflict_modes() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let queue = ConflictQueue::new(&db);

        // Insert a vault entry to test apply_resolution
        db.set_entry(
            "api/test/key",
            "original-value",
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

        // Add a resolved conflict
        let conflict = SyncConflict {
            id: "apply-001".to_string(),
            path: "api/test/key".to_string(),
            local_value: Some("original-value".to_string()),
            remote_value: Some("new-remote-value".to_string()),
            local_updated_at: Some("2025-01-01T00:00:00+00:00".to_string()),
            remote_updated_at: Some("2025-01-01T00:01:00+00:00".to_string()),
            remote_site_id: Some("site-abc".to_string()),
            resolution: Some("pending".to_string()),
            resolved_value: None,
            resolved_at: None,
            resolved_by: None,
            created_at: Some(Utc::now().to_rfc3339()),
            notes: None,
            local_site_id: None,
            remote_db_version: None,
            local_db_version: None,
            previous_value_hash: None,
            related_apps: Vec::new(),
            audit_context: None,
        };
        queue.add_conflict(&conflict).unwrap();

        // Can't apply pending conflict
        assert!(!queue.apply_resolution("apply-001").unwrap());

        // Resolve it
        queue
            .resolve_conflict("apply-001", "keep_remote", None, "")
            .unwrap();

        // Now apply
        assert!(queue.apply_resolution("apply-001").unwrap());

        // Verify the entry was updated
        let entry = db.get_entry("api/test/key").unwrap().unwrap();
        assert_eq!(entry.value, "new-remote-value");
    }

    #[test]
    fn test_conflict_stats() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let queue = ConflictQueue::new(&db);

        // Empty stats
        let stats = queue.get_stats().unwrap();
        assert_eq!(stats.total, 0);
        assert_eq!(stats.pending, 0);

        // Add some conflicts
        for (i, res) in ["pending", "keep_local", "keep_remote", "merge"]
            .iter()
            .enumerate()
        {
            let conflict = SyncConflict {
                id: format!("stats-{i:03}"),
                path: format!("api/key{i}"),
                local_value: Some("local".to_string()),
                remote_value: Some("remote".to_string()),
                resolution: Some(res.to_string()),
                created_at: Some(Utc::now().to_rfc3339()),
                ..Default::default()
            };
            queue.add_conflict(&conflict).unwrap();
        }

        let stats = queue.get_stats().unwrap();
        assert_eq!(stats.total, 4);
        assert_eq!(stats.pending, 1);
        assert_eq!(stats.kept_local, 1);
        assert_eq!(stats.kept_remote, 1);
        assert_eq!(stats.merged, 1);
    }
}
