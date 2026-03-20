//! CredentialStore — the sole external API for credential access.
//!
//! Enforces storage_mode routing (vault/keychain/both), value stripping
//! on bulk reads, and provides a clean boundary for policy enforcement.
//!
//! All credential access from MCP, CLI, and Web should go through this
//! module. Direct access to `CrSqliteDatabase` entry methods is restricted
//! to `pub(crate)` after migration.

use crate::db::{CrSqliteDatabase, DbError, DbResult};
use crate::keyring_backend::{delete_from_keyring, get_from_keyring, set_in_keyring};
use crate::models::VaultEntry;

/// Policy-enforcing credential store.
///
/// Borrows a `CrSqliteDatabase` reference (same pattern as `ConflictQueue::new(&state.db)`).
/// All credential reads/writes should go through this struct.
pub struct CredentialStore<'a> {
    db: &'a CrSqliteDatabase,
}

impl<'a> CredentialStore<'a> {
    /// Create a new CredentialStore wrapping a database reference.
    pub fn new(db: &'a CrSqliteDatabase) -> Self {
        Self { db }
    }

    // =========================================================================
    // Keychain Resolution
    // =========================================================================

    /// Resolve the actual value for an entry based on its storage_mode.
    ///
    /// - `"keychain"`: value comes exclusively from the OS keyring; error if missing.
    /// - `"both"`: prefer keyring, fall back to DB value silently.
    /// - `"vault"` (or anything else): DB value is authoritative, no-op.
    fn resolve_value(&self, entry: &mut VaultEntry) -> DbResult<()> {
        match entry.storage_mode.as_str() {
            "keychain" => match get_from_keyring(&entry.path) {
                Ok(Some(kv)) => entry.value = kv,
                Ok(None) => {
                    return Err(DbError::Other(format!(
                        "keychain entry missing for '{}' (storage_mode=keychain)",
                        entry.path
                    )))
                }
                Err(e) => {
                    return Err(DbError::Other(format!(
                        "keychain error for '{}': {e}",
                        entry.path
                    )))
                }
            },
            "both" => {
                if let Ok(Some(kv)) = get_from_keyring(&entry.path) {
                    entry.value = kv;
                }
                // "both" mode: DB value is fallback — no error if keychain fails
            }
            _ => {} // "vault" — value already correct
        }
        Ok(())
    }

    // =========================================================================
    // Write Operations
    // =========================================================================

    /// Store a credential, routing to keychain if storage_mode requires it.
    #[allow(clippy::too_many_arguments)]
    pub fn remember(
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
        let sm = storage_mode.unwrap_or("vault");

        // Determine what value to store in DB based on storage_mode
        let db_value = match sm {
            "keychain" => {
                // Store in keychain only, empty placeholder in DB
                set_in_keyring(path, value)
                    .map_err(|e| DbError::Other(format!("keyring error: {e}")))?;
                ""
            }
            "both" => {
                // Store in both keychain and DB
                set_in_keyring(path, value)
                    .map_err(|e| DbError::Other(format!("keyring error: {e}")))?;
                value
            }
            _ => value, // "vault" — DB only
        };

        let mut entry = self.db.set_entry(
            path,
            db_value,
            category,
            service,
            app,
            env,
            notes,
            tags,
            Some(sm),
            expires_at,
            rotation_interval_days,
            related_apps,
        )?;

        // Return the original value, not the DB placeholder
        entry.value = value.to_string();
        Ok(entry)
    }

    /// Store multiple credentials in batch.
    pub fn remember_batch(&self, entries: &[BatchEntry<'_>]) -> DbResult<Vec<BatchResult>> {
        let mut results = Vec::with_capacity(entries.len());
        for entry in entries {
            match self.remember(
                entry.path,
                entry.value,
                entry.category,
                entry.service,
                entry.app,
                entry.env,
                entry.notes,
                entry.tags,
                entry.storage_mode,
                entry.expires_at,
                entry.rotation_interval_days,
                entry.related_apps,
            ) {
                Ok(saved) => results.push(BatchResult::Ok(Box::new(saved))),
                Err(e) => results.push(BatchResult::Err(entry.path.to_string(), e.to_string())),
            }
        }
        Ok(results)
    }

    // =========================================================================
    // Read Operations
    // =========================================================================

    /// Retrieve a credential, resolving keychain values if storage_mode requires it.
    ///
    /// Returns `Err` if the entry has `storage_mode=keychain` but the keychain
    /// entry is missing or inaccessible. This surfaces real problems instead of
    /// silently returning an empty string.
    pub fn recall(&self, path: &str) -> DbResult<Option<VaultEntry>> {
        let mut entry = match self.db.get_entry(path)? {
            Some(e) => e,
            None => return Ok(None),
        };
        self.resolve_value(&mut entry)?;
        Ok(Some(entry))
    }

    /// Check if a credential exists (no value returned).
    pub fn exists(&self, path: &str) -> DbResult<bool> {
        Ok(self.db.get_entry(path)?.is_some())
    }

    /// Search credentials by keyword. Values are stripped.
    pub fn find(&self, query: &str, limit: i32) -> DbResult<Vec<VaultEntry>> {
        let mut entries = self.db.search_entries(query, limit)?;
        strip_values(&mut entries);
        Ok(entries)
    }

    /// List credentials with optional filters. Values are stripped.
    pub fn list(
        &self,
        service: Option<&str>,
        category: Option<&str>,
        prefix: Option<&str>,
    ) -> DbResult<Vec<VaultEntry>> {
        let mut entries = self.db.list_entries(service, category, prefix)?;
        strip_values(&mut entries);
        Ok(entries)
    }

    /// Get a bundle of credentials by prefix.
    /// Values are included only when `include_values` is true.
    ///
    /// Returns `(entries, unresolved_paths)` — entries have keychain values resolved
    /// where possible; unresolved_paths lists entries whose keychain values could not
    /// be retrieved (so the caller can warn).
    pub fn recall_bundle(
        &self,
        prefix: &str,
        include_values: bool,
    ) -> DbResult<(Vec<VaultEntry>, Vec<String>)> {
        let mut entries = self.db.list_entries(None, None, Some(prefix))?;
        let mut unresolved: Vec<String> = Vec::new();
        if include_values {
            for entry in entries.iter_mut() {
                if (entry.storage_mode == "keychain" || entry.storage_mode == "both")
                    && self.resolve_value(entry).is_err()
                {
                    unresolved.push(entry.path.clone());
                }
            }
        } else {
            strip_values(&mut entries);
        }
        Ok((entries, unresolved))
    }

    /// List recent credentials ordered by updated_at DESC. Values are stripped.
    pub fn recent(&self, limit: i32) -> DbResult<Vec<VaultEntry>> {
        let mut entries = self.db.list_entries(None, None, None)?;
        entries.sort_by(|a, b| {
            let a_ts = a.updated_at.as_deref().unwrap_or("");
            let b_ts = b.updated_at.as_deref().unwrap_or("");
            b_ts.cmp(a_ts)
        });
        entries.truncate(limit as usize);
        strip_values(&mut entries);
        Ok(entries)
    }

    /// List rotation candidates. Values are stripped.
    pub fn list_rotation_candidates(&self) -> DbResult<Vec<VaultEntry>> {
        let mut entries = self.db.list_rotation_candidates()?;
        strip_values(&mut entries);
        Ok(entries)
    }

    /// List entries with value hashes instead of plaintext values.
    /// Used by vault_changes which needs hash + length but not the actual value.
    ///
    /// Returns `(hashed_entries, unresolved_paths)` — unresolved_paths lists entries
    /// whose keychain values could not be retrieved (hashes for those entries will be
    /// based on the empty DB placeholder).
    pub fn list_with_hashes(
        &self,
        service: Option<&str>,
        category: Option<&str>,
        prefix: Option<&str>,
    ) -> DbResult<(Vec<HashedEntry>, Vec<String>)> {
        let entries = self.db.list_entries(service, category, prefix)?;
        let mut hashed = Vec::with_capacity(entries.len());
        let mut unresolved: Vec<String> = Vec::new();
        for mut e in entries {
            if (e.storage_mode == "keychain" || e.storage_mode == "both")
                && self.resolve_value(&mut e).is_err()
            {
                unresolved.push(e.path.clone());
            }
            let value_hash = crate::crypto::value_hash(&e.value);
            let value_length = e.value.len();
            hashed.push(HashedEntry {
                entry: VaultEntry {
                    value: String::new(),
                    ..e
                },
                value_hash,
                value_length,
            });
        }
        Ok((hashed, unresolved))
    }

    /// Export all credentials with plaintext values for backup purposes.
    ///
    /// Returns `(entries, unresolved_paths)` — entries have keychain values resolved
    /// where possible; unresolved_paths lists entries whose keychain values could not
    /// be retrieved (so the caller can warn).
    ///
    /// # Security
    /// This method returns raw values. Use only for export/backup operations.
    pub fn export_all(&self) -> DbResult<(Vec<VaultEntry>, Vec<String>)> {
        let mut entries = self.db.list_entries(None, None, None)?;
        let mut unresolved: Vec<String> = Vec::new();
        for entry in entries.iter_mut() {
            if (entry.storage_mode == "keychain" || entry.storage_mode == "both")
                && self.resolve_value(entry).is_err()
            {
                unresolved.push(entry.path.clone());
            }
        }
        Ok((entries, unresolved))
    }

    // =========================================================================
    // Delete Operations
    // =========================================================================

    /// Delete a credential, also removing from keyring if applicable.
    pub fn forget(&self, path: &str) -> DbResult<bool> {
        // Check storage_mode before deleting
        if let Some(entry) = self.db.get_entry(path)? {
            if entry.storage_mode == "keychain" || entry.storage_mode == "both" {
                let _ = delete_from_keyring(path);
            }
        }
        self.db.delete_entry(path)
    }
}

// =========================================================================
// Supporting Types
// =========================================================================

/// Input for batch remember operations.
pub struct BatchEntry<'a> {
    pub path: &'a str,
    pub value: &'a str,
    pub category: Option<&'a str>,
    pub service: Option<&'a str>,
    pub app: Option<&'a str>,
    pub env: Option<&'a str>,
    pub notes: Option<&'a str>,
    pub tags: Option<&'a [String]>,
    pub storage_mode: Option<&'a str>,
    pub expires_at: Option<&'a str>,
    pub rotation_interval_days: Option<i32>,
    pub related_apps: Option<&'a [String]>,
}

/// Result of a batch remember operation.
pub enum BatchResult {
    Ok(Box<VaultEntry>),
    Err(String, String), // (path, error_message)
}

/// A vault entry with its value replaced by a hash.
pub struct HashedEntry {
    pub entry: VaultEntry,
    pub value_hash: String,
    pub value_length: usize,
}

// =========================================================================
// Helpers
// =========================================================================

/// Strip values from a list of entries (set to empty string).
fn strip_values(entries: &mut [VaultEntry]) {
    for entry in entries.iter_mut() {
        entry.value = String::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_db(tmp: &TempDir) -> CrSqliteDatabase {
        let path = tmp.path().join("test.db");
        CrSqliteDatabase::open(&path, "test-passphrase", None).unwrap()
    }

    #[test]
    fn test_remember_recall_vault_mode() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let store = CredentialStore::new(&db);

        let entry = store
            .remember(
                "test/api/key",
                "secret-123",
                Some("api_key"),
                Some("test"),
                None,
                None,
                None,
                None,
                None, // default vault mode
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(entry.path, "test/api/key");
        assert_eq!(entry.value, "secret-123");

        let recalled = store.recall("test/api/key").unwrap().unwrap();
        assert_eq!(recalled.value, "secret-123");
    }

    #[test]
    fn test_forget() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let store = CredentialStore::new(&db);

        store
            .remember(
                "test/delete/me",
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

        assert!(store.forget("test/delete/me").unwrap());
        assert!(store.recall("test/delete/me").unwrap().is_none());
    }

    #[test]
    fn test_find_strips_values() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let store = CredentialStore::new(&db);

        store
            .remember(
                "api/openai/key",
                "sk-secret",
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

        let found = store.find("openai", 10).unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].value.is_empty(), "values must be stripped on find");
        assert_eq!(found[0].path, "api/openai/key");
    }

    #[test]
    fn test_list_strips_values() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let store = CredentialStore::new(&db);

        store
            .remember(
                "db/pass",
                "secret-pw",
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

        let listed = store.list(None, None, None).unwrap();
        assert_eq!(listed.len(), 1);
        assert!(
            listed[0].value.is_empty(),
            "values must be stripped on list"
        );
    }

    #[test]
    fn test_exists() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let store = CredentialStore::new(&db);

        assert!(!store.exists("nonexistent").unwrap());

        store
            .remember(
                "test/exists",
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

        assert!(store.exists("test/exists").unwrap());
    }

    #[test]
    fn test_recent_strips_values() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let store = CredentialStore::new(&db);

        store
            .remember(
                "a/key", "val1", None, None, None, None, None, None, None, None, None, None,
            )
            .unwrap();
        store
            .remember(
                "b/key", "val2", None, None, None, None, None, None, None, None, None, None,
            )
            .unwrap();

        let recent = store.recent(10).unwrap();
        assert_eq!(recent.len(), 2);
        for e in &recent {
            assert!(e.value.is_empty(), "values must be stripped on recent");
        }
    }

    #[test]
    fn test_recall_bundle_with_and_without_values() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let store = CredentialStore::new(&db);

        store
            .remember(
                "aws/key",
                "AKIA...",
                None,
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
        store
            .remember(
                "aws/secret",
                "wJa...",
                None,
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

        // Without values
        let (no_vals, unresolved) = store.recall_bundle("aws/", false).unwrap();
        assert_eq!(no_vals.len(), 2);
        assert!(unresolved.is_empty());
        for e in &no_vals {
            assert!(e.value.is_empty());
        }

        // With values
        let (with_vals, unresolved) = store.recall_bundle("aws/", true).unwrap();
        assert_eq!(with_vals.len(), 2);
        assert!(unresolved.is_empty());
        assert!(!with_vals[0].value.is_empty());
    }

    #[test]
    fn test_list_with_hashes() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let store = CredentialStore::new(&db);

        store
            .remember(
                "hash/test",
                "my-secret-value",
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

        let (hashed, unresolved) = store.list_with_hashes(None, None, None).unwrap();
        assert_eq!(hashed.len(), 1);
        assert!(unresolved.is_empty());
        assert!(hashed[0].entry.value.is_empty(), "value must be stripped");
        assert!(!hashed[0].value_hash.is_empty(), "hash must be present");
        assert_eq!(hashed[0].value_length, "my-secret-value".len());
    }

    #[test]
    fn test_remember_batch() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let store = CredentialStore::new(&db);

        let entries = vec![
            BatchEntry {
                path: "batch/a",
                value: "val-a",
                category: None,
                service: None,
                app: None,
                env: None,
                notes: None,
                tags: None,
                storage_mode: None,
                expires_at: None,
                rotation_interval_days: None,
                related_apps: None,
            },
            BatchEntry {
                path: "batch/b",
                value: "val-b",
                category: None,
                service: None,
                app: None,
                env: None,
                notes: None,
                tags: None,
                storage_mode: None,
                expires_at: None,
                rotation_interval_days: None,
                related_apps: None,
            },
        ];

        let results = store.remember_batch(&entries).unwrap();
        assert_eq!(results.len(), 2);
        for r in &results {
            assert!(matches!(r, BatchResult::Ok(_)));
        }

        // Verify both exist
        assert!(store.exists("batch/a").unwrap());
        assert!(store.exists("batch/b").unwrap());
    }

    #[test]
    fn test_export_all_includes_values() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let store = CredentialStore::new(&db);

        store
            .remember(
                "export/test",
                "secret-val",
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

        let (exported, unresolved) = store.export_all().unwrap();
        assert_eq!(exported.len(), 1);
        assert_eq!(
            exported[0].value, "secret-val",
            "export must include values"
        );
        assert!(
            unresolved.is_empty(),
            "vault-mode entries should not be unresolved"
        );
    }

    #[test]
    fn test_recall_bundle_with_values_resolves() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let store = CredentialStore::new(&db);

        store
            .remember(
                "svc/a",
                "val-a",
                None,
                Some("svc"),
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
        store
            .remember(
                "svc/b",
                "val-b",
                None,
                Some("svc"),
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

        // With values — vault-mode entries should have their values intact
        let (with_vals, unresolved) = store.recall_bundle("svc/", true).unwrap();
        assert_eq!(with_vals.len(), 2);
        assert!(unresolved.is_empty());
        for e in &with_vals {
            assert!(!e.value.is_empty(), "vault-mode values should be present");
        }

        // Without values — values should be stripped
        let (no_vals, unresolved) = store.recall_bundle("svc/", false).unwrap();
        assert!(unresolved.is_empty());
        for e in &no_vals {
            assert!(e.value.is_empty(), "values should be stripped");
        }
    }

    // =========================================================================
    // Keychain / Both Mode Tests
    // =========================================================================
    //
    // These tests exercise real OS keychain operations. They are ignored on
    // non-macOS platforms (CI Linux runners, etc.) and use a dedicated prefix
    // to avoid collisions with real vault data.

    /// Run a test closure with automatic keychain cleanup on success or panic.
    fn with_keychain_cleanup<F: FnOnce() + std::panic::UnwindSafe>(paths: &[&str], f: F) {
        let result = std::panic::catch_unwind(f);
        for path in paths {
            let _ = delete_from_keyring(path);
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore)]
    fn test_remember_recall_keychain_mode() {
        let path = "vault-core-test/cs/kc1";
        with_keychain_cleanup(&[path], || {
            let tmp = TempDir::new().unwrap();
            let db = test_db(&tmp);
            let store = CredentialStore::new(&db);

            let entry = store
                .remember(
                    path,
                    "kc-secret",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some("keychain"),
                    None,
                    None,
                    None,
                )
                .unwrap();
            assert_eq!(entry.value, "kc-secret");

            // recall() should return the keychain value
            let recalled = store.recall(path).unwrap().unwrap();
            assert_eq!(recalled.value, "kc-secret");

            // DB should have empty placeholder
            let db_entry = db.get_entry(path).unwrap().unwrap();
            assert!(
                db_entry.value.is_empty(),
                "DB should have empty placeholder for keychain mode"
            );
            assert_eq!(db_entry.storage_mode, "keychain");
        });
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore)]
    fn test_remember_recall_both_mode() {
        let path = "vault-core-test/cs/both1";
        with_keychain_cleanup(&[path], || {
            let tmp = TempDir::new().unwrap();
            let db = test_db(&tmp);
            let store = CredentialStore::new(&db);

            store
                .remember(
                    path,
                    "both-secret",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some("both"),
                    None,
                    None,
                    None,
                )
                .unwrap();

            // recall() returns the value
            let recalled = store.recall(path).unwrap().unwrap();
            assert_eq!(recalled.value, "both-secret");

            // Both keyring and DB should have the value
            let kv = get_from_keyring(path).unwrap();
            assert_eq!(kv, Some("both-secret".to_string()));

            let db_entry = db.get_entry(path).unwrap().unwrap();
            assert_eq!(db_entry.value, "both-secret");
            assert_eq!(db_entry.storage_mode, "both");
        });
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore)]
    fn test_recall_keychain_missing_returns_error() {
        let path = "vault-core-test/cs/missing1";
        // Ensure keychain is clean before the test
        let _ = delete_from_keyring(path);

        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let store = CredentialStore::new(&db);

        // Insert via raw DB with storage_mode="keychain" but no keychain write
        db.set_entry(
            path,
            "",
            None,
            None,
            None,
            None,
            None,
            None,
            Some("keychain"),
            None,
            None,
            None,
        )
        .unwrap();

        // recall() should return Err because keychain entry is missing
        let result = store.recall(path);
        assert!(
            result.is_err(),
            "recall should fail when keychain entry is missing"
        );
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore)]
    fn test_recall_bundle_mixed_modes_partial_failure() {
        let paths = [
            "vault-core-test/cs/mix/a",
            "vault-core-test/cs/mix/b",
            "vault-core-test/cs/mix/c",
        ];
        // Clean up keychain before test
        for p in &paths {
            let _ = delete_from_keyring(p);
        }

        with_keychain_cleanup(&paths, || {
            let tmp = TempDir::new().unwrap();
            let db = test_db(&tmp);
            let store = CredentialStore::new(&db);

            // mix/a: vault mode (normal)
            store
                .remember(
                    paths[0], "val-a", None, None, None, None, None, None, None, None, None, None,
                )
                .unwrap();

            // mix/b: keychain mode via store.remember (writes to keychain)
            store
                .remember(
                    paths[1],
                    "val-b",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some("keychain"),
                    None,
                    None,
                    None,
                )
                .unwrap();

            // mix/c: keychain mode via raw DB only (no keychain write — simulates missing)
            db.set_entry(
                paths[2],
                "",
                None,
                None,
                None,
                None,
                None,
                None,
                Some("keychain"),
                None,
                None,
                None,
            )
            .unwrap();

            let (entries, unresolved) = store
                .recall_bundle("vault-core-test/cs/mix/", true)
                .unwrap();

            assert_eq!(entries.len(), 3);
            assert_eq!(unresolved.len(), 1);
            assert_eq!(unresolved[0], paths[2]);

            // Verify resolved values
            let a = entries.iter().find(|e| e.path == paths[0]).unwrap();
            assert_eq!(a.value, "val-a");

            let b = entries.iter().find(|e| e.path == paths[1]).unwrap();
            assert_eq!(b.value, "val-b");
        });
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore)]
    fn test_export_all_with_keychain_entries() {
        let path = "vault-core-test/cs/export1";
        with_keychain_cleanup(&[path], || {
            let tmp = TempDir::new().unwrap();
            let db = test_db(&tmp);
            let store = CredentialStore::new(&db);

            store
                .remember(
                    path,
                    "export-kc-val",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some("keychain"),
                    None,
                    None,
                    None,
                )
                .unwrap();

            let (exported, unresolved) = store.export_all().unwrap();
            assert!(unresolved.is_empty(), "keychain entry should be resolved");

            let entry = exported.iter().find(|e| e.path == path).unwrap();
            assert_eq!(entry.value, "export-kc-val");
        });
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore)]
    fn test_forget_keychain_mode_cleans_keychain() {
        let path = "vault-core-test/cs/forget1";
        with_keychain_cleanup(&[path], || {
            let tmp = TempDir::new().unwrap();
            let db = test_db(&tmp);
            let store = CredentialStore::new(&db);

            store
                .remember(
                    path,
                    "forget-me",
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some("keychain"),
                    None,
                    None,
                    None,
                )
                .unwrap();

            // Keychain should have the value
            assert!(get_from_keyring(path).unwrap().is_some());

            // forget() should clean both DB and keychain
            assert!(store.forget(path).unwrap());

            assert!(get_from_keyring(path).unwrap().is_none());
            assert!(store.recall(path).unwrap().is_none());
        });
    }
}
