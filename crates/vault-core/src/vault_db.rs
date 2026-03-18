//! High-level vault database with keyring integration.
//!
//! VaultDB wraps CrSqliteDatabase and adds:
//! - Keychain storage mode support (vault, keychain, both)
//! - Statistics and discovery operations
//! - Recent entries

use std::collections::HashMap;
use std::path::Path;

use crate::db::{CrSqliteDatabase, DbError, DbResult};
use crate::keyring_backend::{delete_from_keyring, get_from_keyring, set_in_keyring};
use crate::models::VaultEntry;

/// High-level vault database with keyring integration.
pub struct VaultDB {
    db: CrSqliteDatabase,
}

impl VaultDB {
    /// Open a VaultDB with encryption.
    pub fn open(
        db_path: impl AsRef<Path>,
        passphrase: &str,
        extension_path: Option<&Path>,
    ) -> DbResult<Self> {
        let db = CrSqliteDatabase::open(db_path, passphrase, extension_path)?;
        Ok(Self { db })
    }

    /// Get the underlying database reference.
    pub fn db(&self) -> &CrSqliteDatabase {
        &self.db
    }

    /// Get the underlying database mutable reference.
    pub fn db_mut(&mut self) -> &mut CrSqliteDatabase {
        &mut self.db
    }

    // =========================================================================
    // CRUD with Keychain Integration
    // =========================================================================

    /// Get a vault entry, respecting storage_mode.
    pub fn get(&self, path: &str) -> DbResult<Option<VaultEntry>> {
        let mut entry = match self.db.get_entry(path)? {
            Some(e) => e,
            None => return Ok(None),
        };

        match entry.storage_mode.as_str() {
            "keychain" => {
                // Value only in keychain
                entry.value = get_from_keyring(path).ok().flatten().unwrap_or_default();
            }
            "both" => {
                // Prefer keychain, fallback to DB
                if let Ok(Some(kv)) = get_from_keyring(path) {
                    entry.value = kv;
                }
            }
            _ => {} // "vault" — value already from DB
        }

        Ok(Some(entry))
    }

    /// Set a vault entry, respecting storage_mode.
    #[allow(clippy::too_many_arguments)]
    pub fn set(
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

        // Determine what value to store in DB
        let db_value = match sm {
            "keychain" => {
                // Store in keychain only
                set_in_keyring(path, value)
                    .map_err(|e| DbError::Other(format!("keyring error: {e}")))?;
                "" // Empty placeholder in DB
            }
            "both" => {
                // Store in both
                set_in_keyring(path, value)
                    .map_err(|e| DbError::Other(format!("keyring error: {e}")))?;
                value
            }
            _ => value,
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

    /// Delete a vault entry, also removing from keyring if applicable.
    pub fn delete(&self, path: &str) -> DbResult<bool> {
        // Check storage_mode before deleting
        if let Some(entry) = self.db.get_entry(path)? {
            if entry.storage_mode == "keychain" || entry.storage_mode == "both" {
                let _ = delete_from_keyring(path);
            }
        }
        self.db.delete_entry(path)
    }

    /// List vault entries.
    pub fn list(
        &self,
        category: Option<&str>,
        service: Option<&str>,
        prefix: Option<&str>,
    ) -> DbResult<Vec<VaultEntry>> {
        self.db.list_entries(service, category, prefix)
    }

    /// Search vault entries.
    pub fn search(&self, query: &str, limit: i32) -> DbResult<Vec<VaultEntry>> {
        self.db.search_entries(query, limit)
    }

    /// Get recent entries ordered by created_at DESC.
    pub fn recent(&self, limit: i32) -> DbResult<Vec<VaultEntry>> {
        let mut entries = self.db.list_entries(None, None, None)?;
        entries.sort_by(|a, b| {
            b.created_at
                .as_deref()
                .unwrap_or("")
                .cmp(a.created_at.as_deref().unwrap_or(""))
        });
        entries.truncate(limit as usize);
        Ok(entries)
    }

    /// Get vault statistics.
    pub fn get_stats(&self) -> DbResult<VaultStats> {
        let entries = self.db.list_entries(None, None, None)?;

        let mut categories: HashMap<String, usize> = HashMap::new();
        let mut services: HashMap<String, usize> = HashMap::new();

        for entry in &entries {
            *categories.entry(entry.category.clone()).or_insert(0) += 1;
            if let Some(ref svc) = entry.service {
                *services.entry(svc.clone()).or_insert(0) += 1;
            }
        }

        Ok(VaultStats {
            total_entries: entries.len(),
            categories,
            services,
        })
    }

    /// Close the database.
    pub fn close(self) -> DbResult<()> {
        self.db.close()
    }
}

/// Vault statistics.
#[derive(Debug, Clone)]
pub struct VaultStats {
    pub total_entries: usize,
    pub categories: HashMap<String, usize>,
    pub services: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_vault(tmp: &TempDir) -> VaultDB {
        let path = tmp.path().join("vault.db");
        VaultDB::open(&path, "test-key", None).unwrap()
    }

    #[test]
    fn test_vaultdb_basic_crud() {
        let tmp = TempDir::new().unwrap();
        let vault = test_vault(&tmp);

        // Set
        let entry = vault
            .set(
                "api/test/key",
                "secret-value",
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
        assert_eq!(entry.path, "api/test/key");

        // Get
        let got = vault.get("api/test/key").unwrap().unwrap();
        assert_eq!(got.value, "secret-value");

        // Delete
        assert!(vault.delete("api/test/key").unwrap());
    }

    #[test]
    fn test_vaultdb_stats() {
        let tmp = TempDir::new().unwrap();
        let vault = test_vault(&tmp);

        vault
            .set(
                "api/key1",
                "v1",
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
        vault
            .set(
                "api/key2",
                "v2",
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
        vault
            .set(
                "db/pass",
                "v3",
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

        let stats = vault.get_stats().unwrap();
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.categories.get("api_key"), Some(&2));
        assert_eq!(stats.categories.get("password"), Some(&1));
        assert_eq!(stats.services.get("openai"), Some(&2));
        assert_eq!(stats.services.get("postgres"), Some(&1));
    }
}
