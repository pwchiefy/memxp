//! Vault entry (credential) CRUD operations.

use chrono::Utc;
use rusqlite::params;

use super::{parse_csv, CrSqliteDatabase, DbResult};
use crate::models::VaultEntry;

impl CrSqliteDatabase {
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
}

// =========================================================================
// Row conversion helper
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

#[cfg(test)]
mod tests {
    use crate::db::CrSqliteDatabase;
    use tempfile::TempDir;

    fn test_db(tmp: &TempDir) -> CrSqliteDatabase {
        let path = tmp.path().join("test.db");
        CrSqliteDatabase::open(&path, "test-passphrase", None).unwrap()
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
}
