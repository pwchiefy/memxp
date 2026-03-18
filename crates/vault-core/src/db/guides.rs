//! Vault guide CRUD operations.

use chrono::Utc;
use rusqlite::params;

use super::{parse_csv, CrSqliteDatabase, DbResult};
use crate::models::VaultGuide;

impl CrSqliteDatabase {
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
}

// =========================================================================
// Row conversion helper
// =========================================================================

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

#[cfg(test)]
mod tests {
    use crate::db::CrSqliteDatabase;
    use tempfile::TempDir;

    fn test_db(tmp: &TempDir) -> CrSqliteDatabase {
        let path = tmp.path().join("test.db");
        CrSqliteDatabase::open(&path, "test-passphrase", None).unwrap()
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
}
