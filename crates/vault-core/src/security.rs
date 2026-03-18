//! Security utilities: audit logging, value masking, machine identity.

use chrono::Utc;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;

use crate::config;

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Audit logger that records all vault access to a separate SQLite database.
pub struct AuditLogger {
    conn: Connection,
}

impl AuditLogger {
    /// Open or create the audit log database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SecurityError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                path TEXT,
                machine_id TEXT,
                details TEXT,
                tool_name TEXT,
                success INTEGER DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_path ON audit_log(path);
            CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
            PRAGMA journal_mode=WAL;",
        )?;

        Ok(Self { conn })
    }

    /// Open the default audit log.
    pub fn open_default() -> Result<Self, SecurityError> {
        Self::open(config::audit_db_path())
    }

    /// Log an access event.
    pub fn log(
        &self,
        action: &str,
        path: Option<&str>,
        machine_id: Option<&str>,
        details: Option<&str>,
        tool_name: Option<&str>,
        success: bool,
    ) -> Result<(), SecurityError> {
        let machine_id = machine_id.map(redact_machine_id);
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO audit_log (timestamp, action, path, machine_id, details, tool_name, success)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![now, action, path, machine_id, details, tool_name, success as i32],
        )?;
        Ok(())
    }

    /// Query audit log entries with optional filters.
    pub fn list(
        &self,
        path: Option<&str>,
        action: Option<&str>,
        limit: i32,
    ) -> Result<Vec<AuditEntry>, SecurityError> {
        let mut sql = "SELECT * FROM audit_log WHERE 1=1".to_string();
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(p) = path {
            if p.contains('%') {
                sql.push_str(" AND path LIKE ?");
            } else {
                sql.push_str(" AND path = ?");
            }
            param_values.push(Box::new(p.to_string()));
        }
        if let Some(a) = action {
            sql.push_str(" AND action = ?");
            param_values.push(Box::new(a.to_string()));
        }
        sql.push_str(" ORDER BY timestamp DESC LIMIT ?");
        param_values.push(Box::new(limit));

        let mut stmt = self.conn.prepare(&sql)?;
        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();

        let rows = stmt.query_map(params_ref.as_slice(), |row| {
            Ok(AuditEntry {
                id: row.get("id")?,
                timestamp: row.get("timestamp")?,
                action: row.get("action")?,
                path: row.get("path")?,
                machine_id: row.get("machine_id")?,
                details: row.get("details")?,
                tool_name: row.get("tool_name")?,
                success: row.get::<_, i32>("success")? != 0,
            })
        })?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    /// Clear old audit entries.
    pub fn clear_before(&self, before_timestamp: &str) -> Result<i32, SecurityError> {
        let count = self.conn.execute(
            "DELETE FROM audit_log WHERE timestamp < ?1",
            params![before_timestamp],
        )?;
        Ok(count as i32)
    }
}

/// A single audit log entry.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: i64,
    pub timestamp: String,
    pub action: String,
    pub path: Option<String>,
    pub machine_id: Option<String>,
    pub details: Option<String>,
    pub tool_name: Option<String>,
    pub success: bool,
}

/// Mask a secret value for display purposes.
///
/// Examples:
/// - `"sk-abc123xyz789"` → `"sk-a****z789"`
/// - `"short"` → `"*****"`
/// - `""` → `""`
pub fn mask_value(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }

    let len = value.len();
    if len <= 4 {
        return "*".repeat(len);
    }

    // Check for common prefixes (sk-, pk-, ghp_, etc.)
    let prefix_end = if let Some(idx) = value.find('-') {
        if idx <= 4 {
            idx + 1
        } else {
            0
        }
    } else if let Some(idx) = value.find('_') {
        if idx <= 4 {
            idx + 1
        } else {
            0
        }
    } else {
        0
    };

    if prefix_end > 0 && len > prefix_end + 5 {
        // Show prefix + first char + **** + last 4 chars
        let prefix = &value[..prefix_end];
        let first = &value[prefix_end..prefix_end + 1];
        let last4 = &value[len - 4..];
        format!("{prefix}{first}****{last4}")
    } else if len > 8 {
        // Show first 2 + **** + last 4
        format!("{}****{}", &value[..2], &value[len - 4..])
    } else {
        "*".repeat(len)
    }
}

/// Get the machine ID for audit logging.
pub fn machine_id() -> String {
    config::get_local_machine_id()
}

/// Redact machine identity fields at audit level to reduce exposure of stable host IDs.
///
/// Redaction is enabled by default and can be disabled for advanced debugging
/// by setting `VAULT_AUDIT_LOG_RAW_MACHINE_ID=1`.
pub fn redact_machine_id(machine_id: &str) -> String {
    if std::env::var("VAULT_AUDIT_LOG_RAW_MACHINE_ID").as_deref() == Ok("1") {
        return machine_id.to_string();
    }

    let digest = Sha256::digest(machine_id.as_bytes());
    format!(
        "machine:{}",
        digest
            .iter()
            .take(12)
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_mask_value_formats() {
        // Common API key formats
        assert_eq!(mask_value("sk-abc123xyz789"), "sk-a****z789");
        assert_eq!(mask_value("pk-test12345678"), "pk-t****5678");

        // Short strings
        assert_eq!(mask_value("abc"), "***");
        assert_eq!(mask_value("abcd"), "****");
        assert_eq!(mask_value(""), "");

        // Longer strings without prefix
        assert_eq!(mask_value("mysecretpassword"), "my****word");

        // Medium length
        assert_eq!(mask_value("12345678"), "********");
    }

    #[test]
    fn test_audit_logger() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("audit.db");
        let logger = AuditLogger::open(&path).unwrap();

        // Log events
        logger
            .log(
                "get",
                Some("api/openai/key"),
                Some("100.1.2.3"),
                None,
                Some("vault_get"),
                true,
            )
            .unwrap();
        logger
            .log(
                "set",
                Some("api/test/key"),
                Some("100.1.2.3"),
                None,
                Some("vault_set"),
                true,
            )
            .unwrap();
        logger
            .log(
                "delete",
                Some("api/old/key"),
                Some("100.1.2.3"),
                None,
                Some("vault_delete"),
                true,
            )
            .unwrap();

        // Query all
        let all = logger.list(None, None, 50).unwrap();
        assert_eq!(all.len(), 3);

        // Query by path
        let by_path = logger.list(Some("api/openai/key"), None, 50).unwrap();
        assert_eq!(by_path.len(), 1);

        // Query by action
        let by_action = logger.list(None, Some("get"), 50).unwrap();
        assert_eq!(by_action.len(), 1);

        // Query with limit
        let limited = logger.list(None, None, 2).unwrap();
        assert_eq!(limited.len(), 2);

        // Query with wildcard path
        let wildcard = logger.list(Some("api/%"), None, 50).unwrap();
        assert_eq!(wildcard.len(), 3);
    }
}
