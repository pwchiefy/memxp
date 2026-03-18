//! Agent Task and Messaging System.
//!
//! Provides secure, P2P-synced communication between agents across machines.
//! Tasks and messages sync automatically via cr-sqlite CRDTs.
//!
//! NOTE: This module is kept for migration compatibility only and is not part of
//! the public VaultP2P API surface.

#![allow(deprecated, dead_code)]

use chrono::Utc;
use rusqlite::params;
use uuid::Uuid;

use crate::config;
use crate::db::{CrSqliteDatabase, DbResult};
use crate::models::AgentTask;

/// Manages agent tasks using the vault database.
#[deprecated(
    note = "Agent/task messaging is deprecated in the public VaultP2P surface. Keep for migration compatibility only."
)]
pub struct AgentTaskManager<'a> {
    db: &'a CrSqliteDatabase,
}

#[deprecated(
    note = "Agent/task messaging is deprecated in the public VaultP2P surface. Use only for legacy compatibility."
)]
impl<'a> AgentTaskManager<'a> {
    /// Create a new AgentTaskManager wrapping a database.
    pub fn new(db: &'a CrSqliteDatabase) -> Self {
        Self { db }
    }

    // =========================================================================
    // Task Creation
    // =========================================================================

    /// Maximum title length in bytes.
    const MAX_TITLE_LEN: usize = 200;
    /// Maximum description/content length in bytes (10 KB).
    const MAX_DESCRIPTION_LEN: usize = 10 * 1024;

    /// Create a new task for another agent.
    ///
    /// # Arguments
    /// - `title`: Short task title (max 200 chars)
    /// - `to_machine`: Target machine IP or `"*"` for broadcast
    /// - `description`: Detailed task description (max 10 KB)
    /// - `priority`: Task priority (0=critical, 4=backlog)
    /// - `tags`: Optional tags for filtering
    /// - `reply_to`: Optional task ID this is a reply to
    pub fn create_task(
        &self,
        title: &str,
        to_machine: &str,
        description: &str,
        priority: i32,
        tags: &[String],
        reply_to: Option<&str>,
    ) -> DbResult<AgentTask> {
        // Enforce content length limits
        if title.len() > Self::MAX_TITLE_LEN {
            return Err(crate::db::DbError::Other(format!(
                "Title too long: {} bytes (max {})",
                title.len(),
                Self::MAX_TITLE_LEN
            )));
        }
        if description.len() > Self::MAX_DESCRIPTION_LEN {
            return Err(crate::db::DbError::Other(format!(
                "Description too long: {} bytes (max {})",
                description.len(),
                Self::MAX_DESCRIPTION_LEN
            )));
        }

        let id = Uuid::new_v4().to_string()[..8].to_string();
        let now = Utc::now().to_rfc3339();
        let from_machine = config::get_local_machine_id();
        let tags_json = serde_json::to_string(tags).unwrap_or_else(|_| "[]".to_string());

        self.db.conn().execute(
            "INSERT INTO agent_tasks (
                id, title, from_machine, to_machine, status, priority,
                description, result, created_at, updated_at, claimed_by, tags, reply_to
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                id,
                title,
                from_machine,
                to_machine,
                "pending",
                priority,
                description,
                "",
                now,
                now,
                Option::<String>::None,
                tags_json,
                reply_to,
            ],
        )?;

        Ok(AgentTask {
            id,
            title: title.to_string(),
            from_machine,
            to_machine: to_machine.to_string(),
            status: "pending".to_string(),
            priority,
            description: description.to_string(),
            result: String::new(),
            created_at: Some(now.clone()),
            updated_at: Some(now),
            completed_at: None,
            claimed_by: None,
            tags: tags.to_vec(),
            reply_to: reply_to.map(|s| s.to_string()),
        })
    }

    /// Send a message to another agent (shorthand for create_task with "message" tag).
    pub fn send_message(
        &self,
        to_machine: &str,
        content: &str,
        priority: i32,
        subject: Option<&str>,
    ) -> DbResult<AgentTask> {
        let from = config::get_local_machine_id();
        let title = subject
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("Message from {from}"));

        self.create_task(
            &title,
            to_machine,
            content,
            priority,
            &["message".to_string()],
            None,
        )
    }

    /// Broadcast a message to all agents.
    pub fn broadcast(&self, message: &str, priority: i32) -> DbResult<AgentTask> {
        self.send_message("*", message, priority, None)
    }

    // =========================================================================
    // Task Queries
    // =========================================================================

    /// Get a task by ID.
    pub fn get_task(&self, task_id: &str) -> DbResult<Option<AgentTask>> {
        let result = self.db.conn().query_row(
            "SELECT * FROM agent_tasks WHERE id = ?1",
            params![task_id],
            row_to_task,
        );

        match result {
            Ok(t) => Ok(Some(t)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get tasks assigned to this machine (excludes messages).
    pub fn get_my_tasks(&self, include_completed: bool) -> DbResult<Vec<AgentTask>> {
        let my_ip = config::get_local_machine_id();

        let sql = if include_completed {
            "SELECT * FROM agent_tasks
             WHERE (to_machine = ?1 OR to_machine = '*')
               AND tags NOT LIKE '%\"message\"%'
             ORDER BY priority ASC, created_at DESC"
        } else {
            "SELECT * FROM agent_tasks
             WHERE (to_machine = ?1 OR to_machine = '*')
               AND status IN ('pending', 'in_progress')
               AND tags NOT LIKE '%\"message\"%'
             ORDER BY priority ASC, created_at DESC"
        };

        let mut stmt = self.db.conn().prepare(sql)?;
        let rows = stmt.query_map(params![my_ip], row_to_task)?;
        let mut tasks = Vec::new();
        for row in rows {
            tasks.push(row?);
        }
        Ok(tasks)
    }

    /// Get messages assigned to this machine.
    pub fn get_my_messages(&self, include_read: bool, limit: i32) -> DbResult<Vec<AgentTask>> {
        let my_ip = config::get_local_machine_id();

        let sql = if include_read {
            "SELECT * FROM agent_tasks
             WHERE (to_machine = ?1 OR to_machine = '*')
               AND tags LIKE '%\"message\"%'
             ORDER BY created_at DESC LIMIT ?2"
        } else {
            "SELECT * FROM agent_tasks
             WHERE (to_machine = ?1 OR to_machine = '*')
               AND tags LIKE '%\"message\"%'
               AND (status = 'pending' OR status = 'in_progress')
             ORDER BY created_at DESC LIMIT ?2"
        };

        let mut stmt = self.db.conn().prepare(sql)?;
        let rows = stmt.query_map(params![my_ip, limit], row_to_task)?;
        let mut msgs = Vec::new();
        for row in rows {
            msgs.push(row?);
        }
        Ok(msgs)
    }

    // =========================================================================
    // Task Lifecycle
    // =========================================================================

    /// Claim a task (mark as in_progress).
    pub fn claim_task(&self, task_id: &str) -> DbResult<Option<AgentTask>> {
        let my_ip = config::get_local_machine_id();
        let now = Utc::now().to_rfc3339();

        self.db.conn().execute(
            "UPDATE agent_tasks
             SET status = 'in_progress', claimed_by = ?1, updated_at = ?2
             WHERE id = ?3 AND status = 'pending'",
            params![my_ip, now, task_id],
        )?;

        self.get_task(task_id)
    }

    /// Mark a task as completed, optionally sending a notification to the originator.
    ///
    /// Returns `(updated_task, notification_task)`. The notification is `None`
    /// if `notify` is false or the task originated from this machine.
    pub fn complete_task(
        &self,
        task_id: &str,
        result: &str,
        notify: bool,
    ) -> DbResult<(Option<AgentTask>, Option<AgentTask>)> {
        // Get task before updating to know who to notify
        let task = match self.get_task(task_id)? {
            Some(t) => t,
            None => return Ok((None, None)),
        };

        let now = Utc::now().to_rfc3339();
        self.db.conn().execute(
            "UPDATE agent_tasks
             SET status = 'completed', result = ?1, updated_at = ?2, completed_at = ?2
             WHERE id = ?3",
            params![result, now, task_id],
        )?;

        // Auto-notify originator
        let notification = if notify {
            let my_machine = config::get_local_machine_id();
            if !task.from_machine.is_empty() && task.from_machine != my_machine {
                let notif_title = format!("Task completed: {}", task.title);
                let notif_body = format!(
                    "Task \"{}\" (ID: {}) has been completed.\n\nResult: {}",
                    task.title,
                    task.id,
                    if result.is_empty() {
                        "(no result provided)"
                    } else {
                        result
                    }
                );
                Some(self.create_task(
                    &notif_title,
                    &task.from_machine,
                    &notif_body,
                    2, // medium priority
                    &["message".to_string(), "completion_notification".to_string()],
                    Some(&task.id),
                )?)
            } else {
                None
            }
        } else {
            None
        };

        Ok((self.get_task(task_id)?, notification))
    }

    /// Mark a task as failed.
    pub fn fail_task(&self, task_id: &str, error: &str) -> DbResult<Option<AgentTask>> {
        let now = Utc::now().to_rfc3339();
        self.db.conn().execute(
            "UPDATE agent_tasks
             SET status = 'failed', result = ?1, updated_at = ?2
             WHERE id = ?3",
            params![error, now, task_id],
        )?;
        self.get_task(task_id)
    }

    /// Mark a message as read (completed).
    pub fn mark_message_read(&self, task_id: &str) -> DbResult<Option<AgentTask>> {
        let now = Utc::now().to_rfc3339();
        self.db.conn().execute(
            "UPDATE agent_tasks
             SET status = 'completed', updated_at = ?1
             WHERE id = ?2",
            params![now, task_id],
        )?;
        self.get_task(task_id)
    }
}

// =========================================================================
// Row conversion
// =========================================================================

fn row_to_task(row: &rusqlite::Row) -> rusqlite::Result<AgentTask> {
    let tags_json: String = row
        .get::<_, Option<String>>("tags")?
        .unwrap_or_else(|| "[]".to_string());
    let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();

    Ok(AgentTask {
        id: row.get("id")?,
        title: row.get::<_, Option<String>>("title")?.unwrap_or_default(),
        from_machine: row
            .get::<_, Option<String>>("from_machine")?
            .unwrap_or_default(),
        to_machine: row
            .get::<_, Option<String>>("to_machine")?
            .unwrap_or_else(|| "*".to_string()),
        status: row
            .get::<_, Option<String>>("status")?
            .unwrap_or_else(|| "pending".to_string()),
        priority: row.get::<_, Option<i32>>("priority")?.unwrap_or(2),
        description: row
            .get::<_, Option<String>>("description")?
            .unwrap_or_default(),
        result: row.get::<_, Option<String>>("result")?.unwrap_or_default(),
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
        completed_at: row.get("completed_at").unwrap_or(None),
        claimed_by: row.get("claimed_by").unwrap_or(None),
        tags,
        reply_to: row.get("reply_to").unwrap_or(None),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_db(tmp: &TempDir) -> CrSqliteDatabase {
        let path = tmp.path().join("task_test.db");
        CrSqliteDatabase::open(&path, "test-passphrase", None).unwrap()
    }

    #[test]
    fn test_task_create_claim_complete() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let mgr = AgentTaskManager::new(&db);

        // Create
        let task = mgr
            .create_task(
                "Build feature X",
                "100.1.2.3",
                "Detailed desc",
                2,
                &[],
                None,
            )
            .unwrap();
        assert_eq!(task.status, "pending");
        assert_eq!(task.title, "Build feature X");

        // Get
        let got = mgr.get_task(&task.id).unwrap().unwrap();
        assert_eq!(got.id, task.id);
        assert_eq!(got.description, "Detailed desc");

        // Claim
        let claimed = mgr.claim_task(&task.id).unwrap().unwrap();
        assert_eq!(claimed.status, "in_progress");
        assert!(claimed.claimed_by.is_some());

        // Complete (no notify since from_machine == local)
        let (completed, notification) = mgr.complete_task(&task.id, "Done!", false).unwrap();
        let completed = completed.unwrap();
        assert_eq!(completed.status, "completed");
        assert_eq!(completed.result, "Done!");
        assert!(notification.is_none());
    }

    #[test]
    fn test_task_completion_notification() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let mgr = AgentTaskManager::new(&db);

        // Create task from a "different" machine
        let now = Utc::now().to_rfc3339();
        let tags_json = "[]";
        db.conn()
            .execute(
                "INSERT INTO agent_tasks (id, title, from_machine, to_machine, status, priority,
                description, result, created_at, updated_at, tags)
             VALUES ('notif-001', 'Remote task', '100.99.99.99', '*', 'pending', 2,
                'Do something', '', ?1, ?1, ?2)",
                params![now, tags_json],
            )
            .unwrap();

        // Complete with notify=true
        let (completed, notification) = mgr.complete_task("notif-001", "All done", true).unwrap();
        assert!(completed.is_some());
        assert_eq!(completed.unwrap().status, "completed");

        // Should have created a notification task back to 100.99.99.99
        let notif = notification.unwrap();
        assert_eq!(notif.to_machine, "100.99.99.99");
        assert!(notif.title.contains("Task completed"));
        assert!(notif.tags.contains(&"completion_notification".to_string()));
        assert_eq!(notif.reply_to.as_deref(), Some("notif-001"));
    }

    #[test]
    fn test_message_send_read() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let mgr = AgentTaskManager::new(&db);

        // Send message
        let msg = mgr
            .send_message("100.5.6.7", "Hello from tests", 2, Some("Test subject"))
            .unwrap();
        assert!(msg.tags.contains(&"message".to_string()));
        assert_eq!(msg.title, "Test subject");

        // Get messages (for this machine, so we need to send to * or our IP)
        let msg2 = mgr.send_message("*", "Broadcast hello", 3, None).unwrap();
        assert!(msg2.title.contains("Message from"));

        // Read messages
        let messages = mgr.get_my_messages(false, 10).unwrap();
        // Should include broadcast
        assert!(!messages.is_empty());

        // Mark as read
        let read = mgr.mark_message_read(&msg2.id).unwrap().unwrap();
        assert_eq!(read.status, "completed");
    }

    #[test]
    fn test_task_machine_filtering() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let mgr = AgentTaskManager::new(&db);

        // Create task to specific machine
        let now = Utc::now().to_rfc3339();
        db.conn()
            .execute(
                "INSERT INTO agent_tasks (id, title, from_machine, to_machine, status, priority,
                description, result, created_at, updated_at, tags)
             VALUES ('filter-001', 'Specific task', '100.1.1.1', '100.4.5.6', 'pending', 2,
                '', '', ?1, ?1, '[]')",
                params![now],
            )
            .unwrap();

        // Create broadcast task
        mgr.create_task("Broadcast task", "*", "", 2, &[], None)
            .unwrap();

        // Our machine's tasks should include broadcast but not the specific one
        // (unless our machine_id matches)
        let my_tasks = mgr.get_my_tasks(false).unwrap();

        // Broadcast is always visible
        let broadcast_found = my_tasks.iter().any(|t| t.title == "Broadcast task");
        assert!(broadcast_found);

        // The specific task to 100.4.5.6 should only be visible if that's our IP
        let my_ip = config::get_local_machine_id();
        let specific_found = my_tasks.iter().any(|t| t.title == "Specific task");
        if my_ip == "100.4.5.6" {
            assert!(specific_found);
        } else {
            assert!(!specific_found);
        }
    }

    #[test]
    fn test_task_fail() {
        let tmp = TempDir::new().unwrap();
        let db = test_db(&tmp);
        let mgr = AgentTaskManager::new(&db);

        let task = mgr
            .create_task("Failing task", "*", "", 2, &[], None)
            .unwrap();

        let failed = mgr
            .fail_task(&task.id, "Something went wrong")
            .unwrap()
            .unwrap();
        assert_eq!(failed.status, "failed");
        assert_eq!(failed.result, "Something went wrong");
    }
}
