use serde::{Deserialize, Serialize};

/// A single vault entry storing a credential or configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub path: String,
    #[serde(default)]
    pub value: String,
    #[serde(default = "default_category")]
    pub category: String,
    pub service: Option<String>,
    pub app: Option<String>,
    pub env: Option<String>,
    pub notes: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_storage_mode")]
    pub storage_mode: String,
    pub expires_at: Option<String>,
    pub rotation_interval_days: Option<i32>,
    #[serde(default)]
    pub related_apps: Vec<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

fn default_category() -> String {
    "env_var".to_string()
}

fn default_storage_mode() -> String {
    "vault".to_string()
}

impl VaultEntry {
    pub fn new(path: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            value: value.into(),
            category: "env_var".to_string(),
            service: None,
            app: None,
            env: None,
            notes: None,
            tags: Vec::new(),
            storage_mode: "vault".to_string(),
            expires_at: None,
            rotation_interval_days: None,
            related_apps: Vec::new(),
            created_at: None,
            updated_at: None,
        }
    }
}

/// A vault guide for operational procedures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultGuide {
    pub name: String,
    #[serde(default)]
    pub content: String,
    #[serde(default = "default_guide_category")]
    pub category: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_version")]
    pub version: i32,
    #[serde(default = "default_status")]
    pub status: String,
    pub verified_at: Option<String>,
    #[serde(default)]
    pub related_paths: Vec<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

fn default_guide_category() -> String {
    "procedure".to_string()
}

fn default_version() -> i32 {
    1
}

fn default_status() -> String {
    "active".to_string()
}

impl VaultGuide {
    pub fn new(name: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            content: content.into(),
            category: "procedure".to_string(),
            tags: Vec::new(),
            version: 1,
            status: "active".to_string(),
            verified_at: None,
            related_paths: Vec::new(),
            created_at: None,
            updated_at: None,
        }
    }
}

/// A single change record from cr-sqlite's crsql_changes table.
#[derive(Debug, Clone)]
pub struct SyncChange {
    pub table: String,
    pub pk: Vec<u8>,
    pub cid: String,
    pub val: Option<rusqlite::types::Value>,
    pub col_version: i64,
    pub db_version: i64,
    pub site_id: Option<Vec<u8>>,
    pub cl: i64,
    pub seq: i64,
}

/// Status of an agent task.
/// This type is retained for migration and archive readability and is no longer
/// used by active sync or MCP runtime operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[deprecated(
    note = "Agent/task messaging is deprecated in this public surface. Use only for legacy compatibility."
)]
pub enum TaskStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

#[allow(deprecated)]
impl TaskStatus {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Pending => "pending",
            Self::InProgress => "in_progress",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "pending" => Self::Pending,
            "in_progress" => Self::InProgress,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            _ => Self::Pending,
        }
    }
}

/// Priority of an agent task.
/// Kept for backward compatibility with legacy data and local archives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[deprecated(
    note = "Agent/task messaging is deprecated in this public surface. Use only for legacy compatibility."
)]
pub enum TaskPriority {
    Critical = 0,
    High = 1,
    Medium = 2,
    Low = 3,
    Backlog = 4,
}

#[allow(deprecated)]
impl TaskPriority {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Critical,
            1 => Self::High,
            2 => Self::Medium,
            3 => Self::Low,
            4 => Self::Backlog,
            _ => Self::Medium,
        }
    }

    pub fn as_i32(&self) -> i32 {
        *self as i32
    }
}

/// An agent task or message for legacy inter-agent communication.
/// This type is preserved for read compatibility with existing `agent_tasks` rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[deprecated(
    note = "Agent/task messaging is deprecated in this public surface. Use only for legacy compatibility."
)]
pub struct AgentTask {
    pub id: String,
    pub title: String,
    pub from_machine: String,
    pub to_machine: String,
    pub status: String,
    pub priority: i32,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub result: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub completed_at: Option<String>,
    pub claimed_by: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub reply_to: Option<String>,
}

/// Conflict resolution mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictMode {
    /// Last-Write-Wins (automatic)
    Auto,
    /// Queue for agent review
    Review,
    /// Reject remote, keep local
    Reject,
}

impl ConflictMode {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Auto => "auto",
            Self::Review => "review",
            Self::Reject => "reject",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "auto" => Self::Auto,
            "review" => Self::Review,
            "reject" => Self::Reject,
            _ => Self::Auto,
        }
    }
}

/// A sync conflict between two peers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncConflict {
    pub id: String,
    pub path: String,
    pub local_value: Option<String>,
    pub remote_value: Option<String>,
    pub local_updated_at: Option<String>,
    pub remote_updated_at: Option<String>,
    pub remote_site_id: Option<String>,
    pub resolution: Option<String>,
    pub resolved_value: Option<String>,
    pub resolved_at: Option<String>,
    pub resolved_by: Option<String>,
    pub created_at: Option<String>,
    pub notes: Option<String>,
    pub local_site_id: Option<String>,
    pub remote_db_version: Option<i64>,
    pub local_db_version: Option<i64>,
    pub previous_value_hash: Option<String>,
    #[serde(default)]
    pub related_apps: Vec<String>,
    pub audit_context: Option<String>,
}

/// Schema version for vault database migrations.
pub const SCHEMA_VERSION: i32 = 10;

/// Default sync port.
pub const DEFAULT_SYNC_PORT: u16 = 5480;

/// Default sync interval in seconds.
pub const DEFAULT_SYNC_INTERVAL: u32 = 30;

/// Default clipboard clear time in seconds.
pub const DEFAULT_CLIPBOARD_CLEAR_SECONDS: u32 = 30;
