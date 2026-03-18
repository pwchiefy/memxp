//! Parameter structs for MCP tool definitions.
//!
//! Each tool that accepts parameters gets a `*Params` struct here.
//! Structs derive `Deserialize` + `JsonSchema` for rmcp auto-schema generation.

use schemars::JsonSchema;
use serde::Deserialize;

// ---- Credentials ----

#[derive(Deserialize, JsonSchema)]
pub struct VaultHelpParams {
    /// Optional topic: 'workflow', 'security', 'tools', or 'all' (default)
    pub topic: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultDiscoverParams {
    /// Optional path prefix to filter results
    pub query: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultRecentParams {
    /// Number of entries to return (default: 10)
    pub limit: Option<i32>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultSessionStartParams {
    /// ISO timestamp to filter recent changes from
    pub since: Option<String>,
    /// Days ahead to check for rotation/expiry (default: 7)
    pub rotation_window_days: Option<i32>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultListParams {
    /// Filter by category (api_key, password, token, etc.)
    pub category: Option<String>,
    /// Filter by service name
    pub service: Option<String>,
    /// Filter by path prefix
    pub prefix: Option<String>,
    /// Max entries to return (default: 100)
    pub limit: Option<i32>,
    /// Skip first N entries (default: 0)
    pub offset: Option<i32>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultSearchParams {
    /// Search query (searches path, notes, tags)
    pub query: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultSmartGetParams {
    /// Natural language query (e.g., 'openai prod key', 'postgres password')
    pub query: String,
    /// Include actual secret value in response (default: false for security)
    pub include_value: Option<bool>,
    /// Max number of alternative matches to return (default: 3)
    pub max_candidates: Option<i32>,
    /// Minimum confidence score 0-100 (default: 10)
    pub min_confidence: Option<f64>,
    /// Copy best match value to clipboard (auto-clears in 30s)
    pub copy_to_clipboard: Option<bool>,
    /// When include_value=true, redact value in response and copy to clipboard only
    pub redact: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultGetParams {
    /// The credential path (e.g., 'api/openai/key')
    pub path: String,
    /// Include actual secret value in response (default: false for security)
    pub include_value: Option<bool>,
    /// Include notes, tags, timestamps
    pub show_metadata: Option<bool>,
    /// Copy value to clipboard (auto-clears in 30s)
    pub copy_to_clipboard: Option<bool>,
    /// Redact value in response, copy to clipboard only
    pub redact: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultSetParams {
    /// Hierarchical path (e.g., 'aws/s3/access_key')
    pub path: String,
    /// The secret value to store
    pub value: String,
    /// Type: api_key, password, token, certificate, ssh_key, env_var
    pub category: Option<String>,
    /// Service name (e.g., 'aws', 'postgres')
    pub service: Option<String>,
    /// Application name if app-specific
    pub app: Option<String>,
    /// Environment (dev, staging, production)
    pub env: Option<String>,
    /// Description or usage notes
    pub notes: Option<String>,
    /// Tags for searching
    pub tags: Option<Vec<String>>,
    /// Storage mode: vault (default), keychain, or both
    pub storage_mode: Option<String>,
    /// ISO timestamp when credential expires
    pub expires_at: Option<String>,
    /// Rotation interval in days
    pub rotation_interval_days: Option<i32>,
    /// Applications that use this credential (for impact tracking)
    pub related_apps: Option<Vec<String>>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultDeleteParams {
    /// The path of the credential to delete
    pub path: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultSetBatchParams {
    /// List of credentials to set
    pub entries: Vec<serde_json::Value>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultGetBundleParams {
    /// Path prefix (e.g., 'postgres/prod' or 'aws/s3')
    pub prefix: String,
    /// Include actual values (default: false for security, only masked previews)
    pub include_values: Option<bool>,
    /// Include metadata (category, service, env, etc.)
    pub show_metadata: Option<bool>,
}

// ---- Security ----

#[derive(Deserialize, JsonSchema)]
pub struct VaultInjectParams {
    /// The credential path
    pub path: String,
    /// Environment variable name to set
    pub env_var: String,
    /// Overwrite if env var already exists
    pub overwrite: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultShowGuiParams {
    /// The credential path
    pub path: String,
    /// Copy value to clipboard
    pub copy_to_clipboard: Option<bool>,
    /// Seconds before auto-clearing clipboard
    pub auto_clear_seconds: Option<u64>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultAuditParams {
    /// Optional path to filter logs (supports % wildcard)
    pub path: Option<String>,
    /// Filter by action type
    pub action: Option<String>,
    /// Max logs to return (default: 50)
    pub limit: Option<i32>,
    /// Return only path, action, timestamp (reduces tokens)
    pub brief: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultUseParams {
    /// The credential path (e.g., 'api/openai/key')
    pub path: String,
    /// Environment variable name to inject the secret into
    pub env_var: String,
    /// Command to execute as array of strings (e.g., ["curl", "-H", "Authorization: Bearer $OPENAI_API_KEY", "https://api.openai.com/v1/models"])
    pub command: Vec<String>,
    /// Timeout in seconds (default: 30, max: 300)
    pub timeout_seconds: Option<u64>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultExpandParams {
    /// Template text containing <vault:path> placeholders to expand
    pub template: String,
}

// ---- Monitoring ----

#[derive(Deserialize, JsonSchema)]
pub struct VaultChangesParams {
    /// ISO timestamp to filter changes from
    pub since: Option<String>,
    /// Filter by exact path
    pub path: Option<String>,
    /// Filter by path prefix
    pub prefix: Option<String>,
    /// Filter by action type
    pub action: Option<String>,
    /// Max changes to return (default: 50)
    pub limit: Option<i32>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultImpactParams {
    /// Application name to check
    pub app: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultLintParams {
    /// Filter paths by prefix
    pub prefix: Option<String>,
    /// Threshold for similar path detection (0-1, default: 0.7)
    pub similarity_threshold: Option<f64>,
    /// Maximum similar pairs to return (default: 20)
    pub max_similar_pairs: Option<usize>,
    /// Include canonical path suggestions (default: true)
    pub include_suggestions: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultRotationAlertsParams {
    /// Days ahead to check for rotation/expiry (default: 30)
    pub window_days: Option<i32>,
    /// Include already overdue credentials (default: true)
    pub include_overdue: Option<bool>,
}

// ---- Conflicts ----

#[derive(Deserialize, JsonSchema)]
pub struct VaultConflictsParams {
    /// Include already-resolved conflicts (default: false)
    pub include_resolved: Option<bool>,
    /// Filter conflicts for a specific path
    pub path: Option<String>,
    /// Return only statistics (pending count, resolution history)
    pub stats_only: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultResolveConflictParams {
    /// The conflict ID to resolve
    pub conflict_id: String,
    /// How to resolve: keep_local, keep_remote, or merge
    pub resolution: String,
    /// For merge resolution, the custom merged value
    pub value: Option<String>,
    /// Optional notes about why this resolution was chosen
    pub notes: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultConflictModeParams {
    /// Path to configure (supports wildcards like 'api/*')
    pub path: String,
    /// Conflict mode: auto, review, reject
    pub mode: String,
}

// ---- P2P ----

#[derive(Deserialize, JsonSchema)]
pub struct P2pCreateTaskParams {
    /// Short task title
    pub title: String,
    /// Target machine IP or '*' for any/broadcast
    pub to_machine: Option<String>,
    /// Detailed task description
    pub description: Option<String>,
    /// Priority: 0=critical, 1=high, 2=medium, 3=low, 4=backlog
    pub priority: Option<i32>,
    /// Tags for filtering
    pub tags: Option<Vec<String>>,
    /// Task ID this is a reply to
    pub reply_to: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct P2pSendMessageParams {
    /// Target machine Tailscale IP, or '*' for broadcast
    pub to_machine: String,
    /// Message content
    pub content: String,
    /// Message subject
    pub subject: Option<String>,
    /// Priority: 0=critical, 1=high, 2=medium, 3=low, 4=backlog
    pub priority: Option<i32>,
}

#[derive(Deserialize, JsonSchema)]
pub struct P2pGetMyTasksParams {
    /// Include completed/failed tasks
    pub include_completed: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct P2pGetMessagesParams {
    /// Include read messages
    pub include_read: Option<bool>,
    /// Max messages to return (default: 20)
    pub limit: Option<i32>,
}

#[derive(Deserialize, JsonSchema)]
pub struct P2pMarkReadParams {
    /// Message ID to mark as read
    pub message_id: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct P2pClaimTaskParams {
    /// The task ID to claim
    pub task_id: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct P2pCompleteTaskParams {
    /// The task ID
    pub task_id: String,
    /// Result or output message
    pub result: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct P2pBacklogStatsParams {
    /// Optional: filter to specific peer site ID
    pub peer_site_id: Option<String>,
    /// Include detailed change list (default: false, stats only)
    pub include_details: Option<bool>,
    /// Max changes to return when include_details=true (default: 100)
    pub limit: Option<i32>,
}

// ---- Local Agent ----

#[derive(Deserialize, JsonSchema)]
pub struct LocalAgentRegisterParams {
    /// Agent type: claude-code, codex, gemini, etc.
    pub agent_type: String,
    /// Agent capabilities: code, search, edit, web, etc.
    pub capabilities: Option<Vec<String>>,
}

#[derive(Deserialize, JsonSchema)]
pub struct LocalAgentListParams {
    /// Include agents with stale heartbeats (default: false)
    pub include_inactive: Option<bool>,
}

#[derive(Deserialize, JsonSchema)]
pub struct LocalSendMessageParams {
    /// Target agent type (claude-code, codex, etc.) or '*' for broadcast
    pub to_agent: String,
    /// Message content
    pub content: String,
    /// Message subject
    pub subject: Option<String>,
    /// Priority: low, normal, high, urgent
    pub priority: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct LocalGetMessagesParams {
    /// Include already-read messages (default: false)
    pub include_read: Option<bool>,
    /// Max messages to return (default: 10)
    pub limit: Option<i32>,
}

#[derive(Deserialize, JsonSchema)]
pub struct LocalMarkReadParams {
    /// The message ID to mark as read
    pub message_id: String,
}

// ---- Guides ----

#[derive(Deserialize, JsonSchema)]
pub struct VaultAddGuideParams {
    /// Guide name (e.g., 'vps-deploy', 'postgres-backup')
    pub name: String,
    /// Guide content (markdown)
    pub content: String,
    /// Category: procedure, troubleshooting, runbook, setup
    pub category: Option<String>,
    /// Tags for searching
    pub tags: Option<Vec<String>>,
    /// Status: active (default) or deprecated
    pub status: Option<String>,
    /// Credential paths referenced by this guide
    pub related_paths: Option<Vec<String>>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultGuideParams {
    /// The guide name
    pub name: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultListGuidesParams {
    /// Filter by category
    pub category: Option<String>,
    /// Filter by status (active, deprecated)
    pub status: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultSearchGuidesParams {
    /// Search query
    pub query: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultDeleteGuideParams {
    /// The guide name to delete
    pub name: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultVerifyGuideParams {
    /// The guide name to verify
    pub name: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultDeprecateGuideParams {
    /// The guide name to deprecate
    pub name: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultStaleGuidesParams {
    /// Number of days after which a guide is considered stale (default: 90)
    pub threshold_days: Option<i32>,
}

// ---- Auth ----

#[derive(Deserialize, JsonSchema)]
pub struct VaultAuthenticateParams {
    /// Session token to authenticate this MCP process (required only when VAULT_MCP_SESSION_TOKEN is configured)
    pub token: String,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultOperatorModeParams {
    /// Enable (true) or disable (false) operator mode
    pub enable: bool,
    /// Vault passphrase (optional — omit to auto-resolve from OS keychain or VAULT_PASSPHRASE env var)
    pub password: Option<String>,
    /// Requested operator mode duration in seconds (default: 900, max: 14400)
    pub ttl_seconds: Option<i64>,
}

#[derive(Deserialize, JsonSchema)]
pub struct VaultUnlockParams {
    /// Password to unlock the vault (for headless/CI use)
    pub password: String,
}
