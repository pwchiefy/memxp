//! MCP server struct and tool routing.
//!
//! Uses `rmcp` macros to expose MCP tools via stdio transport.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use chrono::Utc;
use rmcp::handler::server::{router::tool::ToolRouter, wrapper::Parameters};
use rmcp::model::{CallToolResult, ServerCapabilities, ServerInfo};
use rmcp::{tool, tool_handler, tool_router, ErrorData, ServerHandler};

use vault_core::db::CrSqliteDatabase;
use vault_core::security::AuditLogger;

use crate::params::*;
use crate::tools::{conflicts, credentials, guides, monitoring, security};

/// Default operator mode lifetime.
const DEFAULT_OPERATOR_TTL_SECS: i64 = 15 * 60;
/// Hard cap on operator mode lifetime.
const MAX_OPERATOR_TTL_SECS: i64 = 4 * 60 * 60;

/// Shared state for the MCP server.
///
/// Wrapped in `Mutex` because `rusqlite::Connection` is not `Sync`.
pub struct VaultState {
    pub db: CrSqliteDatabase,
    pub audit: AuditLogger,
    /// Whether the vault is locked (blocks all tool access except lock/unlock/auth_status).
    pub locked: AtomicBool,
    /// Optional startup session token requirement.
    pub session_required: bool,
    /// Startup token used to authenticate this MCP process session.
    pub session_token: Option<String>,
    /// Whether the current process session has been authenticated.
    pub session_authenticated: AtomicBool,
    /// UNIX epoch seconds until operator mode expires (0 means inactive).
    pub operator_until_epoch: AtomicI64,
}

impl VaultState {
    /// Get a CredentialStore wrapping this state's database.
    pub fn credentials(&self) -> vault_core::CredentialStore<'_> {
        vault_core::CredentialStore::new(&self.db)
    }

    /// Log an audit event with simplified API.
    pub fn log_audit(&self, action: &str, path: Option<&str>, details: Option<&str>) {
        let machine_id = vault_core::config::get_local_machine_id();
        let _ = self
            .audit
            .log(action, path, Some(&machine_id), details, None, true);
    }

    /// Validate and authenticate a process session token.
    pub fn authenticate_session(&self, token: &str) -> bool {
        if !self.session_required {
            self.session_authenticated.store(true, Ordering::Relaxed);
            return true;
        }
        let valid = self
            .session_token
            .as_deref()
            .map(|expected| vault_core::auth::constant_time_eq_str(expected, token))
            .unwrap_or(false);
        if valid {
            self.session_authenticated.store(true, Ordering::Relaxed);
        }
        valid
    }

    /// Whether process session authentication is currently satisfied.
    pub fn is_session_authenticated(&self) -> bool {
        !self.session_required || self.session_authenticated.load(Ordering::Relaxed)
    }

    /// Enable operator mode for up to `ttl_secs`.
    pub fn elevate_operator(&self, ttl_secs: i64) -> i64 {
        let now = Utc::now().timestamp();
        let ttl = ttl_secs.clamp(1, MAX_OPERATOR_TTL_SECS);
        let until = now + ttl;
        self.operator_until_epoch.store(until, Ordering::Relaxed);
        until
    }

    /// Disable operator mode immediately.
    pub fn clear_operator(&self) {
        self.operator_until_epoch.store(0, Ordering::Relaxed);
    }

    /// Whether operator mode is active.
    pub fn is_operator_active(&self) -> bool {
        let until = self.operator_until_epoch.load(Ordering::Relaxed);
        until > Utc::now().timestamp()
    }

    /// Operator mode expiry as RFC3339 timestamp.
    pub fn operator_expires_at(&self) -> Option<String> {
        let until = self.operator_until_epoch.load(Ordering::Relaxed);
        if until <= Utc::now().timestamp() {
            return None;
        }
        chrono::DateTime::from_timestamp(until, 0).map(|dt| dt.to_rfc3339())
    }

    /// Require operator mode for a high-risk action.
    pub fn require_operator(&self, action: &str) -> Result<(), String> {
        if self.is_operator_active() {
            Ok(())
        } else {
            Err(format!(
                "Operator mode required for '{action}'. Call vault_operator_mode(enable=true) first."
            ))
        }
    }

    /// Internal control-plane paths are not writable via generic credential tools.
    pub fn ensure_non_reserved_path(path: &str) -> Result<(), String> {
        const RESERVED_PREFIXES: &[&str] = &["_agents/"];
        if RESERVED_PREFIXES
            .iter()
            .any(|prefix| path.starts_with(prefix))
        {
            return Err(format!(
                "Path '{path}' is reserved for internal metadata and cannot be modified via generic credential tools."
            ));
        }
        Ok(())
    }
}

/// Thread-safe handle to vault state.
pub type SharedState = Arc<Mutex<VaultState>>;

/// The memxp MCP server.
#[derive(Clone)]
pub struct VaultMcpServer {
    pub state: SharedState,
    /// Whether the passphrase was available at startup (enables passwordless operator mode).
    startup_passphrase_available: bool,
    tool_router: ToolRouter<Self>,
}

impl VaultMcpServer {
    /// Create a new MCP server instance.
    pub fn new(db: CrSqliteDatabase, audit: AuditLogger) -> Self {
        let session_token = std::env::var("VAULT_MCP_SESSION_TOKEN")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let session_required = session_token.is_some();

        // Check if passphrase is resolvable at startup (Keychain or env var).
        // If so, operator mode can auto-resolve without agent providing password.
        let startup_passphrase_available = vault_core::auth::resolve_passphrase_keychain_first()
            .ok()
            .flatten()
            .is_some();

        let state = Arc::new(Mutex::new(VaultState {
            db,
            audit,
            locked: AtomicBool::new(false),
            session_required,
            session_token,
            session_authenticated: AtomicBool::new(!session_required),
            operator_until_epoch: AtomicI64::new(0),
        }));
        Self {
            state,
            startup_passphrase_available,
            tool_router: Self::tool_router(),
        }
    }

    /// Acquire state, returning an error if the vault is locked.
    ///
    /// All tool methods (except vault_lock, vault_unlock, vault_auth_status)
    /// should use this instead of `self.state.lock().unwrap()`.
    fn access_state(&self) -> Result<MutexGuard<'_, VaultState>, ErrorData> {
        let state = self.state.lock().unwrap();
        if !state.is_session_authenticated() {
            return Err(ErrorData::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                "MCP session is not authenticated. Call vault_authenticate(token) first.",
                None,
            ));
        }
        if state.locked.load(Ordering::Relaxed) {
            return Err(ErrorData::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                "Vault is locked. Use vault_unlock() to unlock.",
                None,
            ));
        }
        Ok(state)
    }

    fn validate_passphrase(password: &str) -> Result<bool, ErrorData> {
        vault_core::auth::validate_passphrase(password).map_err(|_| {
            ErrorData::new(
                rmcp::model::ErrorCode::INTERNAL_ERROR,
                "No passphrase configured. Set VAULT_PASSPHRASE or store db-passphrase in OS keychain.",
                None,
            )
        })
    }

    /// Create from paths, opening the database and audit logger.
    pub fn from_paths(
        db_path: &PathBuf,
        passphrase: &str,
        extension_path: Option<&PathBuf>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let db = CrSqliteDatabase::open(db_path, passphrase, extension_path.map(|p| p.as_path()))?;
        let audit = AuditLogger::open(vault_core::config::audit_db_path())?;
        Ok(Self::new(db, audit))
    }
}

#[tool_handler]
impl ServerHandler for VaultMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "memxp: Your second brain. I remember what you work on, what works, \
                 what fails, and how to help — across every conversation. Start with \
                 whats_saved() to see what I know, or read_instructions(\"memxp-onboarding\") \
                 if this is our first session. I learn from every session and get better \
                 over time. Use remember() to save, recall() to retrieve, find() to search."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

// ========================================================================
// Tool implementations — grouped by module
// ========================================================================

#[tool_router]
impl VaultMcpServer {
    // ---- Credentials (12 tools) ----

    /// Get vault usage guide: workflow, security tips, available services. Call this first!
    #[tool(
        description = "Get vault usage guide: workflow, security tips, available services. Call this first!"
    )]
    fn vault_help(
        &self,
        Parameters(p): Parameters<VaultHelpParams>,
    ) -> Result<CallToolResult, ErrorData> {
        Ok(credentials::vault_help(p.topic.as_deref()))
    }

    /// Get overview of vault contents (categories, services, totals).
    #[tool(
        name = "whats_saved",
        description = "See an overview of everything saved — organized by category and service, with totals. Great starting point to explore what's in memory."
    )]
    fn vault_discover(
        &self,
        Parameters(p): Parameters<VaultDiscoverParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(credentials::vault_discover(&state, p.query.as_deref()))
    }

    /// Get the most recently added vault entries.
    #[tool(
        name = "recent",
        description = "See the most recently saved items. Useful to check what was added or changed lately."
    )]
    fn vault_recent(
        &self,
        Parameters(p): Parameters<VaultRecentParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(credentials::vault_recent(&state, p.limit.unwrap_or(10)))
    }

    /// Session bootstrap / morning briefing.
    #[tool(
        description = "Session bootstrap / morning briefing. Returns concise summary of unresolved conflicts and rotation alerts."
    )]
    fn vault_session_start(
        &self,
        Parameters(p): Parameters<VaultSessionStartParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(credentials::vault_session_start(
            &state,
            p.since.as_deref(),
            p.rotation_window_days.unwrap_or(7),
        ))
    }

    /// List credentials with optional filters and pagination. Values are MASKED for security.
    #[tool(
        description = "List credentials with optional filters and pagination. Values are MASKED for security."
    )]
    fn vault_list(
        &self,
        Parameters(p): Parameters<VaultListParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(credentials::vault_list(
            &state,
            p.category.as_deref(),
            p.service.as_deref(),
            p.prefix.as_deref(),
            p.limit.unwrap_or(100),
            p.offset.unwrap_or(0),
        ))
    }

    /// Search credentials by keyword. NO values returned for security.
    #[tool(
        name = "find",
        description = "Search for saved items by keyword — searches names, notes, and tags. Returns matches without showing actual secret values."
    )]
    fn vault_search(
        &self,
        Parameters(p): Parameters<VaultSearchParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(credentials::vault_search(&state, &p.query))
    }

    /// Smart lookup: searches paths/notes/tags and returns best match with confidence score.
    #[tool(
        name = "smart_recall",
        description = "Smart lookup — finds the best match using fuzzy search across names, notes, and tags. More forgiving than exact path lookup. Single call to search and retrieve."
    )]
    fn vault_smart_get(
        &self,
        Parameters(p): Parameters<VaultSmartGetParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(credentials::vault_smart_get(
            &state,
            &p.query,
            p.include_value.unwrap_or(false),
            p.max_candidates.unwrap_or(3),
            p.min_confidence.unwrap_or(10.0),
            p.copy_to_clipboard.unwrap_or(false),
            p.redact.unwrap_or(false),
        ))
    }

    /// Get a credential's value. Use redact=true to copy to clipboard without exposing in chat history.
    #[tool(
        name = "recall",
        description = "Look up a specific saved item by its exact path. Use include_value=true to retrieve the actual secret. Use redact=true to copy to clipboard without showing in chat."
    )]
    fn vault_get(
        &self,
        Parameters(p): Parameters<VaultGetParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(credentials::vault_get(
            &state,
            &p.path,
            p.include_value.unwrap_or(false),
            p.show_metadata.unwrap_or(false),
            p.copy_to_clipboard.unwrap_or(false),
            p.redact.unwrap_or(false),
        ))
    }

    /// Add or update a credential in the vault.
    #[tool(
        name = "remember",
        description = "Save something for later — a password, API key, note, or any piece of information you want to keep. Organize with categories, tags, and notes."
    )]
    fn vault_set(
        &self,
        Parameters(p): Parameters<VaultSetParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(credentials::vault_set(
            &state,
            &p.path,
            &p.value,
            p.category.as_deref(),
            p.service.as_deref(),
            p.app.as_deref(),
            p.env.as_deref(),
            p.notes.as_deref(),
            p.tags.as_deref(),
            p.storage_mode.as_deref(),
            p.expires_at.as_deref(),
            p.rotation_interval_days,
            p.related_apps.as_deref(),
        ))
    }

    /// Delete a credential from the vault.
    #[tool(
        name = "forget",
        description = "Remove a saved item permanently from memory."
    )]
    fn vault_delete(
        &self,
        Parameters(p): Parameters<VaultDeleteParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(credentials::vault_delete(&state, &p.path))
    }

    /// Add or update multiple credentials in one call.
    #[tool(
        name = "remember_batch",
        description = "Save multiple items at once — more efficient than saving one by one."
    )]
    fn vault_set_batch(
        &self,
        Parameters(p): Parameters<VaultSetBatchParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(credentials::vault_set_batch(&state, &p.entries))
    }

    /// Get all credentials under a prefix as a dict.
    #[tool(
        name = "recall_bundle",
        description = "Get all items saved under a common prefix as a group. Use include_values=true to see actual values."
    )]
    fn vault_get_bundle(
        &self,
        Parameters(p): Parameters<VaultGetBundleParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(credentials::vault_get_bundle(
            &state,
            &p.prefix,
            p.include_values.unwrap_or(false),
            p.show_metadata.unwrap_or(false),
        ))
    }

    // ---- Security (3 tools) ----

    /// Inject a credential into an environment variable. Value is NEVER returned in response.
    #[tool(
        description = "Inject a credential into an environment variable. Value is NEVER returned in response."
    )]
    fn vault_inject(
        &self,
        Parameters(p): Parameters<VaultInjectParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(security::vault_inject(
            &state,
            &p.path,
            &p.env_var,
            p.overwrite.unwrap_or(false),
        ))
    }

    /// Send credential to GUI for secure display. Value is NEVER returned in response.
    #[tool(
        description = "Send credential to GUI for secure display. Value is NEVER returned in response."
    )]
    fn vault_show_gui(
        &self,
        Parameters(p): Parameters<VaultShowGuiParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(security::vault_show_gui(
            &state,
            &p.path,
            p.copy_to_clipboard.unwrap_or(true),
            p.auto_clear_seconds.unwrap_or(30),
        ))
    }

    /// View access audit log. Use brief=true for compact output.
    #[tool(description = "View access audit log. Use brief=true for compact output.")]
    fn vault_audit(
        &self,
        Parameters(p): Parameters<VaultAuditParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(security::vault_audit(
            &state,
            p.path.as_deref(),
            p.action.as_deref(),
            p.limit.unwrap_or(50),
            p.brief.unwrap_or(false),
        ))
    }

    /// Execute a command with a vault credential injected as an environment variable.
    #[tool(
        description = "Execute a command with a vault credential injected as env var. Secret is NEVER returned — only stdout/stderr/exit_code. Requires operator mode."
    )]
    fn vault_use(
        &self,
        Parameters(p): Parameters<VaultUseParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        let command_refs: Vec<&str> = p.command.iter().map(|s| s.as_str()).collect();
        Ok(security::vault_use(
            &state,
            &p.path,
            &p.env_var,
            &command_refs,
            p.timeout_seconds,
        ))
    }

    /// Expand <vault:path> placeholders in a template with actual secret values.
    #[tool(
        description = "Expand <vault:path> placeholders in a template with actual secret values. WARNING: expanded text contains secrets. Requires operator mode."
    )]
    fn vault_expand(
        &self,
        Parameters(p): Parameters<VaultExpandParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(security::vault_expand(&state, &p.template))
    }

    // ---- Monitoring (4 tools) ----

    /// List credential changes since a timestamp.
    #[tool(
        description = "List credential changes since a timestamp. Shows set/delete operations with value_hash to detect rotations. Values are NEVER exposed."
    )]
    fn vault_changes(
        &self,
        Parameters(p): Parameters<VaultChangesParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(monitoring::vault_changes(
            &state,
            p.since.as_deref(),
            p.path.as_deref(),
            p.prefix.as_deref(),
            p.action.as_deref(),
            p.limit.unwrap_or(50),
        ))
    }

    /// List all credentials that affect a given app.
    #[tool(
        description = "List all credentials that affect a given app. Use to assess impact before rotating/changing credentials."
    )]
    fn vault_impact(
        &self,
        Parameters(p): Parameters<VaultImpactParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(monitoring::vault_impact(&state, &p.app))
    }

    /// Analyze vault paths for naming issues.
    #[tool(
        description = "Analyze vault paths for naming issues: duplicates, drift, typos, and non-canonical paths. Returns actionable suggestions."
    )]
    fn vault_lint(
        &self,
        Parameters(p): Parameters<VaultLintParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(monitoring::vault_lint(
            &state,
            p.prefix.as_deref(),
            p.similarity_threshold.unwrap_or(0.7),
            p.max_similar_pairs.unwrap_or(20),
            p.include_suggestions.unwrap_or(true),
        ))
    }

    /// List credentials nearing rotation/expiration.
    #[tool(
        description = "List credentials nearing rotation/expiration with optional notifications."
    )]
    fn vault_rotation_alerts(
        &self,
        Parameters(p): Parameters<VaultRotationAlertsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(monitoring::vault_rotation_alerts(
            &state,
            p.window_days.unwrap_or(30),
            p.include_overdue.unwrap_or(true),
        ))
    }

    // ---- Conflicts (3 tools) ----

    /// List sync conflicts or get queue statistics.
    #[tool(
        description = "List sync conflicts or get queue statistics. Use stats_only=true for stats."
    )]
    fn vault_conflicts(
        &self,
        Parameters(p): Parameters<VaultConflictsParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(conflicts::vault_conflicts(
            &state,
            p.include_resolved.unwrap_or(false),
            p.path.as_deref(),
            p.stats_only.unwrap_or(false),
        ))
    }

    /// Resolve a sync conflict by choosing which value to keep or providing a merged value.
    #[tool(
        description = "Resolve a sync conflict by choosing which value to keep or providing a merged value."
    )]
    fn vault_resolve_conflict(
        &self,
        Parameters(p): Parameters<VaultResolveConflictParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(conflicts::vault_resolve_conflict(
            &state,
            &p.conflict_id,
            &p.resolution,
            p.value.as_deref(),
            p.notes.as_deref(),
        ))
    }

    /// Set conflict handling mode for a path.
    #[tool(
        description = "Set conflict handling mode for a path. 'auto' uses LWW, 'review' queues for agent, 'reject' always keeps local."
    )]
    fn vault_conflict_mode(
        &self,
        Parameters(p): Parameters<VaultConflictModeParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(conflicts::vault_conflict_mode(&state, &p.path, &p.mode))
    }

    // ---- Guides (8 tools) ----

    /// Add or update a guide with optional freshness metadata.
    #[tool(
        name = "save_instructions",
        description = "Save a how-to guide, procedure, or reference document for later. Supports markdown formatting, categories, and tags."
    )]
    fn vault_add_guide(
        &self,
        Parameters(p): Parameters<VaultAddGuideParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(guides::vault_add_guide(
            &state,
            &p.name,
            &p.content,
            p.category.as_deref(),
            p.tags.as_deref(),
            p.status.as_deref(),
            p.related_paths.as_deref(),
        ))
    }

    /// Get a guide by name.
    #[tool(
        name = "read_instructions",
        description = "Read a saved how-to guide or procedure by name."
    )]
    fn vault_guide(
        &self,
        Parameters(p): Parameters<VaultGuideParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(guides::vault_guide(&state, &p.name))
    }

    /// List all guides with optional filters.
    #[tool(
        name = "list_instructions",
        description = "List all saved how-to guides with optional category and status filters."
    )]
    fn vault_list_guides(
        &self,
        Parameters(p): Parameters<VaultListGuidesParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(guides::vault_list_guides(
            &state,
            p.category.as_deref(),
            p.status.as_deref(),
        ))
    }

    /// Search guides by name, content, or tags.
    #[tool(
        name = "find_instructions",
        description = "Search saved how-to guides by name, content, or tags."
    )]
    fn vault_search_guides(
        &self,
        Parameters(p): Parameters<VaultSearchGuidesParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(guides::vault_search_guides(&state, &p.query))
    }

    /// Delete a guide from the vault.
    #[tool(
        name = "forget_instructions",
        description = "Remove a saved how-to guide permanently."
    )]
    fn vault_delete_guide(
        &self,
        Parameters(p): Parameters<VaultDeleteGuideParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(guides::vault_delete_guide(&state, &p.name))
    }

    /// Mark a guide as verified (sets verified_at to now).
    #[tool(
        name = "verify_instructions",
        description = "Mark a how-to guide as verified — confirms the content is still accurate and up to date."
    )]
    fn vault_verify_guide(
        &self,
        Parameters(p): Parameters<VaultVerifyGuideParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(guides::vault_verify_guide(&state, &p.name))
    }

    /// Mark a guide as deprecated.
    #[tool(
        name = "deprecate_instructions",
        description = "Mark a how-to guide as outdated and no longer recommended for use."
    )]
    fn vault_deprecate_guide(
        &self,
        Parameters(p): Parameters<VaultDeprecateGuideParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(guides::vault_deprecate_guide(&state, &p.name))
    }

    /// List guides that haven't been verified within the threshold.
    #[tool(
        name = "stale_instructions",
        description = "List how-to guides that haven't been verified recently — helps keep guides accurate and up to date. Default threshold is 90 days."
    )]
    fn vault_stale_guides(
        &self,
        Parameters(p): Parameters<VaultStaleGuidesParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;
        Ok(guides::vault_stale_guides(
            &state,
            p.threshold_days.unwrap_or(90),
        ))
    }

    // ---- Auth (5 tools) ----

    /// Authenticate this MCP process session using the startup session token.
    #[tool(
        description = "Authenticate this MCP process session using a startup token. Required only when VAULT_MCP_SESSION_TOKEN is configured."
    )]
    fn vault_authenticate(
        &self,
        Parameters(p): Parameters<VaultAuthenticateParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.state.lock().unwrap();
        let already_authenticated = state.is_session_authenticated();
        if already_authenticated {
            return Ok(CallToolResult::success(vec![rmcp::model::Content::text(
                serde_json::json!({
                    "authenticated": true,
                    "session_required": state.session_required,
                    "message": "Session already authenticated.",
                })
                .to_string(),
            )]));
        }

        let valid = state.authenticate_session(&p.token);
        if valid {
            state.log_audit(
                "vault_authenticate",
                None,
                Some("MCP session authenticated"),
            );
            Ok(CallToolResult::success(vec![rmcp::model::Content::text(
                serde_json::json!({
                    "authenticated": true,
                    "session_required": state.session_required,
                    "message": "MCP session authenticated.",
                })
                .to_string(),
            )]))
        } else {
            Err(ErrorData::new(
                rmcp::model::ErrorCode::INVALID_PARAMS,
                "Invalid MCP session token.",
                None,
            ))
        }
    }

    /// Get authentication status.
    #[tool(
        description = "Get authentication status including whether vault is locked, auth method, and session info."
    )]
    fn vault_auth_status(&self) -> Result<CallToolResult, ErrorData> {
        let state = self.state.lock().unwrap();
        let locked = state.locked.load(Ordering::Relaxed);
        let session_authenticated = state.is_session_authenticated();
        let operator_active = state.is_operator_active();
        Ok(CallToolResult::success(vec![rmcp::model::Content::text(
            serde_json::json!({
                "authenticated": !locked && session_authenticated,
                "locked": locked,
                "session_required": state.session_required,
                "session_authenticated": session_authenticated,
                "operator_active": operator_active,
                "operator_expires_at": state.operator_expires_at(),
                "method": "mcp_direct",
                "message": if locked {
                    "Vault is locked. Use vault_unlock() to unlock."
                } else if !session_authenticated {
                    "Session token required. Call vault_authenticate(token)."
                } else if operator_active {
                    "MCP server authenticated. Operator mode is active."
                } else {
                    "MCP server authenticated. Routine mode active."
                },
            })
            .to_string(),
        )]))
    }

    /// Enable or disable temporary operator mode for high-risk mutations.
    #[tool(
        description = "Enable or disable temporary operator mode for high-risk mutations. Password is optional — omit it to auto-resolve from OS keychain or VAULT_PASSPHRASE env var."
    )]
    fn vault_operator_mode(
        &self,
        Parameters(p): Parameters<VaultOperatorModeParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let state = self.access_state()?;

        if p.enable {
            if let Some(ref pwd) = p.password {
                // Explicit password provided — validate it
                if !Self::validate_passphrase(pwd)? {
                    return Err(ErrorData::new(
                        rmcp::model::ErrorCode::INVALID_PARAMS,
                        "Invalid passphrase.",
                        None,
                    ));
                }
            } else if self.startup_passphrase_available {
                // No password provided, but passphrase was available at startup.
                // The process already authenticated by opening the encrypted DB.
                // Auto-promote without re-prompting.
            } else {
                // No password, no startup passphrase — cannot auto-resolve
                return Err(ErrorData::new(
                    rmcp::model::ErrorCode::INVALID_PARAMS,
                    "No passphrase available. Provide password parameter, set VAULT_PASSPHRASE env var, or store db-passphrase in OS keychain.",
                    None,
                ));
            }
            let until = state.elevate_operator(p.ttl_seconds.unwrap_or(DEFAULT_OPERATOR_TTL_SECS));
            state.log_audit(
                "vault_operator_mode",
                None,
                Some(&format!("enabled_until_epoch={until}")),
            );
            Ok(CallToolResult::success(vec![rmcp::model::Content::text(
                serde_json::json!({
                    "operator_active": true,
                    "operator_expires_at": state.operator_expires_at(),
                    "message": "Operator mode enabled.",
                })
                .to_string(),
            )]))
        } else {
            state.clear_operator();
            state.log_audit("vault_operator_mode", None, Some("disabled"));
            Ok(CallToolResult::success(vec![rmcp::model::Content::text(
                serde_json::json!({
                    "operator_active": false,
                    "message": "Operator mode disabled.",
                })
                .to_string(),
            )]))
        }
    }

    /// Force lock the vault, clearing all sessions.
    #[tool(description = "Force lock the vault, clear encryption key from memory.")]
    fn vault_lock(&self) -> Result<CallToolResult, ErrorData> {
        let state = self.state.lock().unwrap();
        state.locked.store(true, Ordering::Relaxed);
        state.clear_operator();
        state.log_audit("vault_lock", None, Some("Vault locked via MCP"));
        Ok(CallToolResult::success(vec![rmcp::model::Content::text(
            serde_json::json!({
                "status": "locked",
                "message": "Vault locked. Use vault_unlock() to unlock.",
            })
            .to_string(),
        )]))
    }

    /// Unlock the vault with a password (for headless/CI use).
    #[tool(
        description = "Unlock the vault with a password. For headless/CI use when web GUI is not available."
    )]
    fn vault_unlock(
        &self,
        Parameters(p): Parameters<VaultUnlockParams>,
    ) -> Result<CallToolResult, ErrorData> {
        let valid = Self::validate_passphrase(&p.password)?;

        if valid {
            let state = self.state.lock().unwrap();
            state.locked.store(false, Ordering::Relaxed);
            state.log_audit("vault_unlock", None, Some("Vault unlocked via MCP"));
            Ok(CallToolResult::success(vec![rmcp::model::Content::text(
                serde_json::json!({
                    "status": "unlocked",
                    "message": "Vault unlocked.",
                })
                .to_string(),
            )]))
        } else {
            Err(ErrorData::new(
                rmcp::model::ErrorCode::INVALID_PARAMS,
                "Invalid passphrase.",
                None,
            ))
        }
    }
}
