//! REST API endpoints mirroring MCP tools.

use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;

use vault_core::challenge::ChallengeStore;
use vault_core::db::CrSqliteDatabase;
use vault_core::security::{mask_value, AuditLogger};

use crate::auth::AuthState;

/// Shared app state for all routes.
pub struct AppState {
    pub db: Mutex<CrSqliteDatabase>,
    pub audit: Mutex<AuditLogger>,
    pub auth: AuthState,
}

/// Validate session from HttpOnly cookie only.
/// Returns FORBIDDEN if auth is not configured (must register first).
/// Returns UNAUTHORIZED if session is missing or invalid.
fn require_auth(auth: &AuthState, headers: &HeaderMap) -> Result<(), StatusCode> {
    if !auth.is_configured() {
        return Err(StatusCode::FORBIDDEN);
    }
    let sid = session_from_cookie(headers).ok_or(StatusCode::UNAUTHORIZED)?;
    if auth.validate_session(&sid) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// Build a standard auth error response.
fn auth_error_response(status: StatusCode) -> axum::response::Response {
    let msg = match status {
        StatusCode::FORBIDDEN => "authentication required — register at /api/auth/register",
        _ => "unauthorized",
    };
    (status, Json(serde_json::json!({"error": msg}))).into_response()
}

/// Build a Set-Cookie header value for a session.
fn session_cookie(id: &str) -> String {
    format!("vault_session={id}; HttpOnly; SameSite=Strict; Path=/api; Max-Age=86400")
}

/// Build a Set-Cookie header value that clears the session cookie.
fn clear_session_cookie() -> String {
    "vault_session=; HttpOnly; SameSite=Strict; Path=/api; Max-Age=0".to_string()
}

/// Parse the vault_session cookie from request headers.
fn session_from_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|c| {
            let c = c.trim();
            c.strip_prefix("vault_session=").map(|v| v.to_string())
        })
}

// --- Auth endpoints ---

#[derive(Deserialize)]
pub struct PasswordBody {
    pub password: String,
}

#[derive(Deserialize)]
pub struct TotpBody {
    pub code: String,
}

#[derive(Deserialize)]
pub struct TotpSetupBody {
    pub issuer: Option<String>,
    pub account: Option<String>,
}

/// POST /api/auth/register
pub async fn auth_register(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PasswordBody>,
) -> impl IntoResponse {
    // Prevent re-registration if auth is already configured
    if state.auth.is_configured() {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "auth already configured"})),
        )
            .into_response();
    }

    match crate::auth::password::register(&state.auth, &body.password) {
        Ok(()) => {
            let sid = state.auth.create_session("password");
            let cookie = session_cookie(&sid);
            (
                [(header::SET_COOKIE, cookie)],
                Json(serde_json::json!({
                    "status": "registered",
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

/// POST /api/auth/login
pub async fn auth_login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PasswordBody>,
) -> impl IntoResponse {
    // Rate limit check
    if state.auth.is_rate_limited() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "too many failed attempts, try again later",
                "retry_after_secs": 300,
            })),
        )
            .into_response();
    }

    match crate::auth::password::login(&state.auth, &body.password) {
        Ok(sid) => {
            let cookie = session_cookie(&sid);
            (
                [(header::SET_COOKIE, cookie)],
                Json(serde_json::json!({
                    "status": "authenticated",
                })),
            )
                .into_response()
        }
        Err(e) => {
            state.auth.record_failure();
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": e})),
            )
                .into_response()
        }
    }
}

/// POST /api/auth/totp/setup
pub async fn auth_totp_setup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<TotpSetupBody>,
) -> impl IntoResponse {
    if let Err(status) = require_auth(&state.auth, &headers) {
        return auth_error_response(status);
    }

    let issuer = body.issuer.as_deref().unwrap_or("memxp");
    let account = body.account.as_deref().unwrap_or("admin");

    match crate::auth::totp::register(&state.auth, issuer, account) {
        Ok((secret, uri)) => Json(serde_json::json!({
            "status": "totp_configured",
            "secret": secret,
            "otpauth_uri": uri,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

/// POST /api/auth/totp/verify
pub async fn auth_totp_verify(
    State(state): State<Arc<AppState>>,
    Json(body): Json<TotpBody>,
) -> impl IntoResponse {
    // Rate limit check
    if state.auth.is_rate_limited() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "too many failed attempts, try again later",
                "retry_after_secs": 300,
            })),
        )
            .into_response();
    }

    match crate::auth::totp::login(&state.auth, &body.code) {
        Ok(sid) => {
            let cookie = session_cookie(&sid);
            (
                [(header::SET_COOKIE, cookie)],
                Json(serde_json::json!({
                    "status": "authenticated",
                })),
            )
                .into_response()
        }
        Err(e) => {
            state.auth.record_failure();
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": e})),
            )
                .into_response()
        }
    }
}

/// GET /api/auth/status
pub async fn auth_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(state.auth.status())
}

/// POST /api/auth/lock
pub async fn auth_lock(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.auth.lock();
    let cookie = clear_session_cookie();
    (
        [(header::SET_COOKIE, cookie)],
        Json(serde_json::json!({"status": "locked"})),
    )
        .into_response()
}

// --- Protected endpoints ---

#[derive(Deserialize)]
pub struct GuideDeleteBody {
    pub name: String,
}

fn delete_guide_inner(state: &Arc<AppState>, name: &str) -> Result<bool, String> {
    let db = state.db.lock().unwrap();
    db.delete_guide(name).map_err(|e| e.to_string())
}

/// GET /api/credentials
pub async fn credentials_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(status) = require_auth(&state.auth, &headers) {
        return auth_error_response(status);
    }

    let db = state.db.lock().unwrap();
    let store = vault_core::credential_store::CredentialStore::new(&db);
    let entries = store.list(None, None, None).unwrap_or_default();

    let items: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            // Values are stripped by CredentialStore — show generic mask
            let masked = if e.value.is_empty() {
                "****".to_string()
            } else {
                mask_value(&e.value)
            };
            serde_json::json!({
                "path": e.path,
                "value": masked,
                "category": e.category,
                "service": e.service,
            })
        })
        .collect();

    Json(serde_json::json!({
        "count": items.len(),
        "entries": items,
    }))
    .into_response()
}

/// GET /api/credentials/*path
pub async fn credentials_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(path): axum::extract::Path<String>,
) -> impl IntoResponse {
    if let Err(status) = require_auth(&state.auth, &headers) {
        return auth_error_response(status);
    }

    let db = state.db.lock().unwrap();
    let store = vault_core::credential_store::CredentialStore::new(&db);
    match store.recall(&path) {
        Ok(Some(entry)) => Json(serde_json::json!({
            "path": entry.path,
            "value": mask_value(&entry.value),
            "category": entry.category,
            "service": entry.service,
            "notes": entry.notes,
            "tags": entry.tags,
            "created_at": entry.created_at,
            "updated_at": entry.updated_at,
        }))
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// GET /api/guides
pub async fn guides_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(status) = require_auth(&state.auth, &headers) {
        return auth_error_response(status);
    }

    let db = state.db.lock().unwrap();
    let guides = db.list_guides(None, None).unwrap_or_default();

    let items: Vec<serde_json::Value> = guides
        .iter()
        .map(|g| {
            serde_json::json!({
                "name": g.name,
                "category": g.category,
                "status": g.status,
                "tags": g.tags,
                "updated_at": g.updated_at,
            })
        })
        .collect();

    Json(serde_json::json!({
        "count": items.len(),
        "guides": items,
    }))
    .into_response()
}

/// DELETE /api/guides/{name}
pub async fn guides_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> impl IntoResponse {
    if let Err(status) = require_auth(&state.auth, &headers) {
        return auth_error_response(status);
    }

    let trimmed = name.trim();
    if trimmed.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "guide name cannot be empty"})),
        )
            .into_response();
    }

    match delete_guide_inner(&state, trimmed) {
        Ok(true) => Json(serde_json::json!({
            "status": "deleted",
            "name": trimmed,
        }))
        .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "guide not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

/// POST /api/guides/delete
pub async fn guides_delete_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<GuideDeleteBody>,
) -> impl IntoResponse {
    if let Err(status) = require_auth(&state.auth, &headers) {
        return auth_error_response(status);
    }

    let trimmed = body.name.trim();
    if trimmed.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "guide name cannot be empty"})),
        )
            .into_response();
    }

    match delete_guide_inner(&state, trimmed) {
        Ok(true) => Json(serde_json::json!({
            "status": "deleted",
            "name": trimmed,
        }))
        .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "guide not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

/// GET /api/sync/status
pub async fn sync_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(status) = require_auth(&state.auth, &headers) {
        return auth_error_response(status);
    }

    let db = state.db.lock().unwrap();
    let machine_id = vault_core::config::get_local_machine_id();
    let version = db.db_version().unwrap_or(0);
    let cr = db.cr_enabled();

    Json(serde_json::json!({
        "machine_id": machine_id,
        "db_version": version,
        "cr_sqlite": cr,
    }))
    .into_response()
}

/// GET /api/audit
pub async fn audit_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(status) = require_auth(&state.auth, &headers) {
        return auth_error_response(status);
    }

    let audit = state.audit.lock().unwrap();
    let entries = audit.list(None, None, 50).unwrap_or_default();

    let items: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "timestamp": e.timestamp,
                "action": e.action,
                "path": e.path,
                "success": e.success,
            })
        })
        .collect();

    Json(serde_json::json!({
        "count": items.len(),
        "entries": items,
    }))
    .into_response()
}

// --- New endpoints ---

/// GET /api/guides/{name} — Get guide with full content
pub async fn guide_get(
    Path(name): Path<String>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(status) = require_auth(&state.auth, &headers) {
        return auth_error_response(status);
    }

    let db = state.db.lock().unwrap();
    match db.get_guide(&name) {
        Ok(Some(guide)) => Json(serde_json::json!({
            "name": guide.name,
            "content": guide.content,
            "category": guide.category,
            "tags": guide.tags,
            "status": guide.status,
            "version": guide.version,
            "verified_at": guide.verified_at,
            "related_paths": guide.related_paths,
            "created_at": guide.created_at,
            "updated_at": guide.updated_at,
        }))
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "guide not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct GuideCreateRequest {
    pub name: String,
    pub content: String,
    pub category: Option<String>,
    pub tags: Option<Vec<String>>,
    pub status: Option<String>,
    pub related_paths: Option<Vec<String>>,
}

/// POST /api/guides — Create or update a guide
pub async fn guide_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<GuideCreateRequest>,
) -> impl IntoResponse {
    if let Err(status) = require_auth(&state.auth, &headers) {
        return auth_error_response(status);
    }

    let trimmed = body.name.trim();
    if trimmed.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "guide name cannot be empty"})),
        )
            .into_response();
    }

    let db = state.db.lock().unwrap();
    match db.set_guide(
        trimmed,
        &body.content,
        body.category.as_deref(),
        body.tags.as_deref(),
        body.status.as_deref(),
        None, // verified_at
        body.related_paths.as_deref(),
    ) {
        Ok(guide) => Json(serde_json::json!({
            "status": "created",
            "name": guide.name,
            "category": guide.category,
            "updated_at": guide.updated_at,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// GET /api/challenges/pending — List pending operator challenges
pub async fn challenges_pending(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(status) = require_auth(&state.auth, &headers) {
        return auth_error_response(status);
    }

    let store = ChallengeStore::new();
    match store.list_pending() {
        Ok(pending) => {
            let items: Vec<serde_json::Value> = pending
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "challenge_id": c.challenge_id,
                        "action": c.action,
                        "requesting_tool": c.requesting_tool,
                        "created_at": c.created_at,
                        "expires_at": c.expires_at,
                    })
                })
                .collect();
            Json(serde_json::json!(items)).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
pub struct ChallengeConfirmRequest {
    pub action: String,
}

/// POST /api/challenges/{id}/confirm — Confirm an operator challenge
pub async fn challenge_confirm(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ChallengeConfirmRequest>,
) -> impl IntoResponse {
    if let Err(status) = require_auth(&state.auth, &headers) {
        return auth_error_response(status);
    }

    let store = ChallengeStore::new();
    match store.confirm(&id, &body.action, None) {
        Ok(_payload) => Json(serde_json::json!({
            "status": "confirmed",
            "challenge_id": id,
        }))
        .into_response(),
        Err(e) => {
            let status_code = match &e {
                vault_core::challenge::ChallengeError::NotFound(_) => StatusCode::NOT_FOUND,
                vault_core::challenge::ChallengeError::Expired(_) => StatusCode::GONE,
                _ => StatusCode::BAD_REQUEST,
            };
            (
                status_code,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    }
}

/// POST /api/clipboard/{*path} — Copy credential value to clipboard
pub async fn credential_clipboard(
    Path(path): Path<String>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(status) = require_auth(&state.auth, &headers) {
        return auth_error_response(status);
    }

    let value = {
        let db = state.db.lock().unwrap();
        let store = vault_core::credential_store::CredentialStore::new(&db);
        match store.recall(&path) {
            Ok(Some(entry)) => entry.value.clone(),
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "credential not found"})),
                )
                    .into_response();
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        }
    };

    // Copy to clipboard with auto-clear
    match arboard::Clipboard::new().and_then(|mut cb| cb.set_text(&value)) {
        Ok(()) => {
            // Schedule clipboard clear after 30 seconds
            std::thread::spawn(|| {
                std::thread::sleep(std::time::Duration::from_secs(30));
                if let Ok(mut cb) = arboard::Clipboard::new() {
                    let _ = cb.set_text("");
                }
            });

            // Log the clipboard access
            if let Ok(audit) = state.audit.lock() {
                let _ = audit.log(
                    "clipboard_copy",
                    Some(&path),
                    None,
                    Some("copied via web dashboard, auto-clears in 30s"),
                    Some("vault-web"),
                    true,
                );
            }

            Json(serde_json::json!({
                "status": "copied",
                "path": path,
                "auto_clear_seconds": 30,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("clipboard error: {e}")})),
        )
            .into_response(),
    }
}

/// GET /api/events/poll — Poll for dashboard state updates
pub async fn events_poll(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(status) = require_auth(&state.auth, &headers) {
        return auth_error_response(status);
    }

    // Get challenge count
    let challenge_count = ChallengeStore::new()
        .list_pending()
        .map(|v| v.len())
        .unwrap_or(0);

    // Get credential and guide counts
    let (credential_count, guide_count) = {
        let db = state.db.lock().unwrap();
        let store = vault_core::credential_store::CredentialStore::new(&db);
        let creds = store.list(None, None, None).map(|v| v.len()).unwrap_or(0);
        let guides = db.list_guides(None, None).map(|v| v.len()).unwrap_or(0);
        (creds, guides)
    };

    Json(serde_json::json!({
        "challenges": challenge_count,
        "credentials": credential_count,
        "guides": guide_count,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
    .into_response()
}
