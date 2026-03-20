//! Axum web server with routes, static file serving.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::Router;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;

use vault_core::db::CrSqliteDatabase;
use vault_core::security::AuditLogger;

use crate::api::{self, AppState};
use crate::auth::AuthState;

// Embed static files directly in the binary
const EMBEDDED_INDEX_HTML: &str = include_str!("../../../static/index.html");
const EMBEDDED_STYLE_CSS: &str = include_str!("../../../static/style.css");
const EMBEDDED_APP_JS: &str = include_str!("../../../static/app.js");

/// Serve embedded index.html
async fn embedded_index() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        EMBEDDED_INDEX_HTML,
    )
}

/// Serve embedded style.css
async fn embedded_css() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        EMBEDDED_STYLE_CSS,
    )
}

/// Serve embedded app.js
async fn embedded_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        EMBEDDED_APP_JS,
    )
}

/// Configuration for the web server.
pub struct WebConfig {
    pub port: u16,
    pub static_dir: Option<PathBuf>,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            port: 8777,
            static_dir: None,
        }
    }
}

/// Build the Axum router with all routes.
///
/// `port` is used for strict CORS origin matching. Pass 0 for permissive CORS (tests).
pub fn build_router(state: Arc<AppState>, static_dir: Option<&PathBuf>, port: u16) -> Router {
    let api_routes = Router::new()
        // Auth (no session required)
        .route("/auth/register", post(api::auth_register))
        .route("/auth/login", post(api::auth_login))
        .route("/auth/totp/setup", post(api::auth_totp_setup))
        .route("/auth/totp/verify", post(api::auth_totp_verify))
        .route("/auth/status", get(api::auth_status))
        .route("/auth/lock", post(api::auth_lock))
        // Protected endpoints (require vault_session cookie)
        .route("/credentials", get(api::credentials_list))
        .route("/credentials/{*path}", get(api::credentials_get))
        .route("/guides", get(api::guides_list).post(api::guide_create))
        .route("/guides/delete", post(api::guides_delete_post))
        .route(
            "/guides/{name}",
            get(api::guide_get).delete(api::guides_delete),
        )
        // Backward-compatible alias: documents == guides
        .route("/documents", get(api::guides_list))
        .route("/documents/delete", post(api::guides_delete_post))
        .route("/documents/{name}", delete(api::guides_delete))
        // Challenges
        .route("/challenges/pending", get(api::challenges_pending))
        .route("/challenges/{id}/confirm", post(api::challenge_confirm))
        // Clipboard
        .route("/clipboard/{*path}", post(api::credential_clipboard))
        // Events polling
        .route("/events/poll", get(api::events_poll))
        .route("/sync/status", get(api::sync_status))
        .route("/audit", get(api::audit_list))
        .with_state(state);

    let mut router = Router::new().nest("/api", api_routes);

    // Serve static files from disk if directory exists, otherwise use embedded files
    let use_disk = static_dir
        .map(|d| d.join("index.html").exists())
        .unwrap_or(false);

    if use_disk {
        router = router.fallback_service(ServeDir::new(static_dir.unwrap()));
    } else {
        // Serve embedded static files — no external files needed
        router = router
            .route("/", get(embedded_index))
            .route("/index.html", get(embedded_index))
            .route("/style.css", get(embedded_css))
            .route("/app.js", get(embedded_js));
    }

    let cors = if port == 0 {
        // Tests use reqwest directly — no browser CORS checks needed
        CorsLayer::permissive()
    } else {
        CorsLayer::new()
            .allow_origin([
                format!("http://localhost:{port}")
                    .parse::<HeaderValue>()
                    .unwrap(),
                format!("http://127.0.0.1:{port}")
                    .parse::<HeaderValue>()
                    .unwrap(),
            ])
            .allow_methods([Method::GET, Method::POST, Method::DELETE])
            .allow_headers([header::CONTENT_TYPE, header::COOKIE])
            .allow_credentials(true)
    };

    router.layer(cors)
}

/// Start the web server.
pub async fn start(
    db: CrSqliteDatabase,
    audit: AuditLogger,
    config: WebConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let auth = AuthState::new();
    let state = Arc::new(AppState {
        db: Mutex::new(db),
        audit: Mutex::new(audit),
        auth,
    });

    let router = build_router(state, config.static_dir.as_ref(), config.port);
    let addr = SocketAddr::from(([127, 0, 0, 1], config.port));

    tracing::info!("Web GUI available at http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

/// Start and return the address (for tests).
pub async fn start_test(
    db: CrSqliteDatabase,
    audit: AuditLogger,
) -> Result<(SocketAddr, Arc<AppState>), Box<dyn std::error::Error + Send + Sync>> {
    let auth = AuthState::new();
    let state = Arc::new(AppState {
        db: Mutex::new(db),
        audit: Mutex::new(audit),
        auth,
    });

    let router = build_router(state.clone(), None, 0);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    tokio::spawn(async move {
        axum::serve(listener, router).await.ok();
    });

    Ok((addr, state))
}
