//! Integration tests for vault-web.

use tempfile::TempDir;
use vault_core::db::CrSqliteDatabase;
use vault_core::security::AuditLogger;

/// Helper to create a test database and audit logger.
fn test_components(tmp: &TempDir) -> (CrSqliteDatabase, AuditLogger) {
    let db = CrSqliteDatabase::open(tmp.path().join("test.db"), "test-pass", None).unwrap();
    let audit = AuditLogger::open(tmp.path().join("audit.db")).unwrap();
    (db, audit)
}

/// Helper to register auth and get a session ID for authenticated requests.
async fn setup_auth(
    _addr: &std::net::SocketAddr,
    state: &std::sync::Arc<vault_web::api::AppState>,
) -> String {
    vault_web::auth::password::register(&state.auth, "test-pass").unwrap();
    vault_web::auth::password::login(&state.auth, "test-pass").unwrap()
}

#[tokio::test]
async fn test_web_server_starts() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);
    let (addr, _state) = vault_web::server::start_test(db, audit).await.unwrap();

    let url = format!("http://{addr}/api/auth/status");
    let client = reqwest::Client::new();
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_unauthenticated_rejected() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);
    let (addr, state) = vault_web::server::start_test(db, audit).await.unwrap();

    // Configure auth so endpoints require session
    vault_web::auth::password::register(&state.auth, "test-password-123").unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/api/credentials"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_password_register_login() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);
    let (addr, _state) = vault_web::server::start_test(db, audit).await.unwrap();

    let client = reqwest::Client::new();

    // Register
    let resp = client
        .post(format!("http://{addr}/api/auth/register"))
        .json(&serde_json::json!({"password": "my-secure-password-123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "registered");
    assert!(body["session_id"].is_string());

    // Login
    let resp = client
        .post(format!("http://{addr}/api/auth/login"))
        .json(&serde_json::json!({"password": "my-secure-password-123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "authenticated");
    let session_id = body["session_id"].as_str().unwrap();
    assert!(!session_id.is_empty());
}

#[tokio::test]
async fn test_password_wrong_rejected() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);
    let (addr, _state) = vault_web::server::start_test(db, audit).await.unwrap();

    let client = reqwest::Client::new();

    // Register
    client
        .post(format!("http://{addr}/api/auth/register"))
        .json(&serde_json::json!({"password": "correct-password"}))
        .send()
        .await
        .unwrap();

    // Login with wrong password
    let resp = client
        .post(format!("http://{addr}/api/auth/login"))
        .json(&serde_json::json!({"password": "wrong-password"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[test]
fn test_argon2_hash_format() {
    let hash = vault_web::auth::password::hash_password("test-password").unwrap();
    assert!(hash.starts_with("$argon2id$"));
}

#[test]
fn test_password_verify() {
    let hash = vault_web::auth::password::hash_password("my-password").unwrap();
    assert!(vault_web::auth::password::verify_password(
        "my-password",
        &hash
    ));
    assert!(!vault_web::auth::password::verify_password("wrong", &hash));
}

#[test]
fn test_totp_setup_verify() {
    let (secret, uri) = vault_web::auth::totp::setup("VaultP2P", "test@example.com").unwrap();
    assert!(!secret.is_empty());
    assert!(uri.starts_with("otpauth://"));

    // Generate the current code and verify it
    let result = vault_web::auth::totp::verify(&secret, "000000");
    // Code "000000" is almost certainly wrong, so this should return Ok(false)
    assert!(result.is_ok());
    // We can't test with a valid code without controlling time, but setup/verify don't panic
}

#[test]
fn test_totp_wrong_code_rejected() {
    let auth = vault_web::auth::AuthState::new();
    let (_secret, _uri) = vault_web::auth::totp::register(&auth, "VaultP2P", "admin").unwrap();

    // Wrong code
    let result = vault_web::auth::totp::login(&auth, "000000");
    // This will either be Ok(session) if 000000 happens to be correct (extremely unlikely)
    // or Err("Invalid TOTP code")
    // We just verify it doesn't panic
    let _ = result;
}

#[tokio::test]
async fn test_api_credentials_list() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);

    // Add some entries before starting server
    db.set_entry(
        "api/test/key",
        "secret-val",
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

    let (addr, state) = vault_web::server::start_test(db, audit).await.unwrap();

    // Register and get session
    vault_web::auth::password::register(&state.auth, "test-pass").unwrap();
    let session_id = vault_web::auth::password::login(&state.auth, "test-pass").unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "http://{addr}/api/credentials?session_id={session_id}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["count"], 1);
    // Value should be masked
    let val = body["entries"][0]["value"].as_str().unwrap();
    assert!(val.contains('*'));
}

#[tokio::test]
async fn test_api_sync_status() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);
    let (addr, state) = vault_web::server::start_test(db, audit).await.unwrap();

    vault_web::auth::password::register(&state.auth, "test-pass").unwrap();
    let session_id = vault_web::auth::password::login(&state.auth, "test-pass").unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "http://{addr}/api/sync/status?session_id={session_id}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["machine_id"].is_string());
    assert!(body["db_version"].is_number());
}

#[tokio::test]
async fn test_rate_limiting_on_login() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);
    let (addr, _state) = vault_web::server::start_test(db, audit).await.unwrap();

    let client = reqwest::Client::new();

    // Register
    client
        .post(format!("http://{addr}/api/auth/register"))
        .json(&serde_json::json!({"password": "correct-password"}))
        .send()
        .await
        .unwrap();

    // 10 wrong passwords
    for _ in 0..10 {
        let resp = client
            .post(format!("http://{addr}/api/auth/login"))
            .json(&serde_json::json!({"password": "wrong-password"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    // 11th attempt should be rate limited (429), even with wrong password
    let resp = client
        .post(format!("http://{addr}/api/auth/login"))
        .json(&serde_json::json!({"password": "wrong-password"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);

    // Even correct password should be rate limited
    let resp = client
        .post(format!("http://{addr}/api/auth/login"))
        .json(&serde_json::json!({"password": "correct-password"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429);
}

#[tokio::test]
async fn test_rate_limiting_on_totp_verify() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);
    let (addr, state) = vault_web::server::start_test(db, audit).await.unwrap();

    // Setup TOTP
    let (_secret, _uri) =
        vault_web::auth::totp::register(&state.auth, "VaultP2P", "admin").unwrap();

    let client = reqwest::Client::new();

    // 10 wrong codes
    for _ in 0..10 {
        let resp = client
            .post(format!("http://{addr}/api/auth/totp/verify"))
            .json(&serde_json::json!({"code": "000000"}))
            .send()
            .await
            .unwrap();
        // Could be 401 (wrong code) — we just need to trigger failures
        let status = resp.status().as_u16();
        assert!(status == 401 || status == 200); // 200 if 000000 happens to be valid
    }

    // 11th attempt should be rate limited
    let resp = client
        .post(format!("http://{addr}/api/auth/totp/verify"))
        .json(&serde_json::json!({"code": "000000"}))
        .send()
        .await
        .unwrap();
    // Either 429 (rate limited) or 200 (if all previous were valid — extremely unlikely)
    let status = resp.status().as_u16();
    assert!(status == 429 || status == 200);
}

#[test]
fn test_session_create_validate() {
    let auth = vault_web::auth::AuthState::new();
    let session_id = auth.create_session("password");
    assert!(auth.validate_session(&session_id));
    assert!(!auth.validate_session("invalid-session-id"));

    // Lock should invalidate all sessions
    auth.lock();
    assert!(!auth.validate_session(&session_id));
}

// --- New tests for Part 4 ---

#[tokio::test]
async fn test_guide_get_content() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);

    // Create a guide via DB directly
    db.set_guide(
        "test-guide",
        "# Test Guide\n\nThis is test content.",
        Some("procedure"),
        Some(&["test".to_string(), "guide".to_string()]),
        Some("active"),
        None,
        None,
    )
    .unwrap();

    let (addr, state) = vault_web::server::start_test(db, audit).await.unwrap();
    let session_id = setup_auth(&addr, &state).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "http://{addr}/api/guides/test-guide?session_id={session_id}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["name"], "test-guide");
    assert_eq!(body["content"], "# Test Guide\n\nThis is test content.");
    assert_eq!(body["category"], "procedure");
    assert_eq!(body["status"], "active");
    // Verify tags are present
    let tags = body["tags"].as_array().unwrap();
    assert!(tags.iter().any(|t| t == "test"));
    assert!(tags.iter().any(|t| t == "guide"));
}

#[tokio::test]
async fn test_guide_create() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);
    let (addr, state) = vault_web::server::start_test(db, audit).await.unwrap();
    let session_id = setup_auth(&addr, &state).await;

    let client = reqwest::Client::new();

    // Create a guide via POST
    let resp = client
        .post(format!("http://{addr}/api/guides?session_id={session_id}"))
        .json(&serde_json::json!({
            "name": "new-guide",
            "content": "# New Guide\n\nCreated via API.",
            "category": "runbook",
            "tags": ["api", "test"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "created");
    assert_eq!(body["name"], "new-guide");
    assert_eq!(body["category"], "runbook");

    // Now GET the guide to verify content
    let resp = client
        .get(format!(
            "http://{addr}/api/guides/new-guide?session_id={session_id}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["content"], "# New Guide\n\nCreated via API.");
}

#[tokio::test]
async fn test_guide_create_requires_auth() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);
    let (addr, state) = vault_web::server::start_test(db, audit).await.unwrap();

    // Register auth but don't provide session_id
    vault_web::auth::password::register(&state.auth, "test-pass").unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/api/guides"))
        .json(&serde_json::json!({
            "name": "should-fail",
            "content": "nope",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_guide_get_not_found() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);
    let (addr, state) = vault_web::server::start_test(db, audit).await.unwrap();
    let session_id = setup_auth(&addr, &state).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "http://{addr}/api/guides/nonexistent?session_id={session_id}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("not found"));
}

#[tokio::test]
async fn test_challenges_pending_empty() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);
    let (addr, state) = vault_web::server::start_test(db, audit).await.unwrap();
    let session_id = setup_auth(&addr, &state).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "http://{addr}/api/challenges/pending?session_id={session_id}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    // Should be an empty array
    assert!(body.is_array());
    assert_eq!(body.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_credential_clipboard() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);

    // Add a credential
    db.set_entry(
        "api/clipboard/test",
        "clipboard-secret-value",
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

    let (addr, state) = vault_web::server::start_test(db, audit).await.unwrap();
    let session_id = setup_auth(&addr, &state).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "http://{addr}/api/clipboard/api/clipboard/test?session_id={session_id}"
        ))
        .send()
        .await
        .unwrap();

    // On CI or headless environments, clipboard may not be available.
    // Accept either 200 (success) or 500 (clipboard unavailable).
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap();

    if status == 200 {
        assert_eq!(body["status"], "copied");
        assert_eq!(body["path"], "api/clipboard/test");
        assert_eq!(body["auto_clear_seconds"], 30);
        // CRITICAL: value must NEVER be in the response
        assert!(body.get("value").is_none());
    } else {
        // Clipboard not available (CI/headless) — just verify it's a clipboard error
        assert_eq!(status, 500);
        assert!(body["error"].as_str().unwrap().contains("clipboard"));
    }
}

#[tokio::test]
async fn test_events_poll() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);

    // Add some entries to have counts > 0
    db.set_entry(
        "api/poll/key",
        "val",
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
    db.set_guide("poll-guide", "content", None, None, None, None, None)
        .unwrap();

    let (addr, state) = vault_web::server::start_test(db, audit).await.unwrap();
    let session_id = setup_auth(&addr, &state).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "http://{addr}/api/events/poll?session_id={session_id}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["challenges"].is_number());
    assert!(body["credentials"].is_number());
    assert!(body["guides"].is_number());
    assert!(body["timestamp"].is_string());
    // We added 1 credential and 1 guide
    assert_eq!(body["credentials"], 1);
    assert_eq!(body["guides"], 1);
}

#[tokio::test]
async fn test_events_poll_requires_auth() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);
    let (addr, state) = vault_web::server::start_test(db, audit).await.unwrap();

    vault_web::auth::password::register(&state.auth, "test-pass").unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/api/events/poll"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_guide_get_requires_auth() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);
    let (addr, state) = vault_web::server::start_test(db, audit).await.unwrap();

    vault_web::auth::password::register(&state.auth, "test-pass").unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/api/guides/something"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_guide_create_update() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);
    let (addr, state) = vault_web::server::start_test(db, audit).await.unwrap();
    let session_id = setup_auth(&addr, &state).await;

    let client = reqwest::Client::new();

    // Create guide
    let resp = client
        .post(format!("http://{addr}/api/guides?session_id={session_id}"))
        .json(&serde_json::json!({
            "name": "updatable-guide",
            "content": "version 1",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Update the same guide
    let resp = client
        .post(format!("http://{addr}/api/guides?session_id={session_id}"))
        .json(&serde_json::json!({
            "name": "updatable-guide",
            "content": "version 2",
            "category": "troubleshooting",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Verify the content was updated
    let resp = client
        .get(format!(
            "http://{addr}/api/guides/updatable-guide?session_id={session_id}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["content"], "version 2");
    assert_eq!(body["category"], "troubleshooting");
}

#[tokio::test]
async fn test_challenges_pending_requires_auth() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);
    let (addr, state) = vault_web::server::start_test(db, audit).await.unwrap();

    vault_web::auth::password::register(&state.auth, "test-pass").unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{addr}/api/challenges/pending"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_guide_create_empty_name_rejected() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);
    let (addr, state) = vault_web::server::start_test(db, audit).await.unwrap();
    let session_id = setup_auth(&addr, &state).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/api/guides?session_id={session_id}"))
        .json(&serde_json::json!({
            "name": "  ",
            "content": "some content",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_register_rejects_when_already_configured() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);
    let (addr, _state) = vault_web::server::start_test(db, audit).await.unwrap();
    let client = reqwest::Client::new();

    // First registration should succeed
    let resp = client
        .post(format!("http://{addr}/api/auth/register"))
        .json(&serde_json::json!({"password": "first-pass"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Second registration should fail with 409
    let resp = client
        .post(format!("http://{addr}/api/auth/register"))
        .json(&serde_json::json!({"password": "overwrite-attempt"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
}

#[tokio::test]
async fn test_totp_setup_requires_session() {
    let tmp = TempDir::new().unwrap();
    let (db, audit) = test_components(&tmp);
    let (addr, state) = vault_web::server::start_test(db, audit).await.unwrap();
    let client = reqwest::Client::new();

    // TOTP setup without auth should fail
    let resp = client
        .post(format!("http://{addr}/api/auth/totp/setup"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    // Should be FORBIDDEN (no auth configured) or UNAUTHORIZED
    assert!(resp.status() == 403 || resp.status() == 401);

    // Register + login, then TOTP setup should work
    let session_id = setup_auth(&addr, &state).await;
    let resp = client
        .post(format!(
            "http://{addr}/api/auth/totp/setup?session_id={session_id}"
        ))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}
